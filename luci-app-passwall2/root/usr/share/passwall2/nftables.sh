#!/bin/sh

DIR="$(cd "$(dirname "$0")" && pwd)"
MY_PATH=$DIR/nftables.sh
UTILS_PATH=$DIR/utils.sh
NFTABLE_NAME="inet passwall2"
# 影子启动（见 app.sh stage）把规则写入不挂钩子的影子表：可以照常生成、查询与按位置插入，但不处理任何报文。
[ -n "${PW2_STAGE}" ] && NFTABLE_NAME="inet passwall2_stage"
NFTSET_LOCAL="psw2_local"
NFTSET_DIRECT="psw2_direct"
NFTSET_VPS="psw2_vps"
NFTSET_WAN="psw2_wan"

NFTSET_LOCAL6="psw2_local6"
NFTSET_DIRECT6="psw2_direct6"
NFTSET_VPS6="psw2_vps6"
NFTSET_WAN6="psw2_wan6"

FWMARK="0x50535732"
# 使用默认实例（全局节点及跟随全局的访问控制）的分流项放在专用子链中，热切换全局节点时只替换子链内容。
SHUNT_CHAINS="PSW2_SHUNT_NAT PSW2_SHUNT_MARK PSW2_SHUNT_MARK6 PSW2_SHUNT_ICMP PSW2_SHUNT_ICMP6"

FWI=$(uci -q get firewall.passwall2.path 2>/dev/null)
FAKE_IP="198.18.0.0/16"
FAKE_IP_6="2001:2::/48"

factor() {
	local ports="$1"
	if [ -z "$1" ] || [ -z "$2" ] || [ "$ports" = "1:65535" ]; then
		echo ""
	# acl mac address
	elif echo "$1" | grep -qE '([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}'; then
		echo "$2 {$1}"
	else
		ports=$(echo "$ports" | tr -d ' ' | sed 's/:/-/g' | tr ',' '\n' | awk '!a[$0]++' | grep -v '^$')
		[ -z "$ports" ] && { echo ""; return; }
		if echo "$ports" | grep -q '^1-65535$'; then
			echo ""
			return
		fi
		local port
		local port_list=""
		for port in $ports; do
			port_list="${port_list},$port"
		done
		port_list="${port_list#,}"
		echo "$2 {$port_list}"
	fi
}

insert_rule_before() {
	[ $# -ge 4 ] || {
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		nft "add rule $table_name $chain_name $rule"
	else
		if [ -z "${_index}" ]; then
			_index=${default_index}
		fi
		nft "insert rule $table_name $chain_name position $_index $rule"
	fi
}

insert_rule_after() {
	[ $# -ge 4 ] || {
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		nft "add rule $table_name $chain_name $rule"
	else
		if [ -n "${_index}" ]; then
			_index=$((_index + 1))
		else
			_index=${default_index}
		fi
		nft "insert rule $table_name $chain_name position $_index $rule"
	fi
}

RULE_LAST_INDEX() {
	[ $# -ge 3 ] || {
		log_i18n 1 "Incorrect index listing method (%s), execution terminated!" "nftables"
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local default="${1:-0}"; shift
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	echo "${_index:-${default}}"
}

REDIRECT() {
	local s="counter redirect"
	[ -n "$1" ] && {
		local s="$s to :$1"
		[ "$2" == "TPROXY" ] && {
			s="counter meta mark ${FWMARK} tproxy to :$1"
		}
		[ "$2" == "TPROXY4" ] && {
			s="counter meta mark ${FWMARK} tproxy ip to :$1"
		}
		[ "$2" == "TPROXY6" ] && {
			s="counter meta mark ${FWMARK} tproxy ip6 to :$1"
		}

	}
	echo $s
}

destroy_nftset() {
	for i in "$@"; do
		nft flush set $NFTABLE_NAME $i 2>/dev/null
		nft delete set $NFTABLE_NAME $i 2>/dev/null
	done
}

# 基础链及其钩子；热重载提交时按同一份定义创建缺失的基础链（影子启动把它写入暂存目录）。
NFT_BASE_CHAINS="dstnat|type nat hook prerouting priority dstnat - 1; policy accept;
mangle_prerouting|type filter hook prerouting priority mangle - 1; policy accept;
mangle_output|type route hook output priority mangle - 1; policy accept;
nat_output|type nat hook output priority -1; policy accept;"

gen_nft_tables() {
	if ! nft list table "$NFTABLE_NAME" >/dev/null 2>&1; then
		[ -n "${PW2_STAGE}" ] && echo "${NFT_BASE_CHAINS}" > "$TMP_PATH/nft_base_chains"
		echo "${NFT_BASE_CHAINS}" | awk -F '|' -v t="$NFTABLE_NAME" -v stage="${PW2_STAGE}" '
			BEGIN { print "table " t " {" }
			# 影子表中的基础链是普通链，不挂钩子。
			{ print "\tchain " $1 " {"; if (stage == "") print "\t\t" $2; print "\t}" }
			END { print "}" }
		' | nft -f -
	fi
}

# 热刷新时集合操作写入 NFT_SCRIPT，由调用者在一个 nft 事务中提交；未设置时保持原行为直接执行。
nft_apply() {
	if [ -n "${NFT_SCRIPT}" ]; then
		cat >> "${NFT_SCRIPT}"
	else
		nft -f -
	fi
}

insert_nftset() {
	local nftset_name="${1}"; shift
	local timeout_argument="${1:--1}"; shift
	local default_timeout="365d"
	local suffix=""

	if [ -n "$nftset_name" ] && { [ $# -gt 0 ] || [ ! -t 0 ]; }; then
		case "$timeout_argument" in
			"-1") suffix="" ;;
			 "0") suffix=" timeout $default_timeout" ;;
			   *) suffix=" timeout $timeout_argument" ;;
		esac
		{
			if [ $# -gt 0 ] && [ $# -le 1000 ]; then
				printf "%s\n" "$@"
			elif [ $# -gt 1000 ]; then
				printf "%s\n" "$*"
			else
				cat
			fi | awk -v s="$suffix" -v n="$nftset_name" -v t="$NFTABLE_NAME" '
				BEGIN {
					RS = "[ \t\n\r]+"
					ORS = ""
				}
				$0 != "" {
					if (!first) {
						printf "add element %s %s { \n", t, n
						first = 1;
					} else {
						print ",\n"
					}
					print $0 s
				}
				END {
					if (first) print "\n }\n"
				}
			'
		} | nft_apply
	fi
}

gen_nftset() {
	local nftset_name="${1}"; shift
	local ip_type="${1}"; shift
	#  0 - don't set defalut timeout
	local timeout_argument_set="${1}"; shift
	#  0 - don't let element timeout(365 days) when set's timeout parameters be seted
	# -1 - follow the set's timeout parameters
	local timeout_argument_element="${1}"; shift
	local gc_interval_time="1h"

	if [ -n "${NFT_SCRIPT}" ]; then
		# 热刷新：同定义的 add set 对已存在的集合是空操作，随后在同一事务中清空并重新填充。
		if [ "$timeout_argument_set" == "0" ]; then
			echo "add set $NFTABLE_NAME $nftset_name { type $ip_type; flags interval, timeout; auto-merge; }"
		else
			echo "add set $NFTABLE_NAME $nftset_name { type $ip_type; flags interval, timeout; timeout $timeout_argument_set; gc-interval $gc_interval_time; auto-merge; }"
		fi >> "${NFT_SCRIPT}"
		echo "flush set $NFTABLE_NAME $nftset_name" >> "${NFT_SCRIPT}"
	elif ! nft list set $NFTABLE_NAME $nftset_name >/dev/null 2>&1; then
		if [ "$timeout_argument_set" == "0" ]; then
			nft "add set $NFTABLE_NAME $nftset_name { type $ip_type; flags interval, timeout; auto-merge; }"
		else
			nft "add set $NFTABLE_NAME $nftset_name { type $ip_type; flags interval, timeout; timeout $timeout_argument_set; gc-interval $gc_interval_time; auto-merge; }"
		fi
	fi
	if [ $# -gt 0 ]; then
		insert_nftset "$nftset_name" "$timeout_argument_element" "$@"
	fi
}

gen_shunt_list() {
	local node=${1}
	local shunt_list4_var_name=${2}
	local shunt_list6_var_name=${3}
	[ -z "$node" ] && continue
	unset ${shunt_list4_var_name}
	unset ${shunt_list6_var_name}
	local _SHUNT_LIST4 _SHUNT_LIST6
	local USE_SHUNT_NODE=0
	NODE_PROTOCOL=$(config_n_get $node protocol)
	[ "$NODE_PROTOCOL" = "_shunt" ] && USE_SHUNT_NODE=1
	[ "$USE_SHUNT_NODE" = "1" ] && {
		local enable_geoview_ip=$(config_n_get $node enable_geoview_ip 0)
		[ -z "$(first_type geoview)" ] && enable_geoview_ip=0
		local preloading=0
		preloading=$enable_geoview_ip
		[ "${preloading}" = "1" ] && {
			local default_node=$(config_n_get ${node} default_node _direct)
			local default_outbound="redirect"
			[ "$default_node" = "_direct" ] && default_outbound="direct"
			local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
			local shunt_group=$(config_n_get $node shunt_group)
			for shunt_id in $shunt_ids; do
				[ "${shunt_group}" != "$(config_n_get ${shunt_id} group)" ] && continue
				local shunt_node=$(config_n_get ${node} "${shunt_id}")
				[ -n "$shunt_node" ] && {
					local nftset_v4="psw2_${node}_${shunt_id}"
					local nftset_v6="psw2_${node}_${shunt_id}6"
					local outbound="redirect"
					[ "$shunt_node" = "_direct" ] && outbound="direct"
					[ "$shunt_node" = "_default" ] && outbound="${default_outbound}"
					_SHUNT_LIST4="${_SHUNT_LIST4} ${nftset_v4}:${outbound}"
					_SHUNT_LIST6="${_SHUNT_LIST6} ${nftset_v6}:${outbound}"
					# 热切换或同一节点再次使用时，已存在的集合沿用已载入的内容，避免重复解析 GeoIP。
					[ -n "${SHUNT_PRESERVE_SETS}" ] && nft list set $NFTABLE_NAME $nftset_v4 >/dev/null 2>&1 && \
						nft list set $NFTABLE_NAME $nftset_v6 >/dev/null 2>&1 && continue
					gen_nftset $nftset_v4 ipv4_addr 0 0
					gen_nftset $nftset_v6 ipv6_addr 0 0
					# 影子启动：运行中已有的规则集合沿用原内容（内容变化由集合热刷新处理），影子表只建同名空集合供规则引用。
					[ -n "${PW2_STAGE}" ] && [ -z "${PW2_STAGE_REFRESH}" ] && nft list set inet passwall2 $nftset_v4 >/dev/null 2>&1 && \
						nft list set inet passwall2 $nftset_v6 >/dev/null 2>&1 && {
						echo "$nftset_v4 $nftset_v6" >> "$TMP_PATH/preserved_sets"
						continue
					}
					config_n_get $shunt_id ip_list | sed 's/#.*//' | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | insert_nftset $nftset_v4 "0"
					config_n_get $shunt_id ip_list | sed 's/#.*//' | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | insert_nftset $nftset_v6 "0"
					[ "${enable_geoview_ip}" = "1" ] && {
						local _geoip_code=$(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
						[ -n "$_geoip_code" ] && {
							get_geoip $_geoip_code ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | insert_nftset $nftset_v4 "0"
							get_geoip $_geoip_code ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | insert_nftset $nftset_v6 "0"
							#log 3 "$(i18n "parse the traffic splitting rules[%s]-[geoip:%s] add to %s to complete." "${shunt_id}" "${_geoip_code}" "NFTSET[${nftset_v4},${nftset_v6}]")"
						}
					}
				}
			done
		}
		local direct_nftset4=$(get_cache_var "node_${node}_direct_nftset4")
		[ -n "${direct_nftset4}" ] && {
			gen_nftset $direct_nftset4 ipv4_addr 0 0
			_SHUNT_LIST4="${_SHUNT_LIST4} ${direct_nftset4}:direct"
		}
		local direct_nftset6=$(get_cache_var "node_${node}_direct_nftset6")
		[ -n "${direct_nftset6}" ] && {
			gen_nftset $direct_nftset6 ipv6_addr 0 0
			_SHUNT_LIST6="${_SHUNT_LIST6} ${direct_nftset6}:direct"
		}
	}
	[ -n "${_SHUNT_LIST4}" ] && eval ${shunt_list4_var_name}=\"${_SHUNT_LIST4}\"
	[ -n "${_SHUNT_LIST6}" ] && eval ${shunt_list6_var_name}=\"${_SHUNT_LIST6}\"
	set_cache_var "node_${node}_gen_shunt_list" "1"
}

add_shunt_t_rule() {
	local shunt_args=${1}
	local t_args=${2}
	local t_jump_args=${3}
	local t_comment=${4}
	[ -n "${t_comment}" ] && t_comment="comment \"$t_comment\""
	if [ "${shunt_args}" = "@global" ]; then
		# 默认实例的分流列表只在主链留一条跳转；按地址族与动作选择共享子链。
		local prefix chain
		case "${t_args}" in
			*" ip6 daddr")
				prefix=${t_args% ip6 daddr}
				chain=PSW2_SHUNT_MARK6
				[ "${t_jump_args}" = "counter redirect" ] && chain=PSW2_SHUNT_ICMP6
				;;
			*)
				prefix=${t_args% ip daddr}
				case "${t_jump_args}" in
					"counter redirect") chain=PSW2_SHUNT_ICMP ;;
					"counter redirect to "*) chain=PSW2_SHUNT_NAT ;;
					*) chain=PSW2_SHUNT_MARK ;;
				esac
				;;
		esac
		# 已由代理接管的流量不再按分流集合重新分类，热切换后已有 UDP 会话保持原路径。
		case "${chain}" in
			PSW2_SHUNT_MARK*) prefix="${prefix} ct mark != ${FWMARK}" ;;
		esac
		${prefix} counter jump ${chain} ${t_comment}
		return
	fi
	[ -n "${shunt_args}" ] && {
		for j in ${shunt_args}; do
			local _set_name=$(echo ${j} | awk -F ':' '{print $1}')
			local _outbound=$(echo ${j} | awk -F ':' '{print $2}')
			[ -n "${_set_name}" ] && [ -n "${_outbound}" ] && {
				local _t_arg="${t_jump_args}"
				[ "${_outbound}" = "direct" ] && _t_arg="counter return"
				${t_args} @${_set_name} ${_t_arg} ${t_comment}
			}
		done
	}
}

# 输出整套分流子链内容（先清空再填充），交给 nft -f 在同一个事务中原子替换。
# 直连项用 accept 结束本钩子的基础链，与原先在主链中 return 的效果相同。
gen_shunt_chains() {
	local redir_port=${1}
	local chain list match verdict item set_name outbound
	for chain in ${SHUNT_CHAINS}; do
		echo "flush chain $NFTABLE_NAME ${chain}"
		case "${chain}" in
			PSW2_SHUNT_NAT) list=${SHUNT_LIST4}; match="ip daddr"; verdict="counter redirect to :${redir_port}" ;;
			PSW2_SHUNT_MARK) list=${SHUNT_LIST4}; match="ip daddr"; verdict="counter jump PSW2_RULE" ;;
			PSW2_SHUNT_MARK6) list=${SHUNT_LIST6}; match="ip6 daddr"; verdict="counter jump PSW2_RULE" ;;
			PSW2_SHUNT_ICMP) list=${SHUNT_LIST4}; match="ip daddr"; verdict="counter redirect" ;;
			PSW2_SHUNT_ICMP6) list=${SHUNT_LIST6}; match="ip6 daddr"; verdict="counter redirect" ;;
		esac
		[ -n "${redir_port}" ] || list=""
		for item in ${list}; do
			set_name=${item%%:*}
			outbound=${item##*:}
			[ -n "${set_name}" ] && [ -n "${outbound}" ] || continue
			if [ "${outbound}" = "direct" ]; then
				echo "add rule $NFTABLE_NAME ${chain} ${match} @${set_name} counter accept"
			elif [ "${chain}" = "PSW2_SHUNT_NAT" ]; then
				# 端口重定向要求先匹配传输层协议；该子链只承接 TCP。
				echo "add rule $NFTABLE_NAME ${chain} ip protocol tcp ${match} @${set_name} ${verdict}"
			else
				echo "add rule $NFTABLE_NAME ${chain} ${match} @${set_name} ${verdict}"
			fi
		done
	done
}

shunt_ready() {
	local chain
	for chain in ${SHUNT_CHAINS}; do
		nft list chain $NFTABLE_NAME ${chain} >/dev/null 2>&1 || return 2
	done
}

# 热切换全局节点：只替换分流子链并补充新节点地址白名单；主链、DNS 劫持及其它规则保持不变。
# 新连接立即按新规则分流；TCP 重定向只作用于新连接，已标记的 UDP 流按 conntrack 标记保持原路径。
shunt_switch() {
	local node=${1}
	local redir_port=${2}
	[ -n "${node}" ] && [ -n "${redir_port}" ] || return 1
	[ -z "$(command -v log_i18n)" ] && . "$UTILS_PATH"
	shunt_ready || return 2
	SHUNT_PRESERVE_SETS=1
	gen_shunt_list "${node}" SHUNT_LIST4 SHUNT_LIST6
	gen_shunt_chains "${redir_port}" | nft -f - || return 1
	filter_vps_addr $(config_n_get ${node} address) $(config_n_get ${node} download_address) >/dev/null 2>&1 &
	gen_include
}

# 规则数据或分流规则内容更新后的热刷新：在一个 nft 事务中重建由规则派生的集合（直连集合、GeoIP 预加载集合），
# 按上游 flush_set 语义清空直连写集合，并重填默认实例的分流子链；主链、DNS 劫持与 psw2_vps/local/wan 不变。
# 独立访问控制实例只刷新集合内容：配置指纹保证其引用的集合名不变。flush=1 时先丢弃 geoip 解析缓存。
refresh_sets() {
	local node=${1}
	local redir_port=${2}
	local flush=${3}
	[ -z "$(command -v log_i18n)" ] && . "$UTILS_PATH"
	shunt_ready || return 2
	[ "${flush}" = "1" ] && rm -rf "$TMP_PATH2/geo_output"
	if [ -z "${ISP_DNS}${ISP_DNS6}" ]; then
		local resolv=/tmp/resolv.conf.d/resolv.conf.auto
		[ -s "${resolv}" ] || resolv=/tmp/resolv.conf.auto
		ISP_DNS=$(cat $resolv 2>/dev/null | grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | grep -v -E '^(0\.0\.0\.0|127\.0\.0\.1)$' | awk '!seen[$0]++')
		ISP_DNS6=$(cat $resolv 2>/dev/null | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | awk -F % '{print $1}' | awk -F " " '{print $2}' | grep -v -Fx ::1 | grep -v -Fx :: | awk '!seen[$0]++')
	fi
	local script="$TMP_PATH/refresh_sets.nft" var_file acl_use acl_node done_nodes=" "
	: > "${script}"
	NFT_SCRIPT="${script}"
	gen_nftset $NFTSET_DIRECT ipv4_addr 0 "-1"
	gen_nftset $NFTSET_DIRECT6 ipv6_addr 0 "-1"
	fill_direct_sets
	for var_file in "${TMP_ACL_PATH}"/*/var; do
		[ -s "${var_file}" ] || continue
		# var 文件可能有两行 node（条目自身的选项与所用实例的节点），与 eval 一致取最后一行。
		acl_use=$(sed -n 's/^use="\(.*\)"$/\1/p' "${var_file}" | tail -n 1)
		acl_node=$(sed -n 's/^node="\(.*\)"$/\1/p' "${var_file}" | tail -n 1)
		[ "${acl_use}" = "acl_default" ] || [ -z "${acl_node}" ] && continue
		case "${done_nodes}" in *" ${acl_node} "*) continue ;; esac
		done_nodes="${done_nodes}${acl_node} "
		[ "${acl_node}" = "${node}" ] && continue
		gen_shunt_list "${acl_node}" _refresh_list4 _refresh_list6
	done
	unset SHUNT_LIST4 SHUNT_LIST6
	[ -n "${node}" ] && gen_shunt_list "${node}" SHUNT_LIST4 SHUNT_LIST6
	unset NFT_SCRIPT
	# nft 的 auto-merge 在同一事务中 flush 之后，若同一集合的多条 add element 被其它语句隔开，
	# 会按陈旧缓存删除已清空的元素而失败（ENOENT）：按集合归并成一条 add element 再提交。
	awk '
		$1 == "add" && $2 == "set" { name = $3 " " $4 " " $5; if (!(name in seen)) { seen[name] = 1; order[++n] = name }; def[name] = $0; next }
		$1 == "flush" && $2 == "set" { name = $3 " " $4 " " $5; if (!(name in seen)) { seen[name] = 1; order[++n] = name }; flush[name] = 1; next }
		$1 == "add" && $2 == "element" { cur = $3 " " $4 " " $5; if (!(cur in seen)) { seen[cur] = 1; order[++n] = cur }; next }
		cur != "" && $0 ~ /^[ \t]*}[ \t]*$/ { cur = ""; next }
		cur != "" { gsub(/^[ \t]+|[ \t,]+$/, ""); if ($0 != "") elems[cur] = (count[cur]++ ? elems[cur] ",\n" : "") $0; next }
		{ rest[++m] = $0 }
		END {
			for (i = 1; i <= n; i++) {
				name = order[i]
				if (name in def) print def[name]
				if (name in flush) print "flush set " name
				if (name in elems) print "add element " name " {\n" elems[name] "\n}"
			}
			for (i = 1; i <= m; i++) print rest[i]
		}
	' "${script}" > "${script}.grouped" && mv -f "${script}.grouped" "${script}"
	gen_shunt_chains "${redir_port}" >> "${script}"
	nft -f "${script}" || return 1
	gen_include
}

load_acl() {
	[ -n "${ACL_NODE_DONE}" ] || {
		log_i18n 1 "Access Control:"
		acl_node
	}
	for sid in $(jsonfilter -s "${ACL_JSON}" -e '$.acl[*].flag'); do
		eval $(cat "${TMP_ACL_PATH}/${sid}/var")

		# 使用默认实例的条目跳转到共享分流子链；独立实例按各自节点生成静态规则（同一节点的集合只载入一次）。
		unset shunt_list4 shunt_list6
		if [ "${use}" = "acl_default" ]; then
			shunt_list4="@global"
			shunt_list6="@global"
		elif [ -n "${node}" ]; then
			SHUNT_PRESERVE_SETS=1
			gen_shunt_list "${node}" shunt_list4 shunt_list6
			unset SHUNT_PRESERVE_SETS
		fi
		[ -n "${use}" ] && local dns_redirect_port=$(get_cache_var "ACL_${use}_dns_port")

		[ "${local_proxy}" = "1" ] && {
			msg="$(i18n "[Local],")"
			[ -n "$tcp_no_redir_ports" ] && {
				nft "add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp $(factor $tcp_no_redir_ports "tcp dport") counter return"
				nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto tcp $(factor $tcp_no_redir_ports "tcp dport") counter return"
				if ! has_1_65535 "$tcp_no_redir_ports"; then
					log 2 "${msg}$(i18n "not proxy %s port [%s]" "TCP" "${tcp_no_redir_ports}")"
				else
					no_tcp_local_proxy="1"
					log 2 "${msg}$(i18n "not proxy all %s" "TCP")"
				fi
			}
			[ -n "$udp_no_redir_ports" ] && {
				nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip protocol udp $(factor $udp_no_redir_ports "udp dport") counter return"
				nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto udp $(factor $udp_no_redir_ports "udp dport") counter return"
				if ! has_1_65535 "$udp_no_redir_ports"; then
					log 2 "${msg}$(i18n "not proxy %s port [%s]" "UDP" "${udp_no_redir_ports}")"
				else
					no_udp_local_proxy="1"
					log 2 "${msg}$(i18n "not proxy all %s" "UDP")"
				fi
			}

			local comment_l="$(i18n "Local")"

			if [ -n "$node" ] && ([ -z "$no_tcp_local_proxy" ] || [ -z "$no_udp_local_proxy" ]); then
				[ -n "$dns_redirect_port" ] && {
					#nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip protocol udp udp dport 53 counter accept"
					#nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip protocol tcp tcp dport 53 counter accept"
					#nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto udp udp dport 53 counter accept"
					#nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto tcp tcp dport 53 counter accept"
					nft "add rule $NFTABLE_NAME nat_output oif lo meta l4proto udp udp dport 53 counter redirect to :$dns_redirect_port comment \"PSW2_DNS\""
					nft "add rule $NFTABLE_NAME nat_output oif lo meta l4proto tcp tcp dport 53 counter redirect to :$dns_redirect_port comment \"PSW2_DNS\""
					log 2 "${msg}$(i18n "DNS will redirected to the dedicated DNS server [%s]." "${dns_redirect_port}")"
				}
			fi

			# Loading local router proxy TCP
			if [ -n "$node" ] && [ -z "$no_tcp_local_proxy" ]; then
				[ "$accept_icmp" = "1" ] && {
					nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo ip protocol icmp ip daddr $FAKE_IP counter redirect"
					add_shunt_t_rule "${shunt_list4}" "nft add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo ip protocol icmp ip daddr" "counter redirect"
					nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo ip protocol icmp counter redirect"
					nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo ip protocol icmp counter return"
				}

				[ "$accept_icmpv6" = "1" ] && {
					nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr $FAKE_IP_6 counter redirect"
					add_shunt_t_rule "${shunt_list6}" "nft add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr" "counter redirect"
					nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo meta l4proto icmpv6 counter redirect"
					nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT oif lo meta l4proto icmpv6 counter return"
				}

				msg2="${msg}$(i18n "Use the %s node [%s]" "TCP" "${node_remarks}")"
				if [ -n "${is_tproxy}" ]; then
					msg2="${msg2}(TPROXY:${redir_port})"
					nft_chain="PSW2_OUTPUT_MANGLE"
					nft_j="counter jump PSW2_RULE"
				else
					msg2="${msg2}(REDIRECT:${redir_port})"
					nft_chain="PSW2_OUTPUT_NAT"
					nft_j="$(REDIRECT $redir_port)"
				fi

				nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ip daddr $FAKE_IP ${nft_j}"
				add_shunt_t_rule "${shunt_list4}" "nft add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(factor $tcp_redir_ports "tcp dport") ip daddr" "${nft_j}"
				nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp $(factor $tcp_redir_ports "tcp dport") ${nft_j}"
				[ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME nat_output ip daddr != @$NFTSET_DIRECT ip protocol tcp counter jump PSW2_OUTPUT_NAT"
				[ -n "${is_tproxy}" ] && {
					nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp iif lo $(REDIRECT $redir_port TPROXY4) comment \"${comment_l}\""
					nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp iif lo counter return comment \"${comment_l}\""
					nft "add rule $NFTABLE_NAME mangle_output ip daddr != @$NFTSET_DIRECT ip protocol tcp counter jump PSW2_OUTPUT_MANGLE comment \"PSW2_OUTPUT_MANGLE\""
				}

				[ "$PROXY_IPV6" == "1" ] && {
					nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr $FAKE_IP_6 jump PSW2_RULE"
					add_shunt_t_rule "${shunt_list6}" "nft add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto tcp $(factor $tcp_redir_ports "tcp dport") ip6 daddr" "counter jump PSW2_RULE"
					nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto tcp $(factor $tcp_redir_ports "tcp dport") counter jump PSW2_RULE"
					nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp iif lo $(REDIRECT $redir_port TPROXY6) comment \"${comment_l}\""
					nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp iif lo counter return comment \"${comment_l}\""
				}

				[ -d "${TMP_IFACE_PATH}" ] && {
					for iface in $(ls ${TMP_IFACE_PATH}); do
						nft "add rule $NFTABLE_NAME $nft_output_chain ip protocol tcp oif $iface counter return"
						nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 ip protocol tcp oif $iface counter return"
					done
				}
				log 2 "${msg2}"
			fi

			# Loading local router proxy UDP
			if [ -n "$node" ] && [ -z "$no_udp_local_proxy" ]; then
				msg2="${msg}$(i18n "Use the %s node [%s]" "UDP" "${node_remarks}")(TPROXY:${redir_port})"
				nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip protocol udp ip daddr $FAKE_IP counter jump PSW2_RULE"
				add_shunt_t_rule "${shunt_list4}" "nft add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip protocol udp $(factor $udp_redir_ports "udp dport") ip daddr" "counter jump PSW2_RULE"
				nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip protocol udp $(factor $udp_redir_ports "udp dport") counter jump PSW2_RULE"
				nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp iif lo $(REDIRECT $redir_port TPROXY4) comment \"${comment_l}\""
				nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp iif lo counter return comment \"${comment_l}\""
				nft "add rule $NFTABLE_NAME mangle_output ip daddr != @$NFTSET_DIRECT ip protocol udp counter jump PSW2_OUTPUT_MANGLE comment \"PSW2_OUTPUT_MANGLE\""

				[ "$PROXY_IPV6" == "1" ] && {
					nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr $FAKE_IP_6 jump PSW2_RULE"
					add_shunt_t_rule "${shunt_list6}" "nft add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto udp $(factor $udp_redir_ports "udp dport") ip6 daddr" "counter jump PSW2_RULE"
					nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto udp $(factor $udp_redir_ports "udp dport") counter jump PSW2_RULE"
					nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp iif lo $(REDIRECT $redir_port TPROXY6) comment \"${comment_l}\""
					nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp iif lo counter return comment \"${comment_l}\""
				}

				[ -d "${TMP_IFACE_PATH}" ] && {
					for iface in $(ls ${TMP_IFACE_PATH}); do
						nft "add rule $NFTABLE_NAME $nft_output_chain ip protocol udp oif $iface counter return"
						nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 ip protocol udp oif $iface counter return"
					done
				}

				log 2 "${msg2}"
			fi

			nft "add rule $NFTABLE_NAME mangle_output oif lo counter return comment \"PSW2_OUTPUT_MANGLE\""
			nft "add rule $NFTABLE_NAME mangle_output meta mark ${FWMARK} counter return comment \"PSW2_OUTPUT_MANGLE\""

			unset msg msg2 comment_l
		}
		[ "${client_proxy}" = "1" ] && {
			msg1="$(i18n "[%s]," "${remarks}")"
			for i in $(cat ${TMP_ACL_PATH}/${sid}/source_list); do
				local _ipt_source _ipv4
				local msg
				if [ -n "${interface}" ]; then
					local gateway device
					network_get_gateway gateway "${interface}"
					network_get_device device "${interface}"
					# network_get_device returns empty for non-UP interfaces (e.g. auto='0').
					# Try ubus directly, then check if the name is a kernel device.
					[ -z "${device}" ] && device=$(ubus call "network.interface.${interface}" status 2>/dev/null | jsonfilter -e '@.device' 2>/dev/null)
					[ -z "${device}" ] && [ -d "/sys/class/net/${interface}" ] && device="${interface}"
					[ -z "${device}" ] && device="${interface}"
					_ipt_source="iifname ${device} "
					msg=$(i18n "Source iface [%s]," "${device}")
				else
					msg=$(i18n "Source iface [%s]," $(i18n "All"))
				fi
				if [ -n "$(echo ${i} | grep '^iprange:')" ]; then
					_iprange=$(echo ${i} | sed 's#iprange:##g')
					_ipt_source=$(factor ${_iprange} "${_ipt_source}ip saddr")
					msg="${msg}$(i18n "IP range [%s]," "${_iprange}")"
					_ipv4="1"
					unset _iprange
				elif [ -n "$(echo ${i} | grep '^ipset:')" ]; then
					_ipset=$(echo ${i} | sed 's#ipset:##g')
					_ipt_source="${_ipt_source}ip daddr @${_ipset}"
					msg="${msg}Nftset$(i18n "[%s]," "${_ipset}")"
					unset _ipset
				elif [ -n "$(echo ${i} | grep '^ip:')" ]; then
					_ip=$(echo ${i} | sed 's#ip:##g')
					_ipt_source=$(factor ${_ip} "${_ipt_source}ip saddr")
					msg="${msg}IP$(i18n "[%s]," "${_ip}")"
					_ipv4="1"
					unset _ip
				elif [ -n "$(echo ${i} | grep '^mac:')" ]; then
					_mac=$(echo ${i} | sed 's#mac:##g')
					_ipt_source=$(factor ${_mac} "${_ipt_source}ether saddr")
					msg="${msg}MAC$(i18n "[%s]," "${_mac}")"
					unset _mac
				elif [ -n "$(echo ${i} | grep '^any')" ]; then
					msg="${msg}$(i18n "All device,")"
				else
					continue
				fi
				msg="${msg1}${msg}"
				
				[ -n "$tcp_no_redir_ports" ] && {
					if ! has_1_65535 "$tcp_no_redir_ports"; then
						nft "add rule $NFTABLE_NAME $nft_prerouting_chain ${_ipt_source} ip protocol tcp $(factor $tcp_no_redir_ports "tcp dport") counter return comment \"$remarks\""
						[ "$_ipv4" != "1" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 ${_ipt_source} meta l4proto tcp $(factor $tcp_no_redir_ports "tcp dport") counter return comment \"$remarks\""
						log 2 "${msg}$(i18n "not proxy %s port [%s]" "TCP" "${tcp_no_redir_ports}")"
					else
						# It will return when it ends, so no extra rules are needed.
						no_tcp_proxy="1"
						log 2 "${msg}$(i18n "not proxy all %s" "TCP")"
					fi
				}
				
				[ -n "$udp_no_redir_ports" ] && {
					if ! has_1_65535 "$udp_no_redir_ports"; then
						nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_no_redir_ports "udp dport") counter return comment \"$remarks\""
						[ "$_ipv4" != "1" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_no_redir_ports "udp dport") counter return comment \"$remarks\"" 2>/dev/null
						log 2 "${msg}$(i18n "not proxy %s port [%s]" "UDP" "${udp_no_redir_ports}")"
					else
						# It will return when it ends, so no extra rules are needed.
						no_udp_proxy="1"
						log 2 "${msg}$(i18n "not proxy all %s" "UDP")"
					fi
				}

				if ([ -z "$no_tcp_proxy" ] || [ -z "$no_udp_proxy" ]) && [ -n "$dns_redirect_port" ]; then
					nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} udp dport 53 counter accept"
					nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp ${_ipt_source} tcp dport 53 counter accept"
					nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} udp dport 53 counter accept" 2>/dev/null
					nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} tcp dport 53 counter accept" 2>/dev/null
					nft "add rule $NFTABLE_NAME PSW2_DNS meta l4proto udp ${_ipt_source} udp dport 53 counter redirect to :$dns_redirect_port comment \"$remarks\""
					nft "add rule $NFTABLE_NAME PSW2_DNS meta l4proto tcp ${_ipt_source} tcp dport 53 counter redirect to :$dns_redirect_port comment \"$remarks\""
					log 2 "${msg}$(i18n "DNS will redirected to the dedicated DNS server [%s]." "${dns_redirect_port}")"
				else
					nft "add rule $NFTABLE_NAME PSW2_DNS meta l4proto udp ${_ipt_source} udp dport 53 counter return comment \"$remarks\"" 2>/dev/null
					nft "add rule $NFTABLE_NAME PSW2_DNS meta l4proto tcp ${_ipt_source} tcp dport 53 counter return comment \"$remarks\"" 2>/dev/null
				fi

				[ -z "$no_tcp_proxy" ] && [ -n "$redir_port" ] && {
					msg2="${msg}$(i18n "Use the %s node [%s]" "TCP" "${node_remarks}")"
					if [ -n "${is_tproxy}" ]; then
						msg2="${msg2}(TPROXY:${redir_port})"
						nft_chain="PSW2_MANGLE"
						nft_j="counter jump PSW2_RULE"
					else
						msg2="${msg2}(REDIRECT:${redir_port})"
						nft_chain="PSW2_NAT"
						nft_j="$(REDIRECT $redir_port)"
					fi

					[ "$accept_icmp" = "1" ] && {
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr $FAKE_IP $(REDIRECT) comment \"$remarks\""
						add_shunt_t_rule "${shunt_list4}" "nft add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr" "$(REDIRECT)" "$remarks"
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp ${_ipt_source} $(REDIRECT) comment \"$remarks\""
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip protocol icmp ${_ipt_source} return comment \"$remarks\""
					}

					[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr $FAKE_IP_6 $(REDIRECT) comment \"$remarks\"" 2>/dev/null
						add_shunt_t_rule "${shunt_list6}" "nft add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr" "$(REDIRECT)" "$remarks" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} $(REDIRECT) comment \"$remarks\"" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} return comment \"$remarks\"" 2>/dev/null
					}

					nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} ip daddr $FAKE_IP ${nft_j} comment \"$remarks\""
					add_shunt_t_rule "${shunt_list4}" "nft add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr" "${nft_j}" "$remarks"
					nft "add rule $NFTABLE_NAME $nft_chain ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ${nft_j} comment \"$remarks\""
					[ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol tcp ${_ipt_source} $(REDIRECT $redir_port TPROXY4) comment \"$remarks\""

					[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] &&  {
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} ip6 daddr $FAKE_IP_6 counter jump PSW2_RULE comment \"$remarks\""
						add_shunt_t_rule "${shunt_list6}" "nft add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip6 daddr" "counter jump PSW2_RULE" "$remarks" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") counter jump PSW2_RULE comment \"$remarks\"" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(REDIRECT $redir_port TPROXY) comment \"$remarks\"" 2>/dev/null
					}
					log 2 "${msg2}"
				}
				nft "add rule $NFTABLE_NAME $nft_prerouting_chain ip protocol tcp ${_ipt_source} counter return comment \"$remarks\""
				[ "$_ipv4" != "1" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto tcp ${_ipt_source} counter return comment \"$remarks\"" 2>/dev/null

				[ -z "$no_udp_proxy" ] && [ -n "$redir_port" ] && {
					msg2="${msg}$(i18n "Use the %s node [%s]" "UDP" "${node_remarks}")(TPROXY:${redir_port})"

					nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} ip daddr $FAKE_IP counter jump PSW2_RULE comment \"$remarks\""
					add_shunt_t_rule "${shunt_list4}" "nft add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip daddr" "counter jump PSW2_RULE" "$remarks"
					nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") counter jump PSW2_RULE comment \"$remarks\""
					nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} $(REDIRECT $redir_port TPROXY4) comment \"$remarks\""

					[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} ip6 daddr $FAKE_IP_6 counter jump PSW2_RULE comment \"$remarks\""
						add_shunt_t_rule "${shunt_list6}" "nft add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip6 daddr" "counter jump PSW2_RULE" "$remarks" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") counter jump PSW2_RULE comment \"$remarks\"" 2>/dev/null
						nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} $(REDIRECT $redir_port TPROXY) comment \"$remarks\"" 2>/dev/null
					}
					log 2 "${msg2}"
				}
				nft "add rule $NFTABLE_NAME PSW2_MANGLE ip protocol udp ${_ipt_source} counter return comment \"$remarks\""
				[ "$_ipv4" != "1" ] && nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 meta l4proto udp ${_ipt_source} counter return comment \"$remarks\"" 2>/dev/null
				unset nft_chain nft_j _ipt_source msg msg2 _ipv4 no_tcp_proxy no_udp_proxy
			done
			unset msg1
		}
		unset dns_redirect_port
		unset $(cat "${TMP_ACL_PATH}/${sid}/var" | awk -F '=' '{print $1}' | tr "\n" " ")
	done
}

filter_haproxy() {
	[ "$(config_n_get @global_haproxy[0] balancing_enable 0)" != "1" ] && return
	for item in $(uci show $CONFIG | grep ".lbss=" | cut -d "'" -f 2); do
		get_host_ip ipv4 $(echo $item | awk -F ":" '{print $1}') 1
	done | insert_nftset $NFTSET_VPS "-1"
	log_i18n 1 "Add node to the load balancer is directly connected to %s[%s]." "nftset" "${NFTSET_VPS}"
}

filter_vps_addr() {
	for server_host in "$@"; do
		get_host_ip "ipv4" ${server_host}
	done | insert_nftset $NFTSET_VPS "-1"

	for server_host in "$@"; do
		get_host_ip "ipv6" ${server_host}
	done | insert_nftset $NFTSET_VPS6 "-1"
}

filter_vpsip() {
	local ipv4_addrs=$(uci show $CONFIG | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2 | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | grep -v "^127\.0\.0\.1$")
	[ -n "$ipv4_addrs" ] && {
		echo "$ipv4_addrs" | insert_nftset $NFTSET_VPS "-1"
		log_i18n 1 "Add all %s nodes to %s[%s] direct connection complete." "IPv4" "nftset" "${NFTSET_VPS}"
	}
	local ipv6_addrs=$(uci show $CONFIG | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
	[ -n "$ipv6_addrs" ] && {
		echo "$ipv6_addrs" | insert_nftset $NFTSET_VPS6 "-1"
		log_i18n 1 "Add all %s nodes to %s[%s] direct connection complete." "IPv6" "nftset" "${NFTSET_VPS6}"
	}
}

filter_server_port() {
	local address=${1}
	local port=${2}
	local stream=${3}
	stream=$(echo ${3} | tr 'A-Z' 'a-z')
	local _is_tproxy
	_is_tproxy=${is_tproxy}
	[ "$stream" == "udp" ] && _is_tproxy="TPROXY"

	for _ipt in 4 6; do
		[ "$_ipt" == "4" ] && _ip_type=ip
		[ "$_ipt" == "6" ] && _ip_type=ip6
		nft "list chain $NFTABLE_NAME $nft_output_chain" 2>/dev/null | grep -q "${address}:${port}"
		if [ $? -ne 0 ]; then
			nft "insert rule $NFTABLE_NAME $nft_output_chain meta l4proto $stream $_ip_type daddr $address $stream dport $port return comment \"${address}:${port}\"" 2>/dev/null
		fi
	done
}

filter_node() {
	local node=${1}
	local stream=${2}
	if [ -n "$node" ]; then
		local address=$(config_n_get $node address)
		local port=$(config_n_get $node port)
		[ -z "$address" ] && [ -z "$port" ] && {
			return 1
		}
		filter_server_port $address $port $stream
		filter_server_port $address $port $stream
	fi
}

filter_direct_node_list() {
	[ ! -s "$TMP_PATH/direct_node_list" ] && return
	for _node_id in $(cat $TMP_PATH/direct_node_list | awk '!seen[$0]++'); do
		filter_node "$_node_id" TCP
		filter_node "$_node_id" UDP
		unset _node_id
	done
}

del_script_mwan3() {
	[ -s "/etc/init.d/mwan3" ] && sed -i "/${CONFIG}/d" /etc/init.d/mwan3 >/dev/null 2>&1
}

add_script_mwan3() {
	del_script_mwan3
	[ -s "/etc/init.d/mwan3" ] && {
		sed -i '/start_service()/,/}/ s/^}/    \/usr\/share\/passwall2\/nftables.sh mwan3_start\n}/' /etc/init.d/mwan3
		sed -i '/stop_service().*{/a \    \/usr\/share\/passwall2\/nftables.sh mwan3_stop' /etc/init.d/mwan3
	}
}

MWAN3_RULE_ARGS="-m connmark --mark ${FWMARK}/0xffffffff -j RETURN"

mwan3_stop() {
	nft list chain ip mangle mwan3_hook >/dev/null 2>&1 || return 0
	local handles=$(nft -a list chain ip mangle mwan3_hook 2>/dev/null | grep "${FWMARK}" | awk -F '# handle ' '{print$2}')
	for handle in $handles; do
		nft delete rule ip mangle mwan3_hook handle ${handle} 2>/dev/null
	done
	while iptables -w 5 -t mangle -D mwan3_hook ${MWAN3_RULE_ARGS} >/dev/null 2>&1; do :; done
}

mwan3_start() {
	nft list chain ip mangle mwan3_hook >/dev/null 2>&1 || return 0
	mwan3_stop
	iptables -w 5 -t mangle -I mwan3_hook 1 ${MWAN3_RULE_ARGS} >/dev/null 2>&1 || \
		logger -t passwall2 "mwan3: failed to add ${FWMARK} exemption rule to mangle/mwan3_hook"
}

# 直连集合的内容：direct_ip（含 geoip 代码）、LAN 网段与 ISP DNS。启动时直接写入，热刷新时写入同一事务。
fill_direct_sets() {
	for ip in $(cat /usr/share/passwall2/direct_ip | tr -s "\r\n" "\n" | grep -v "^#" | sed -e "/^$/d"); do
		if [[ "$ip" == *::* ]]; then
			echo "$ip" | insert_nftset $NFTSET_DIRECT6 "-1"
		elif [[ "$ip" == "geoip:"* ]]; then
			local _geoip_code=$(echo $ip | awk -F ':' '{print $2}')
			get_geoip $_geoip_code ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | insert_nftset $NFTSET_DIRECT "-1"
			get_geoip $_geoip_code ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | insert_nftset $NFTSET_DIRECT6 "-1"
		else
			echo "$ip" | insert_nftset $NFTSET_DIRECT "-1"
		fi
	done

	# Ignore special IP ranges
	local lan_ifname lan_ip
	lan_ifname=$(uci -q -p /tmp/state get network.lan.ifname)
	[ -n "$lan_ifname" ] && {
		lan_ip=$(ip address show $lan_ifname | grep -w "inet" | awk '{print $2}')
		lan_ip6=$(ip address show $lan_ifname | grep -w "inet6" | awk '{print $2}')
		#log_i18n 1 "local network segments (%s) direct connection: %s" "IPv4" "${lan_ip}"
		#log_i18n 1 "local network segments (%s) direct connection: %s" "IPv6" "${lan_ip6}"

		[ -n "$lan_ip" ] && echo $lan_ip | insert_nftset $NFTSET_DIRECT "-1"
		[ -n "$lan_ip6" ] && echo $lan_ip6 | insert_nftset $NFTSET_DIRECT6 "-1"
	}

	[ -n "$ISP_DNS" ] && {
		echo "$ISP_DNS" | insert_nftset $NFTSET_DIRECT "-1"
		[ -z "${NFT_SCRIPT}" ] && for ispip in $ISP_DNS; do
			log_i18n 1 "$(i18n "Add ISP %s DNS to the whitelist: %s" "IPv4" "${ispip}")"
		done
	}

	[ -n "$ISP_DNS6" ] && {
		echo $ISP_DNS6 | insert_nftset $NFTSET_DIRECT6 "-1"
		[ -z "${NFT_SCRIPT}" ] && for ispip6 in $ISP_DNS6; do
			log_i18n 1 "$(i18n "Add ISP %s DNS to the whitelist: %s" "IPv6" "${ispip6}")"
		done
	}
	return 0
}

update_wan_sets() {
	[ -z "$(command -v get_wan_ips)" ] && . "$UTILS_PATH"

	(
		flock -x 9 || exit 1

		local WAN_IP=$(get_wan_ips ip4)
		[ -n "$WAN_IP" ] && {
			# nft flush set $NFTABLE_NAME $NFTSET_WAN
			echo "$WAN_IP" | insert_nftset $NFTSET_WAN "-1"
		}

		local WAN6_IP=$(get_wan_ips ip6)
		[ -n "${WAN6_IP}" ] && {
			# nft flush set $NFTABLE_NAME $NFTSET_WAN6
			echo "$WAN6_IP" | insert_nftset $NFTSET_WAN6 "-1"
		}
	) 9>"${LOCK_PATH}/${CONFIG}_update_wan_sets.lock"
}

add_firewall_rule() {
	log_i18n 0 "Starting to load %s firewall rules..." "nftables"
	gen_nft_tables
	# 影子启动不触碰其它程序的规则；提交后由热重载补做。
	[ -z "${PW2_STAGE}" ] && {
		add_script_mwan3
		mwan3_start
	}

	gen_nftset $NFTSET_LOCAL ipv4_addr 0 "-1"
	gen_nftset $NFTSET_DIRECT ipv4_addr 0 "-1"
	gen_nftset $NFTSET_VPS ipv4_addr 0 "-1"
	gen_nftset $NFTSET_WAN ipv4_addr 0 "-1"

	gen_nftset $NFTSET_LOCAL6 ipv6_addr 0 "-1"
	gen_nftset $NFTSET_DIRECT6 ipv6_addr 0 "-1"
	gen_nftset $NFTSET_VPS6 ipv6_addr 0 "-1"
	gen_nftset $NFTSET_WAN6 ipv6_addr 0 "-1"

	get_local_ips ip4 | insert_nftset $NFTSET_LOCAL "-1"
	get_local_ips ip6 | insert_nftset $NFTSET_LOCAL6 "-1"

	fill_direct_sets
	update_wan_sets

	# Filter all node IPs
	# psw2_vps 只增不减（前置 DNS 也会写入）：影子启动不生成，提交后在正式表中照常补充。
	[ -z "${PW2_STAGE}" ] && {
		filter_vpsip > /dev/null 2>&1 &
		filter_haproxy > /dev/null 2>&1 &
		# Prevent some conditions
		filter_vps_addr $(config_n_get $NODE address) > /dev/null 2>&1 &
		filter_vps_addr $(config_n_get $NODE download_address) > /dev/null 2>&1 &
	}

	accept_icmp=$(config_n_get @global_forwarding[0] accept_icmp 0)
	accept_icmpv6=$(config_n_get @global_forwarding[0] accept_icmpv6 0)

	if [ "${TCP_PROXY_WAY}" = "redirect" ]; then
		unset is_tproxy
		nft_prerouting_chain="PSW2_NAT"
		nft_output_chain="PSW2_OUTPUT_NAT"
	elif [ "${TCP_PROXY_WAY}" = "tproxy" ]; then
		is_tproxy="TPROXY"
		nft_prerouting_chain="PSW2_MANGLE"
		nft_output_chain="PSW2_OUTPUT_MANGLE"
	fi

	nft "add chain $NFTABLE_NAME PSW2_DNS"
	nft "flush chain $NFTABLE_NAME PSW2_DNS"
	if [ $(config_n_get @global[0] dns_redirect "1") = "0" ]; then
		#Only hijack when dest address is local IP
		nft "insert rule $NFTABLE_NAME dstnat ip saddr @${NFTSET_DIRECT} ip daddr @${NFTSET_LOCAL} jump PSW2_DNS"
		nft "insert rule $NFTABLE_NAME dstnat ip6 saddr @${NFTSET_DIRECT6} ip6 daddr @${NFTSET_LOCAL6} jump PSW2_DNS"
	else
		nft "insert rule $NFTABLE_NAME dstnat ip saddr @${NFTSET_DIRECT} jump PSW2_DNS"
		nft "insert rule $NFTABLE_NAME dstnat ip6 saddr @${NFTSET_DIRECT6} jump PSW2_DNS"
	fi

	# for ipv4 ipv6 tproxy mark
	nft "add chain $NFTABLE_NAME PSW2_RULE"
	nft "flush chain $NFTABLE_NAME PSW2_RULE"
	nft "add rule $NFTABLE_NAME PSW2_RULE counter meta mark set ct mark"
	nft "add rule $NFTABLE_NAME PSW2_RULE meta mark ${FWMARK} counter return"
	nft "add rule $NFTABLE_NAME PSW2_RULE tcp flags & (fin|syn|rst|ack) == syn counter meta mark set ${FWMARK}"
	nft "add rule $NFTABLE_NAME PSW2_RULE meta l4proto udp ct state { new, related } counter meta mark set ${FWMARK}"
	nft "add rule $NFTABLE_NAME PSW2_RULE counter ct mark set mark"

	# 先启动各实例（核心、前置 DNS、直连写集合 DNS）：默认实例的分流子链要包含启动时登记的直连写集合，
	# 且生成器在分流规则变化时清空集合的动作必须发生在集合填充之前。
	log_i18n 1 "Access Control:"
	acl_node
	ACL_NODE_DONE=1

	# 默认实例的分流子链；热切换全局节点时整体原子替换。须在 PSW2_RULE 之后、主链跳转之前创建。
	local default_redir_port=$(sed -n 's/^redir_port="\(.*\)"$/\1/p' ${TMP_ACL_PATH}/acl_default/var 2>/dev/null)
	unset SHUNT_LIST4 SHUNT_LIST6
	[ -n "${default_redir_port}" ] && [ -n "${NODE}" ] && gen_shunt_list "${NODE}" SHUNT_LIST4 SHUNT_LIST6
	for chain in ${SHUNT_CHAINS}; do
		nft "add chain $NFTABLE_NAME ${chain}"
	done
	gen_shunt_chains "${default_redir_port}" | nft -f -

	#ipv4 tproxy mode and udp
	nft "add chain $NFTABLE_NAME PSW2_MANGLE"
	nft "flush chain $NFTABLE_NAME PSW2_MANGLE"
	nft "add rule $NFTABLE_NAME PSW2_MANGLE ip daddr @$NFTSET_VPS counter return"
	nft "add rule $NFTABLE_NAME PSW2_MANGLE ct direction reply counter return"
	nft "add chain $NFTABLE_NAME PSW2_OUTPUT_MANGLE"
	nft "flush chain $NFTABLE_NAME PSW2_OUTPUT_MANGLE"
	nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip daddr @$NFTSET_VPS counter return"
	nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ct direction reply counter return"
	nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE meta mark and 0xff == 0xff counter return"

	# jump chains
	# Only TCP, UDP Invalid.
	nft "add rule $NFTABLE_NAME mangle_prerouting meta nfproto ipv4 meta l4proto tcp socket transparent 1 mark set ${FWMARK} counter accept comment PSW2_SOCKET"

	nft "add rule $NFTABLE_NAME mangle_prerouting ip daddr != @$NFTSET_DIRECT ip protocol udp counter jump PSW2_MANGLE"
	[ -n "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME mangle_prerouting ip daddr != @$NFTSET_DIRECT ip protocol tcp counter jump PSW2_MANGLE"

	#ipv4 tcp redirect mode
	[ -z "${is_tproxy}" ] && {
		nft "add chain $NFTABLE_NAME PSW2_NAT"
		nft "flush chain $NFTABLE_NAME PSW2_NAT"
		nft "add rule $NFTABLE_NAME PSW2_NAT ip daddr @$NFTSET_VPS counter return"
		nft "add rule $NFTABLE_NAME dstnat ip daddr != @$NFTSET_DIRECT ip protocol tcp counter jump PSW2_NAT"

		nft "add chain $NFTABLE_NAME PSW2_OUTPUT_NAT"
		nft "flush chain $NFTABLE_NAME PSW2_OUTPUT_NAT"
		nft "add rule $NFTABLE_NAME PSW2_OUTPUT_NAT ip daddr @$NFTSET_VPS counter return"
		nft "add rule $NFTABLE_NAME PSW2_OUTPUT_NAT meta mark and 0xff == 0xff counter return"
	}

	#icmp ipv6-icmp redirect
	if [ "$accept_icmp" = "1" ]; then
		nft "add chain $NFTABLE_NAME PSW2_ICMP_REDIRECT"
		nft "flush chain $NFTABLE_NAME PSW2_ICMP_REDIRECT"
		nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip daddr @$NFTSET_VPS counter return"

		[ "$accept_icmpv6" = "1" ] && {
			nft "add rule $NFTABLE_NAME PSW2_ICMP_REDIRECT ip6 daddr @$NFTSET_VPS6 counter return"
		}

		nft "add rule $NFTABLE_NAME dstnat ip daddr != @$NFTSET_DIRECT meta l4proto icmp counter jump PSW2_ICMP_REDIRECT"
		nft "add rule $NFTABLE_NAME dstnat ip6 daddr != @$NFTSET_DIRECT6 meta l4proto icmpv6 counter jump PSW2_ICMP_REDIRECT"
		nft "add rule $NFTABLE_NAME nat_output ip daddr != @$NFTSET_DIRECT meta l4proto icmp counter jump PSW2_ICMP_REDIRECT"
		nft "add rule $NFTABLE_NAME nat_output ip6 daddr != @$NFTSET_DIRECT6 meta l4proto icmpv6 counter jump PSW2_ICMP_REDIRECT"
	fi

	#ipv4 wan_ip
	[ -z "${is_tproxy}" ] && nft "add rule $NFTABLE_NAME PSW2_NAT ip daddr @$NFTSET_WAN counter return comment \"WAN_IP_RETURN\""
	nft "add rule $NFTABLE_NAME PSW2_MANGLE ip daddr @$NFTSET_WAN counter return comment \"WAN_IP_RETURN\""

	[ -z "${PW2_STAGE}" ] && {
		ip rule add fwmark ${FWMARK} table 999 priority 999
		ip route add local 0.0.0.0/0 dev lo table 999
	}

	#ipv6 tproxy mode and udp
	nft "add chain $NFTABLE_NAME PSW2_MANGLE_V6"
	nft "flush chain $NFTABLE_NAME PSW2_MANGLE_V6"
	nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 ip6 daddr @$NFTSET_VPS6 counter return"
	nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 ct direction reply counter return"

	nft "add chain $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6"
	nft "flush chain $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6"
	nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_VPS6 counter return"
	nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 ct direction reply counter return"
	nft "add rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta mark and 0xff == 0xff counter return"

	[ -n "$RETURN_DNS" ] && {
		for _dns in $(echo $RETURN_DNS | tr ',' ' '); do
			local dns_address=$(echo $_dns | awk -F '#' '{print $1}')
			local dns_port=$(echo $_dns | awk -F '#' '{print $2}')
			local dns_proto=$(echo $_dns | awk -F '#' '{print $3}')
			dns_proto=${dns_proto:-udp}
			if [[ "$dns_address" == *::* ]]; then
				nft "insert rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE_V6 meta l4proto ${dns_proto} ip6 daddr ${dns_address} $(factor ${dns_port:-53} "${dns_proto} dport") counter return"
				log_i18n 1 "$(i18n "Add direct DNS to %s: %s" "nftables" "[${dns_address}]:${dns_port:-53}")"
			else
				nft "insert rule $NFTABLE_NAME PSW2_OUTPUT_MANGLE ip protocol ${dns_proto} ip daddr ${dns_address} $(factor ${dns_port:-53} "${dns_proto} dport") counter return"
				log_i18n 1 "$(i18n "Add direct DNS to %s: %s" "nftables" "${dns_address}:${dns_port:-53}")"
			fi
		done
	}

	# jump chains
	[ "$PROXY_IPV6" == "1" ] && {
		# Only TCP, UDP Invalid.
		nft "add rule $NFTABLE_NAME mangle_prerouting meta nfproto ipv6 meta l4proto tcp socket transparent 1 mark set ${FWMARK} counter accept comment PSW2_SOCKET"

		nft "add rule $NFTABLE_NAME mangle_prerouting ip6 daddr != @$NFTSET_DIRECT6 meta nfproto {ipv6} counter jump PSW2_MANGLE_V6"
		nft "add rule $NFTABLE_NAME mangle_output ip6 daddr != @$NFTSET_DIRECT6 meta nfproto {ipv6} counter jump PSW2_OUTPUT_MANGLE_V6 comment \"PSW2_OUTPUT_MANGLE\""
		nft "add rule $NFTABLE_NAME PSW2_MANGLE_V6 ip6 daddr @$NFTSET_WAN6 counter return comment \"WAN6_IP_RETURN\""

		[ -z "${PW2_STAGE}" ] && {
			ip -6 rule add fwmark ${FWMARK} table 999 priority 999
			ip -6 route add local ::/0 dev lo table 999
		}
	}

	load_acl

	# 影子启动同步生成直连节点的放行规则，使目标规则集完整。
	if [ -n "${PW2_STAGE}" ]; then
		filter_direct_node_list > /dev/null 2>&1
	else
		filter_direct_node_list > /dev/null 2>&1 &
	fi

	log_i18n 0 "%s firewall rules load complete!" "nftables"
}

del_firewall_rule() {
	for nft in "dstnat" "srcnat" "nat_output" "mangle_prerouting" "mangle_output"; do
		local handles=$(nft -a list chain $NFTABLE_NAME ${nft} 2>/dev/null | grep -E "PSW2_" | awk -F '# handle ' '{print$2}')
		for handle in $handles; do
			nft delete rule $NFTABLE_NAME ${nft} handle ${handle} 2>/dev/null
		done
	done

	for handle in $(nft -a list chains | grep -E "chain PSW2_" | grep -v -E "PSW2_RULE|PSW2_SHUNT_" | awk -F '# handle ' '{print$2}'); do
		nft delete chain $NFTABLE_NAME handle ${handle} 2>/dev/null
	done

	# 分流子链被上面的主链引用，又会跳转到 PSW2_RULE，须在两者之间删除。
	for handle in $(nft -a list chains | grep -E "chain PSW2_SHUNT_" | awk -F '# handle ' '{print$2}'); do
		nft delete chain $NFTABLE_NAME handle ${handle} 2>/dev/null
	done

	# Need to be removed at the end, otherwise it will show "Resource busy"
	nft delete chain $NFTABLE_NAME handle $(nft -a list chains | grep -E "PSW2_RULE" | awk -F '# handle ' '{print$2}') 2>/dev/null

	ip rule del fwmark ${FWMARK} 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table 999 2>/dev/null

	ip -6 rule del fwmark ${FWMARK} 2>/dev/null
	ip -6 route del local ::/0 dev lo table 999 2>/dev/null

	destroy_nftset $NFTSET_LOCAL
	destroy_nftset $NFTSET_WAN
	destroy_nftset $NFTSET_DIRECT
	destroy_nftset $NFTSET_VPS

	destroy_nftset $NFTSET_LOCAL6
	destroy_nftset $NFTSET_WAN6
	destroy_nftset $NFTSET_DIRECT6
	destroy_nftset $NFTSET_VPS6

	del_script_mwan3

	log_i18n 0 "Delete %s rules is complete." "nftables"
}

flush_nftset() {
	log_i18n 0 "Clear %s." "NFTSet"
	for _name in $(nft -a list sets | grep -E "psw2_" | awk -F 'set ' '{print $2}' | awk '{print $1}'); do
		destroy_nftset ${_name}
	done
}

flush_table() {
	nft flush table $NFTABLE_NAME
	nft delete table $NFTABLE_NAME
}

flush_include() {
	echo '#!/bin/sh' >$FWI
}

gen_include() {
	flush_include
	local nft_chain_file=$TMP_PATH/PSW2_RULE.nft
	echo '#!/bin/sh' > $nft_chain_file
	nft list table $NFTABLE_NAME >> $nft_chain_file

	local __nft=" "
	__nft=$(cat <<- EOF
		[ -z "\$(nft list chain $NFTABLE_NAME mangle_prerouting | grep PSW2)" ] && nft -f ${nft_chain_file}

		${MY_PATH} update_wan_sets
	EOF
	)

	cat <<-EOF >> $FWI
	${__nft}
	
	return 0
	EOF
	return 0
}

start() {
	[ "$ENABLED_DEFAULT_ACL" == 0 -a "$ENABLED_ACLS" == 0 ] && return
	add_firewall_rule
	[ -z "${PW2_STAGE}" ] && gen_include
}

stop() {
	[ -z "$(command -v log_i18n)" ] && . "$UTILS_PATH"
	del_firewall_rule
	[ $(config_n_get @global[0] flush_set "0") = "1" ] && {
		uci -q delete ${CONFIG}.@global[0].flush_set
		uci -q commit ${CONFIG}
		#flush_table
		flush_nftset
		rm -rf $TMP_PATH2/singbox*
		rm -rf $TMP_PATH2/geo_output
	}
	flush_include
}

arg1=$1
shift
case $arg1 in
insert_nftset)
	insert_nftset "$@"
	;;
filter_direct_node_list)
	[ -z "$(command -v config_n_get)" ] && . "$UTILS_PATH"
	# 直接调用（热重载、Socks 节点切换）时没有启动阶段的变量：按当前 TCP 转发方式确定本机输出链。
	[ -n "${nft_output_chain}" ] || {
		if [ "$(config_n_get @global_forwarding[0] tcp_proxy_way redirect)" = "tproxy" ]; then
			is_tproxy="TPROXY"
			nft_output_chain="PSW2_OUTPUT_MANGLE"
		else
			nft_output_chain="PSW2_OUTPUT_NAT"
		fi
	}
	filter_direct_node_list
	;;
filter_vpsip)
	[ -z "$(command -v config_n_get)" ] && . "$UTILS_PATH"
	filter_vpsip
	;;
filter_vps_addr)
	[ -z "$(command -v config_n_get)" ] && . "$UTILS_PATH"
	filter_vps_addr "$@"
	;;
mwan3_start)
	mwan3_start
	;;
mwan3_stop)
	mwan3_stop
	;;
update_wan_sets)
	update_wan_sets "$@"
	;;
shunt_ready)
	shunt_ready
	;;
shunt_switch)
	shunt_switch "$@"
	;;
refresh_sets)
	refresh_sets "$@"
	;;
post_reconcile)
	# 差量热重载提交防火墙事务之后：恢复与其它程序的协作（mwan3）并重写防火墙重载时的恢复脚本。
	[ -z "$(command -v log_i18n)" ] && . "$UTILS_PATH"
	add_script_mwan3
	mwan3_start
	gen_include
	;;
clear)
	# 差量热重载的目标状态不再需要透明代理规则：只删除规则，不处理 flush_set。
	[ -z "$(command -v log_i18n)" ] && . "$UTILS_PATH"
	del_firewall_rule
	flush_include
	;;
stop)
	stop
	;;
start)
	start
	;;
*) ;;
esac
