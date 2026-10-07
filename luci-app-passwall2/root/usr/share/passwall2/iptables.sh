#!/bin/sh

DIR="$(cd "$(dirname "$0")" && pwd)"
MY_PATH=$DIR/iptables.sh
UTILS_PATH=$DIR/utils.sh
IPSET_LOCAL="psw2_local"
IPSET_DIRECT="psw2_direct"
IPSET_VPS="psw2_vps"
IPSET_WAN="psw2_wan"

IPSET_LOCAL6="psw2_local6"
IPSET_DIRECT6="psw2_direct6"
IPSET_VPS6="psw2_vps6"
IPSET_WAN6="psw2_wan6"

FWMARK="0x50535732"
# 使用默认实例（全局节点及跟随全局的访问控制）的分流项放在共享子链中，热切换全局节点时用 iptables-restore --noflush 原子替换。
# 子链命中直连项时置一次性标记位，主链紧接的规则按它 goto 清标记链（结束后返回主链的调用者），等同于原先在主链中 RETURN。
SHUNT_DIRECT_MARK="0x80000000"
SHUNT_MARK_KEEP="0x7fffffff"
SHUNT_HELPER_CHAINS="PSW2_SHUNT_DIRECT PSW2_SHUNT_RETURN"
SHUNT_CHAINS="PSW2_SHUNT_NAT PSW2_SHUNT_ICMP PSW2_SHUNT_ICMP6 PSW2_SHUNT_MARK PSW2_SHUNT_MARK6"

ipt=$(command -v iptables-legacy || command -v iptables)
ip6t=$(command -v ip6tables-legacy || command -v ip6tables)
IPT_BIN=$ipt
IP6T_BIN=$ip6t

# 规则配方：启动、热重载与运行时改动经 ipt_run 执行的 iptables 命令按顺序记录在 $TMP_PATH/ipt.log
# （每行一条，字段以 \037 分隔；iptables-restore 与 ipset -R 的输入以 \036 结束）。
# 差量热重载据此判断防火墙是否需要变化；影子启动（PW2_STAGE）只记录、不执行，查询由 reconcile.lua 模拟。
IPT_LOG=${TMP_PATH:-/tmp/etc/passwall2}/ipt.log
RECONCILE_LUA=${PW2_RECONCILE_LUA:-/usr/lib/lua/luci/passwall2/reconcile.lua}

ipt_record() {
	[ -d "${IPT_LOG%/*}" ] || return 0
	{
		printf '%s' "$1"
		shift
		for _arg in "$@"; do printf '\037%s' "${_arg}"; done
		printf '\n'
	} >> "${IPT_LOG}"
}

# 查询命令（-L、-nL 等）不改变规则，不记录。
ipt_query() {
	local _arg
	for _arg in "$@"; do
		case "${_arg}" in --list|-L|-[a-zA-Z]*L*) return 0 ;; esac
	done
	return 1
}

ipt_run() {
	local family=$1 table=$2 bin=$IPT_BIN
	shift 2
	[ "${family}" = "6" ] && bin=$IP6T_BIN
	if [ -n "${PW2_STAGE}" ]; then
		if ipt_query "$@"; then
			lua "${RECONCILE_LUA}" ipt-list "${IPT_LOG}" "${family}" "${table}" "$@"
			return $?
		fi
		ipt_record C "${family}" "${table}" "$@"
		return 0
	fi
	ipt_query "$@" || ipt_record C "${family}" "${table}" "$@"
	$bin -t "${table}" -w "$@"
}

# 一个地址族的 iptables-restore --noflush 输入（标准输入）；影子启动只记录。
ipt_restore() {
	local family=$1
	local input=$(cat)
	ipt_record R "${family}"
	{ echo "${input}"; printf '\036\n'; } >> "${IPT_LOG}" 2>/dev/null
	[ -n "${PW2_STAGE}" ] && return 0
	if [ "${family}" = "6" ]; then
		echo "${input}" | ${IP6T_BIN}-restore --noflush
	else
		echo "${input}" | ${IPT_BIN}-restore --noflush
	fi
}

# 影子启动中的 ipset：查询照常读取系统，修改只记录（由热重载提交时按集合语义应用）。
[ -n "${PW2_STAGE}" ] && ipset() {
	case " $* " in
		*" list "*|*" -L "*|*" test "*) command ipset "$@"; return $? ;;
	esac
	ipt_record S "$@"
	case " $* " in
		*" -R "*|*" restore "*) { cat; printf '\036\n'; } >> "${IPT_LOG}" ;;
	esac
	return 0
}

ipt_n="ipt_run 4 nat"
ipt_m="ipt_run 4 mangle"
ip6t_n="ipt_run 6 nat"
ip6t_m="ipt_run 6 mangle"
[ -z "$ip6t" -o -z "$(lsmod | grep 'ip6table_nat')" ] && ip6t_n="eval #$ip6t_n"
[ -z "$ip6t" -o -z "$(lsmod | grep 'ip6table_mangle')" ] && ip6t_m="eval #$ip6t_m"
FWI=$(uci -q get firewall.passwall2.path 2>/dev/null)
FAKE_IP="198.18.0.0/16"
FAKE_IP_6="2001:2::/48"

factor() {
	if [ -z "$1" ] || [ -z "$2" ]; then
		echo ""
	elif [ "$1" == "1:65535" ]; then
		echo ""
	else
		echo "$2 $1"
	fi
}

dst() {
	echo "-m set $2 --match-set $1 dst"
}

comment() {
	local name=$(echo $1 | sed 's/ /_/g')
	echo "-m comment --comment "${name}""
}

# Resolves invalid IP addresses for ports exceeding 15; it supports single ports and port ranges.
add_port_rules() {
	local ipt_cmd="$1"
	local port_list="$2"
	local target="$3"
	echo "$port_list" | grep -vq '[0-9]' && return
	port_list=$(echo "$port_list" | tr -d ' ' | sed 's/-/:/g' | tr ',' '\n' | awk '!a[$0]++' | grep -v '^$')
	[ -z "$port_list" ] && return
	if echo "$port_list" | grep -q '^1:65535$'; then
		eval "$ipt_cmd $target"
		return
	fi
	local multiport_ports=""
	local range_ports=""
	local count=0
	local port
	for port in $port_list; do
		if echo "$port" | grep -q ':'; then
			range_ports="$range_ports $port"
		else
			multiport_ports="$multiport_ports,$port"
			count=$((count + 1))
			if [ "$count" -eq 15 ]; then
				eval "$ipt_cmd -m multiport --dport ${multiport_ports#,} $target"
				multiport_ports=""
				count=0
			fi
		fi
	done
	if [ -n "$multiport_ports" ]; then
		eval "$ipt_cmd -m multiport --dport ${multiport_ports#,} $target"
	fi
	for port in $range_ports; do
		eval "$ipt_cmd --dport $port $target"
	done
}

destroy_ipset() {
	for i in "$@"; do
		ipset -q -F $i
		ipset -q -X $i
	done
}

insert_rule_before() {
	[ $# -ge 3 ] || {
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$keyword" | head -n 1 | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		$ipt_tmp -A $chain $rule
	else
		if [ -z "${_index}" ]; then
			_index=${default_index}
		fi
		$ipt_tmp -I $chain $_index $rule
	fi
}

insert_rule_after() {
	[ $# -ge 3 ] || {
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$keyword" | awk 'END {print}' | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		$ipt_tmp -A $chain $rule
	else
		if [ -n "${_index}" ]; then
			_index=$((_index + 1))
		else
			_index=${default_index}
		fi
		$ipt_tmp -I $chain $_index $rule
	fi
}

RULE_LAST_INDEX() {
	[ $# -ge 3 ] || {
		log_i18n 1 "Incorrect index listing method (%s), execution terminated!" "iptables"
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local list="${1}"; shift
	local default="${1:-0}"; shift
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$list" | head -n 1 | awk '{print $1}')
	echo "${_index:-${default}}"
}

REDIRECT() {
	local s="-j REDIRECT"
	[ -n "$1" ] && {
		local s="$s --to-ports $1"
		[ "$2" == "TPROXY" ] && {
			local mark="-m mark --mark ${FWMARK}"
			s="${mark} -j TPROXY --on-port $1"
		}
	}
	echo $s
}

get_redirect_ipt() {
	echo "$(REDIRECT $2 $3)"
}

get_redirect_ip6t() {
	echo "$(REDIRECT $2 $3)"
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
					local ipset_v4="psw2_${node}_${shunt_id}"
					local ipset_v6="psw2_${node}_${shunt_id}6"
					local outbound="redirect"
					[ "$shunt_node" = "_direct" ] && outbound="direct"
					[ "$shunt_node" = "_default" ] && outbound="${default_outbound}"
					_SHUNT_LIST4="${_SHUNT_LIST4} ${ipset_v4}:${outbound}"
					_SHUNT_LIST6="${_SHUNT_LIST6} ${ipset_v6}:${outbound}"
					# 热切换或同一节点再次使用时，已存在的集合沿用已载入的内容，避免重复解析 GeoIP。
					[ -n "${SHUNT_PRESERVE_SETS}" ] && ipset -q list -n $ipset_v4 >/dev/null && \
						ipset -q list -n $ipset_v6 >/dev/null && continue
					# 影子启动：运行中已有的规则集合沿用原内容（内容变化由集合热刷新处理）。
					[ -n "${PW2_STAGE}" ] && [ -z "${PW2_STAGE_REFRESH}" ] && ipset -q list -n $ipset_v4 >/dev/null && \
						ipset -q list -n $ipset_v6 >/dev/null && {
						echo "$ipset_v4 $ipset_v6" >> "$TMP_PATH/preserved_sets"
						continue
					}
					ipset -! create $ipset_v4 nethash maxelem 1048576
					ipset -! create $ipset_v6 nethash family inet6 maxelem 1048576
					# 热刷新：写入临时集合，全部完成后由 refresh_sets 用 ipset swap 逐个原子替换。
					local fill_v4=$ipset_v4 fill_v6=$ipset_v6
					[ -n "${IPSET_REFRESH}" ] && {
						fill_v4=$(refresh_set $ipset_v4 nethash maxelem 1048576)
						fill_v6=$(refresh_set $ipset_v6 nethash family inet6 maxelem 1048576)
					}

					config_n_get $shunt_id ip_list | sed 's/#.*//' | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $fill_v4 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
					config_n_get $shunt_id ip_list | sed 's/#.*//' | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $fill_v6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
					[ "${enable_geoview_ip}" = "1" ] && {
						local _geoip_code=$(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
						[ -n "$_geoip_code" ] && {
							get_geoip $_geoip_code ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $fill_v4 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
							get_geoip $_geoip_code ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $fill_v6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
							#log 3 "$(i18n "parse the traffic splitting rules[%s]-[geoip:%s] add to %s to complete." "${shunt_id}" "${_geoip_code}" "IPSET[${ipset_v4},${ipset_v6}]")"
						}
					}
				}
			done
		}
		local direct_ipset4=$(get_cache_var "node_${node}_direct_ipset4")
		[ -n "${direct_ipset4}" ] && {
			ipset -! create ${direct_ipset4} iphash maxelem 1048576 timeout 259200
			# 热刷新按上游 flush_set 语义清空直连写集合，由 DNS 重新写入。
			[ -n "${IPSET_REFRESH}" ] && ipset -q flush ${direct_ipset4}
			_SHUNT_LIST4="${_SHUNT_LIST4} ${direct_ipset4}:direct"
		}
		local direct_ipset6=$(get_cache_var "node_${node}_direct_ipset6")
		[ -n "${direct_ipset6}" ] && {
			ipset -! create ${direct_ipset6} iphash family inet6 maxelem 1048576 timeout 259200
			[ -n "${IPSET_REFRESH}" ] && ipset -q flush ${direct_ipset6}
			_SHUNT_LIST6="${_SHUNT_LIST6} ${direct_ipset6}:direct"
		}
	}
	[ -n "${_SHUNT_LIST4}" ] && eval ${shunt_list4_var_name}=\"${_SHUNT_LIST4}\"
	[ -n "${_SHUNT_LIST6}" ] && eval ${shunt_list6_var_name}=\"${_SHUNT_LIST6}\"
	set_cache_var "node_${node}_gen_shunt_list" "1"
}

# 热刷新用的临时集合：名字由正式集合名的摘要得出（ipset 名最长 31 字符），记录待 refresh_sets 交换。
refresh_set() {
	local real=${1}; shift
	local tmp="psw2_r$(echo -n "${real}" | md5sum | cut -c1-12)"
	ipset -q destroy ${tmp}
	ipset -! create ${tmp} "$@"
	echo "${tmp} ${real}" >> "${IPSET_REFRESH}"
	echo ${tmp}
}

add_shunt_t_rule() {
	local shunt_args=${1}
	local t_args=${2}
	local t_jump_args=${3}
	local t_ports_args=${4}
	if [ "${shunt_args}" = "@global" ]; then
		# 默认实例的分流项在共享子链中：按原来的端口限制跳转（打标记的子链跳过已由代理接管的连接，
		# 与 nftables 的 ct mark 条件一致）；子链命中直连项时置标记，下一条规则据此结束本主链。
		local chain guard=""
		case "${t_args}" in
			*"ipt_run 6 mangle"*) chain="PSW2_SHUNT_MARK6"; guard="-m connmark ! --mark ${FWMARK}" ;;
			*"ipt_run 4 mangle"*) chain="PSW2_SHUNT_MARK"; guard="-m connmark ! --mark ${FWMARK}" ;;
			*"-p ipv6-icmp"*) chain="PSW2_SHUNT_ICMP6" ;;
			*"-p icmp"*) chain="PSW2_SHUNT_ICMP" ;;
			*) chain="PSW2_SHUNT_NAT" ;;
		esac
		if [ -z "${t_ports_args}" ] || [ "${t_ports_args}" == "1:65535" ]; then
			${t_args} ${guard} -j ${chain}
		else
			add_port_rules "${t_args}" "${t_ports_args}" "${guard} -j ${chain}"
		fi
		${t_args} -m mark --mark ${SHUNT_DIRECT_MARK}/${SHUNT_DIRECT_MARK} -g PSW2_SHUNT_RETURN
		return
	fi
	[ -n "${shunt_args}" ] && {
		for j in ${shunt_args}; do
			local _set_name=$(echo ${j} | awk -F ':' '{print $1}')
			local _outbound=$(echo ${j} | awk -F ':' '{print $2}')
			[ -n "${_set_name}" ] && [ -n "${_outbound}" ] && {
				local _t_arg="${t_jump_args}"
				[ "${_outbound}" = "direct" ] && _t_arg="-j RETURN"
				if [ -z "${t_ports_args}" ] || [ "${t_ports_args}" == "1:65535" ]; then
					${t_args} $(dst ${_set_name}) ${_t_arg}
				else
					add_port_rules "${t_args} $(dst ${_set_name})" "${t_ports_args}" "${_t_arg}"
				fi
			}
		done
	}
}

# 输出一个表的分流子链（先声明以清空，再填充），交给 iptables-restore --noflush 在该表的一次提交中原子替换。
gen_shunt_chains() {
	local family=${1}
	local table=${2}
	local redir_port=${3}
	local list chains chain verdict item set_name outbound
	list=${SHUNT_LIST4}
	[ "${family}" = "6" ] && list=${SHUNT_LIST6}
	case "${family}${table}" in
		4nat) chains="PSW2_SHUNT_NAT PSW2_SHUNT_ICMP" ;;
		4mangle) chains="PSW2_SHUNT_MARK" ;;
		6nat) chains="PSW2_SHUNT_ICMP6" ;;
		6mangle) chains="PSW2_SHUNT_MARK6" ;;
	esac
	echo "*${table}"
	for chain in ${chains} ${SHUNT_HELPER_CHAINS}; do
		echo ":${chain} - [0:0]"
	done
	echo "-A PSW2_SHUNT_DIRECT -j MARK --or-mark ${SHUNT_DIRECT_MARK}"
	echo "-A PSW2_SHUNT_RETURN -j MARK --and-mark ${SHUNT_MARK_KEEP}"
	[ -n "${redir_port}" ] && for chain in ${chains}; do
		case "${chain}" in
			PSW2_SHUNT_NAT) verdict="-p tcp $(REDIRECT ${redir_port})" ;;
			PSW2_SHUNT_ICMP|PSW2_SHUNT_ICMP6) verdict="$(REDIRECT)" ;;
			*) verdict="-j PSW2_RULE" ;;
		esac
		for item in ${list}; do
			set_name=${item%%:*}
			outbound=${item##*:}
			[ -n "${set_name}" ] && [ -n "${outbound}" ] || continue
			if [ "${outbound}" = "direct" ]; then
				echo "-A ${chain} $(dst ${set_name}) -g PSW2_SHUNT_DIRECT"
			else
				echo "-A ${chain} $(dst ${set_name}) ${verdict}"
			fi
		done
	done
	echo "COMMIT"
}

# 按当前 SHUNT_LIST4/6 建立或替换全部分流子链；IPv6 表不可用时跳过（与上游 ip6t_n/ip6t_m 的判断一致）。
apply_shunt_chains() {
	local redir_port=${1}
	{ gen_shunt_chains 4 nat "${redir_port}"; gen_shunt_chains 4 mangle "${redir_port}"; } | ipt_restore 4 || return 1
	case "${ip6t_n}" in
		"eval #"*) ;;
		*) gen_shunt_chains 6 nat "${redir_port}" | ipt_restore 6 || return 1 ;;
	esac
	case "${ip6t_m}" in
		"eval #"*) ;;
		*) gen_shunt_chains 6 mangle "${redir_port}" | ipt_restore 6 || return 1 ;;
	esac
}

shunt_ready() {
	$ipt_n -n -L PSW2_SHUNT_NAT >/dev/null 2>&1 && $ipt_m -n -L PSW2_SHUNT_MARK >/dev/null 2>&1 || return 2
}

# 热切换全局节点：只替换分流子链并补充新节点地址白名单；主链、DNS 劫持及其它规则保持不变。
shunt_switch() {
	local node=${1}
	local redir_port=${2}
	[ -n "${node}" ] && [ -n "${redir_port}" ] || return 1
	[ -z "$(command -v log_i18n)" ] && . "$UTILS_PATH"
	shunt_ready || return 2
	SHUNT_PRESERVE_SETS=1
	gen_shunt_list "${node}" SHUNT_LIST4 SHUNT_LIST6
	unset SHUNT_PRESERVE_SETS
	apply_shunt_chains "${redir_port}" || return 1
	filter_vps_addr $(config_n_get ${node} address) $(config_n_get ${node} download_address) >/dev/null 2>&1 &
	gen_include
}

# 规则数据或分流规则内容更新后的热刷新：由规则派生的集合写入临时集合后逐个 ipset swap，再原子替换默认实例的分流子链。
# 直连写集合按上游 flush_set 语义清空；独立访问控制实例只刷新集合内容（配置指纹保证集合名不变）。
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
	local var_file acl_use acl_node done_nodes=" " tmp real status=0
	IPSET_REFRESH="$TMP_PATH/refresh_sets.ipset"
	: > "${IPSET_REFRESH}"
	fill_direct_sets $(refresh_set $IPSET_DIRECT nethash maxelem 1048576) $(refresh_set $IPSET_DIRECT6 nethash family inet6 maxelem 1048576)
	for var_file in "${TMP_ACL_PATH}"/*/var; do
		[ -s "${var_file}" ] || continue
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
	while read -r tmp real; do
		ipset swap ${tmp} ${real} && ipset destroy ${tmp} || status=1
	done < "${IPSET_REFRESH}"
	unset IPSET_REFRESH
	[ "${status}" = 0 ] || return 1
	apply_shunt_chains "${redir_port}" || return 1
	gen_include
}

load_acl() {
	[ -n "${ACL_NODE_DONE}" ] || {
		log_i18n 1 "Access Control:"
		acl_node
	}
	for sid in $(jsonfilter -s "${ACL_JSON}" -e '$.acl[*].flag'); do
		eval local $(cat "${TMP_ACL_PATH}/${sid}/var")

		# 使用默认实例的条目跳转到共享分流子链；独立实例按各自节点生成静态规则（同一节点的集合只载入一次）。
		# 上游按“节点是否已生成过列表”跳过计算，列表变量会沿用上一条目的值。
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

		local ipt_tmp=$ipt_n
		[ -n "${is_tproxy}" ] && ipt_tmp=$ipt_m

		[ "${local_proxy}" = "1" ] && {
			msg="$(i18n "[Local],")"
			[ -n "$tcp_no_redir_ports" ] && {
				add_port_rules "$ipt_tmp -A PSW2_OUTPUT -p tcp" $tcp_no_redir_ports "-j RETURN"
				add_port_rules "$ip6t_m -A PSW2_OUTPUT -p tcp" $tcp_no_redir_ports "-j RETURN"
				if ! has_1_65535 "$tcp_no_redir_ports"; then
					log 2 "${msg}$(i18n "not proxy %s port [%s]" "TCP" "${tcp_no_redir_ports}")"
				else
					no_tcp_local_proxy="1"
					log 2 "${msg}$(i18n "not proxy all %s" "TCP")"
				fi
			}
			[ -n "$udp_no_redir_ports" ] && {
				add_port_rules "$ipt_m -A PSW2_OUTPUT -p udp" $udp_no_redir_ports "-j RETURN"
				add_port_rules "$ip6t_m -A PSW2_OUTPUT -p udp" $udp_no_redir_ports "-j RETURN"
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
					#$ipt_m -A PSW2_OUTPUT $(comment "${comment_l}") -p udp --dport 53 -j ACCEPT
					#$ipt_m -A PSW2_OUTPUT $(comment "${comment_l}") -p tcp --dport 53 -j ACCEPT
					#$ip6t_m -A PSW2_OUTPUT $(comment "${comment_l}") -p udp  --dport 53 -j ACCEPT 2>/dev/null
					#$ip6t_m -A PSW2_OUTPUT $(comment "${comment_l}") -p tcp --dport 53 -j ACCEPT 2>/dev/null
					$ipt_n -A OUTPUT $(comment "PSW2_DNS") -p udp -o lo --dport 53 -j REDIRECT --to-ports $dns_redirect_port
					$ip6t_n -A OUTPUT $(comment "PSW2_DNS") -p udp -o lo --dport 53 -j REDIRECT --to-ports $dns_redirect_port 2>/dev/null
					$ipt_n -A OUTPUT $(comment "PSW2_DNS") -p tcp -o lo --dport 53 -j REDIRECT --to-ports $dns_redirect_port
					$ip6t_n -A OUTPUT $(comment "PSW2_DNS") -p tcp -o lo --dport 53 -j REDIRECT --to-ports $dns_redirect_port 2>/dev/null
					log 2 "${msg}$(i18n "DNS will redirected to the dedicated DNS server [%s]." "${dns_redirect_port}")"
				}
			fi

			# Loading local router proxy TCP
			if [ -n "$node" ] && [ -z "$no_tcp_local_proxy" ]; then
				[ "$accept_icmp" = "1" ] && {
					$ipt_n -A OUTPUT $(dst $IPSET_DIRECT !) -p icmp -j PSW2_OUTPUT
					$ipt_n -A PSW2_OUTPUT -p icmp -d $FAKE_IP $(REDIRECT)
					add_shunt_t_rule "${shunt_list4}" "$ipt_n -A PSW2_OUTPUT -p icmp" "$(REDIRECT)"
					$ipt_n -A PSW2_OUTPUT -p icmp $(REDIRECT)
				}

				[ "$accept_icmpv6" = "1" ] && {
					$ip6t_n -A OUTPUT $(dst $IPSET_DIRECT6 !) -p ipv6-icmp -j PSW2_OUTPUT
					$ip6t_n -A PSW2_OUTPUT -p ipv6-icmp -d $FAKE_IP_6 $(REDIRECT)
					add_shunt_t_rule "${shunt_list6}" "$ip6t_n -A PSW2_OUTPUT -p ipv6-icmp" "$(REDIRECT)"
					$ip6t_n -A PSW2_OUTPUT -p ipv6-icmp $(REDIRECT)
				}

				msg2="${msg}$(i18n "Use the %s node [%s]" "TCP" "${node_remarks}")"
				if [ -n "${is_tproxy}" ]; then
					msg2="${msg2}(TPROXY:${redir_port})"
					ipt_j="-j PSW2_RULE"
				else
					msg2="${msg2}(REDIRECT:${redir_port})"
					ipt_j="$(REDIRECT $redir_port)"
				fi

				$ipt_tmp -A PSW2_OUTPUT -p tcp -d $FAKE_IP ${ipt_j}
				add_shunt_t_rule "${shunt_list4}" "$ipt_tmp -A PSW2_OUTPUT -p tcp" "${ipt_j}" $tcp_redir_ports
				add_port_rules "$ipt_tmp -A PSW2_OUTPUT -p tcp" $tcp_redir_ports "${ipt_j}"
				[ -z "${is_tproxy}" ] && $ipt_n -A OUTPUT $(dst $IPSET_DIRECT !) -p tcp -j PSW2_OUTPUT
				[ -n "${is_tproxy}" ] && {
					$ipt_m -A PSW2 $(comment "${comment_l}") -p tcp -i lo $(REDIRECT $redir_port TPROXY)
					$ipt_m -A PSW2 $(comment "${comment_l}") -p tcp -i lo -j RETURN
					insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) $(dst $IPSET_DIRECT !) -p tcp -j PSW2_OUTPUT"
				}

				[ "$PROXY_IPV6" == "1" ] && {
					$ip6t_m -A PSW2_OUTPUT -p tcp -d $FAKE_IP_6 -j PSW2_RULE
					add_shunt_t_rule "${shunt_list6}" "$ip6t_m -A PSW2_OUTPUT -p tcp" "-j PSW2_RULE" $tcp_redir_ports
					add_port_rules "$ip6t_m -A PSW2_OUTPUT -p tcp" $tcp_redir_ports "-j PSW2_RULE"
					$ip6t_m -A PSW2 $(comment "${comment_l}") -p tcp -i lo $(REDIRECT $redir_port TPROXY)
					$ip6t_m -A PSW2 $(comment "${comment_l}") -p tcp -i lo -j RETURN
					insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) $(dst $IPSET_DIRECT6 !) -p tcp -j PSW2_OUTPUT"
				}

				[ -d "${TMP_IFACE_PATH}" ] && {
					for iface in $(ls ${TMP_IFACE_PATH}); do
						$ipt_n -A PSW2_OUTPUT -o $iface -p tcp -j RETURN
						$ipt_m -A PSW2_OUTPUT -o $iface -p tcp -j RETURN
					done
				}
				log 2 "${msg2}"
			fi

			# Loading local router proxy UDP
			if [ -n "$node" ] && [ -z "$no_udp_local_proxy" ]; then
				msg2="${msg}$(i18n "Use the %s node [%s]" "UDP" "${node_remarks}")(TPROXY:${redir_port})"
				$ipt_m -A PSW2_OUTPUT -p udp -d $FAKE_IP -j PSW2_RULE
				add_shunt_t_rule "${shunt_list4}" "$ipt_m -A PSW2_OUTPUT -p udp" "-j PSW2_RULE" $udp_redir_ports
				add_port_rules "$ipt_m -A PSW2_OUTPUT -p udp" $udp_redir_ports "-j PSW2_RULE"
				$ipt_m -A PSW2 $(comment "${comment_l}") -p udp -i lo $(REDIRECT $redir_port TPROXY)
				$ipt_m -A PSW2 $(comment "${comment_l}") -p udp -i lo -j RETURN
				insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) $(dst $IPSET_DIRECT !) -p udp -j PSW2_OUTPUT"

				[ "$PROXY_IPV6" == "1" ] && {
					$ip6t_m -A PSW2_OUTPUT -p udp -d $FAKE_IP_6 -j PSW2_RULE
					add_shunt_t_rule "${shunt_list6}" "$ip6t_m -A PSW2_OUTPUT -p udp" "-j PSW2_RULE" $udp_redir_ports
					add_port_rules "$ip6t_m -A PSW2_OUTPUT -p udp" $udp_redir_ports "-j PSW2_RULE"
					$ip6t_m -A PSW2 $(comment "${comment_l}") -p udp -i lo $(REDIRECT $redir_port TPROXY)
					$ip6t_m -A PSW2 $(comment "${comment_l}") -p udp -i lo -j RETURN
					insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) $(dst $IPSET_DIRECT6 !) -p udp -j PSW2_OUTPUT"
				}

				[ -d "${TMP_IFACE_PATH}" ] && {
					for iface in $(ls ${TMP_IFACE_PATH}); do
						$ipt_n -A PSW2_OUTPUT -o $iface -p udp -j RETURN
						$ipt_m -A PSW2_OUTPUT -o $iface -p udp -j RETURN
					done
				}

				log 2 "${msg2}"
			fi

			$ipt_m -I OUTPUT $(comment "mangle-OUTPUT-PSW2") -o lo -j RETURN
			insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) -m mark --mark ${FWMARK} -j RETURN"
			
			$ip6t_m -I OUTPUT $(comment "mangle-OUTPUT-PSW2") -o lo -j RETURN
			insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) -m mark --mark ${FWMARK} -j RETURN"

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
					_ipt_source="-i ${device} "
					msg=$(i18n "Source iface [%s]," "${device}")
				else
					msg=$(i18n "Source iface [%s]," $(i18n "All"))
				fi
				if [ -n "$(echo ${i} | grep '^iprange:')" ]; then
					_iprange=$(echo ${i} | sed 's#iprange:##g')
					_ipt_source=$(factor ${_iprange} "${_ipt_source}-m iprange --src-range")
					msg="${msg}$(i18n "IP range [%s]," "${_iprange}")"
					_ipv4="1"
					unset _iprange
				elif [ -n "$(echo ${i} | grep '^ipset:')" ]; then
					_ipset=$(echo ${i} | sed 's#ipset:##g')
					msg="${msg}IPset$(i18n "[%s]," "${_ipset}")"
					ipset -q list ${_ipset} >/dev/null
					if [ $? -eq 0 ]; then
						_ipt_source="${_ipt_source}-m set --match-set ${_ipset} src"
						unset _ipset
					else
						log 2 "$(i18n "[%s]," "${remarks}")${msg}$(i18n "Does not exist, ignore.")"
						unset _ipset
						continue
					fi
				elif [ -n "$(echo ${i} | grep '^ip:')" ]; then
					_ip=$(echo ${i} | sed 's#ip:##g')
					_ipt_source=$(factor ${_ip} "${_ipt_source}-s")
					msg="${msg}IP$(i18n "[%s]," "${_ip}")"
					_ipv4="1"
					unset _ip
				elif [ -n "$(echo ${i} | grep '^mac:')" ]; then
					_mac=$(echo ${i} | sed 's#mac:##g')
					_ipt_source=$(factor ${_mac} "${_ipt_source}-m mac --mac-source")
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
						[ "$_ipv4" != "1" ] && add_port_rules "$ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp" $tcp_no_redir_ports "-j RETURN" 2>/dev/null
						add_port_rules "$ipt_tmp -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp" $tcp_no_redir_ports "-j RETURN"
						log 2 "${msg}$(i18n "not proxy %s port [%s]" "TCP" "${tcp_no_redir_ports}")"
					else
						# It will return when it ends, so no extra rules are needed.
						no_tcp_proxy="1"
						log 2 "${msg}$(i18n "not proxy all %s" "TCP")"
					fi
				}
				
				[ -n "$udp_no_redir_ports" ] && {
					if ! has_1_65535 "$udp_no_redir_ports"; then
						[ "$_ipv4" != "1" ] && add_port_rules "$ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp" $udp_no_redir_ports "-j RETURN" 2>/dev/null
						add_port_rules "$ipt_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp" $udp_no_redir_ports "-j RETURN"
						log 2 "${msg}$(i18n "not proxy %s port [%s]" "UDP" "${udp_no_redir_ports}")"
					else
						# It will return when it ends, so no extra rules are needed.
						no_udp_proxy="1"
						log 2 "${msg}$(i18n "not proxy all %s" "UDP")"
					fi
				}
				
				if ([ -z "$no_tcp_proxy" ] || [ -z "$no_udp_proxy" ]) && [ -n "$dns_redirect_port" ]; then
					$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j ACCEPT
					$ipt_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j ACCEPT
					$ip6t_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j ACCEPT 2>/dev/null
					$ip6t_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j ACCEPT 2>/dev/null
					$ipt_n -A PSW2_DNS $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j REDIRECT --to-ports $dns_redirect_port
					$ip6t_n -A PSW2_DNS $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j REDIRECT --to-ports $dns_redirect_port 2>/dev/null
					$ipt_n -A PSW2_DNS $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j REDIRECT --to-ports $dns_redirect_port
					$ip6t_n -A PSW2_DNS $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j REDIRECT --to-ports $dns_redirect_port 2>/dev/null
					log 2 "${msg}$(i18n "DNS will redirected to the dedicated DNS server [%s]." "${dns_redirect_port}")"
				else
					$ipt_n -A PSW2_DNS $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j RETURN
					$ip6t_n -A PSW2_DNS $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j RETURN 2>/dev/null
					$ipt_n -A PSW2_DNS $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j RETURN
					$ip6t_n -A PSW2_DNS $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j RETURN 2>/dev/null
				fi

				[ -z "$no_tcp_proxy" ] && [ -n "$redir_port" ] && {
					msg2="${msg}$(i18n "Use the %s node [%s]" "TCP" "${node_remarks}")"
					if [ -n "${is_tproxy}" ]; then
						msg2="${msg2}(TPROXY:${redir_port})"
						ipt_j="-j PSW2_RULE"
					else
						msg2="${msg2}(REDIRECT:${redir_port})"
						ipt_j="$(REDIRECT $redir_port)"
					fi

					[ "$accept_icmp" = "1" ] && {
						$ipt_n -A PSW2 $(comment "$remarks") -p icmp ${_ipt_source} -d $FAKE_IP $(REDIRECT)
						add_shunt_t_rule "${shunt_list4}" "$ipt_n -A PSW2 $(comment "$remarks") -p icmp ${_ipt_source}" "$(REDIRECT)"
						$ipt_n -A PSW2 $(comment "$remarks") -p icmp ${_ipt_source} $(REDIRECT)
					}
					
					[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
						$ip6t_n -A PSW2 $(comment "$remarks") -p ipv6-icmp ${_ipt_source} -d $FAKE_IP_6 $(REDIRECT) 2>/dev/null
						add_shunt_t_rule "${shunt_list6}" "$ip6t_n -A PSW2 $(comment "$remarks") -p ipv6-icmp ${_ipt_source}" "$(REDIRECT)" 2>/dev/null
						$ip6t_n -A PSW2 $(comment "$remarks") -p ipv6-icmp ${_ipt_source} $(REDIRECT) 2>/dev/null
					}

					$ipt_tmp -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} -d $FAKE_IP ${ipt_j}
					add_shunt_t_rule "${shunt_list4}" "$ipt_tmp -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source}" "${ipt_j}" $tcp_redir_ports
					add_port_rules "$ipt_tmp -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_redir_ports "${ipt_j}"
					[ -n "${is_tproxy}" ] && $ipt_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} $(REDIRECT $redir_port TPROXY)

					[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
						$ip6t_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} -d $FAKE_IP_6 -j PSW2_RULE 2>/dev/null
						add_shunt_t_rule "${shunt_list6}" "$ip6t_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source}" "${ipt_j}" $tcp_redir_ports 2>/dev/null
						add_port_rules "$ip6t_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_redir_ports "-j PSW2_RULE" 2>/dev/null
						$ip6t_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} $(REDIRECT $redir_port TPROXY) 2>/dev/null
					}
					log 2 "${msg2}"
				}
				$ipt_tmp -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp -j RETURN
				[ "$_ipv4" != "1" ] && $ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp -j RETURN 2>/dev/null

				[ -z "$no_udp_proxy" ] && [ -n "$redir_port" ] && {
					msg2="${msg}$(i18n "Use the %s node [%s]" "UDP" "${node_remarks}")(TPROXY:${redir_port})"

					$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} -d $FAKE_IP -j PSW2_RULE
					add_shunt_t_rule "${shunt_list4}" "$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source}" "-j PSW2_RULE" $udp_redir_ports
					add_port_rules "$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source}" $udp_redir_ports "-j PSW2_RULE"
					$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} $(REDIRECT $redir_port TPROXY)

					[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
						$ip6t_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} -d $FAKE_IP_6 -j PSW2_RULE 2>/dev/null
						add_shunt_t_rule "${shunt_list6}" "$ip6t_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source}" "-j PSW2_RULE" $udp_redir_ports 2>/dev/null
						add_port_rules "$ip6t_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source}" $udp_redir_ports "-j PSW2_RULE" 2>/dev/null
						$ip6t_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} $(REDIRECT $redir_port TPROXY) 2>/dev/null
					}
					log 2 "${msg2}"
				}
				$ipt_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp -j RETURN
				[ "$_ipv4" != "1" ] && $ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp -j RETURN 2>/dev/null
				unset ipt_j _ipt_source msg msg2 _ipv4 no_tcp_proxy no_udp_proxy
			done
			unset msg1
		}
		unset dns_redirect_port ipt_tmp
		unset $(cat "${TMP_ACL_PATH}/${sid}/var" | awk -F '=' '{print $1}' | tr "\n" " ")
	done
}

filter_haproxy() {
	[ "$(config_n_get @global_haproxy[0] balancing_enable 0)" != "1" ] && return
	for item in $(uci show $CONFIG | grep ".lbss=" | cut -d "'" -f 2); do
		local ip=$(get_host_ip ipv4 $(echo $item | awk -F ":" '{print $1}') 1)
		[ -n "$ip" ] && ipset -q add $IPSET_VPS $ip
	done
	log_i18n 1 "Add node to the load balancer is directly connected to %s[%s]." "ipset" "${IPSET_VPS}"
}

filter_vpsip() {
	local ipv4_addrs=$(uci show $CONFIG | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2 | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | grep -v "^127\.0\.0\.1$")
	[ -n "$ipv4_addrs" ] && {
		echo "$ipv4_addrs" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_VPS &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
		log 1 "$(i18n "Add all %s nodes to %s[%s] direct connection complete." "IPv4" "ipset" "${IPSET_VPS}")"
	}
	local ipv6_addrs=$(uci show $CONFIG | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
	[ -n "$ipv6_addrs" ] && {
		echo "$ipv6_addrs" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_VPS6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
		log 1 "$(i18n "Add all %s nodes to %s[%s] direct connection complete." "IPv6" "ipset" "${IPSET_VPS6}")"
	}
}

filter_server_port() {
	local address=${1}
	local port=${2}
	local stream=${3}
	stream=$(echo ${3} | tr 'A-Z' 'a-z')
	local _is_tproxy ipt_tmp
	ipt_tmp=$ipt_n
	_is_tproxy=${is_tproxy}
	[ "$stream" == "udp" ] && _is_tproxy="TPROXY"
	[ -n "${_is_tproxy}" ] && ipt_tmp=$ipt_m

	for _ipt in 4 6; do
		[ "$_ipt" == "4" ] && _ipt=$ipt_tmp
		[ "$_ipt" == "6" ] && _ipt=$ip6t_m
		$_ipt -n -L PSW2_OUTPUT | grep -q "${address}:${port}"
		if [ $? -ne 0 ]; then
			$_ipt -I PSW2_OUTPUT $(comment "${address}:${port}") -p $stream -d $address --dport $port -j RETURN 2>/dev/null
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

# 直连集合的内容：direct_ip（含 geoip 代码）、LAN 网段与 ISP DNS。参数为目标集合（热刷新时是临时集合）。
fill_direct_sets() {
	local set4=${1}
	local set6=${2}
	for ip in $(cat /usr/share/passwall2/direct_ip | tr -s "\r\n" "\n" | grep -v "^#" | sed -e "/^$/d"); do
		if [[ "$ip" == *::* ]]; then
			ipset -! add $set6 $ip
		elif [[ "$ip" == "geoip:"* ]]; then
			local _geoip_code=$(echo $ip | awk -F ':' '{print $2}')
			get_geoip $_geoip_code ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $set4 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
			get_geoip $_geoip_code ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $set6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
		else
			ipset -! add $set4 $ip
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

		[ -n "$lan_ip" ] && ipset -! -R <<-EOF
			$(echo $lan_ip | sed -e "s/ /\n/g" | sed -e "s/^/add $set4 /")
		EOF

		[ -n "$lan_ip6" ] && ipset -! -R <<-EOF
			$(echo $lan_ip6 | sed -e "s/ /\n/g" | sed -e "s/^/add $set6 /")
		EOF
	}

	[ -n "$ISP_DNS" ] && {
		for ispip in $ISP_DNS; do
			ipset -! add $set4 $ispip
			[ -z "${IPSET_REFRESH}" ] && log_i18n 1 "$(i18n "Add ISP %s DNS to the whitelist: %s" "IPv4" "${ispip}")"
		done
	}

	[ -n "$ISP_DNS6" ] && {
		for ispip6 in $ISP_DNS6; do
			ipset -! add $set6 $ispip6
			[ -z "${IPSET_REFRESH}" ] && log_i18n 1 "$(i18n "Add ISP %s DNS to the whitelist: %s" "IPv6" "${ispip6}")"
		done
	}
	return 0
}

filter_vps_addr() {
	local server_host ip
	for server_host in "$@"; do
		ip=$(get_host_ip "ipv4" ${server_host})
		[ -n "$ip" ] && ipset -q add $IPSET_VPS $ip
		ip=$(get_host_ip "ipv6" ${server_host})
		[ -n "$ip" ] && ipset -q add $IPSET_VPS6 $ip
	done
}

update_wan_sets() {
	[ -z "$(command -v get_wan_ips)" ] && . "$UTILS_PATH"

	(
		flock -x 9 || exit 1

		local WAN_IP=$(get_wan_ips ip4)
		[ -n "$WAN_IP" ] && {
			# ipset -F "$IPSET_WAN"
			for wan_ip in $WAN_IP; do
				ipset -! add "$IPSET_WAN" "$wan_ip"
			done
		}

		local WAN6_IP=$(get_wan_ips ip6)
		[ -n "$WAN6_IP" ] && {
			# ipset -F "$IPSET_WAN6"
			for wan6_ip in $WAN6_IP; do
				ipset -! add "$IPSET_WAN6" "$wan6_ip"
			done
		}
	) 9>"${LOCK_PATH}/${CONFIG}_update_wan_sets.lock"
}

add_firewall_rule() {
	log_i18n 0 "Starting to load %s firewall rules..." "iptables"
	
	ipset -! create $IPSET_LOCAL nethash maxelem 1048576
	ipset -! create $IPSET_DIRECT nethash maxelem 1048576
	ipset -! create $IPSET_VPS iphash maxelem 1048576
	ipset -! create $IPSET_WAN nethash maxelem 1048576
	
	ipset -! create $IPSET_LOCAL6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_DIRECT6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_VPS6 iphash family inet6 maxelem 1048576
	ipset -! create $IPSET_WAN6 nethash family inet6 maxelem 1048576

	get_local_ips ip4 | sed "s/^/add $IPSET_LOCAL /" | ipset -! -R
	get_local_ips ip6 | sed "s/^/add $IPSET_LOCAL6 /" | ipset -! -R

	fill_direct_sets $IPSET_DIRECT $IPSET_DIRECT6
	update_wan_sets

	# Filter all node IPs
	# psw2_vps 只增不减（前置 DNS 也会写入）：影子启动不生成，提交后在系统中照常补充。
	[ -z "${PW2_STAGE}" ] && {
		filter_vpsip > /dev/null 2>&1 &
		filter_haproxy > /dev/null 2>&1 &
	}

	accept_icmp=$(config_n_get @global_forwarding[0] accept_icmp 0)
	accept_icmpv6=$(config_n_get @global_forwarding[0] accept_icmpv6 0)

	if [ "${TCP_PROXY_WAY}" = "redirect" ]; then
		unset is_tproxy
	elif [ "${TCP_PROXY_WAY}" = "tproxy" ]; then
		is_tproxy="TPROXY"
	fi

	if [ -z "${is_tproxy}" ] || [ "$accept_icmp" = "1" ]; then
		IPT_N=1
	fi

	if [ -z "${is_tproxy}" ] || [ "$accept_icmpv6" = "1" ]; then
		IP6T_N=1
	fi

	$ipt_n -N PSW2
	$ipt_n -A PSW2 $(dst $IPSET_VPS) -j RETURN
	$ipt_n -A PSW2 $(comment "WAN_IP_RETURN") $(dst $IPSET_WAN) -j RETURN
	
	[ "$accept_icmp" = "1" ] && insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "$(dst $IPSET_DIRECT !) -p icmp -j PSW2"
	[ -z "${is_tproxy}" ] && insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "$(dst $IPSET_DIRECT !) -p tcp -j PSW2"

	$ipt_n -N PSW2_OUTPUT
	$ipt_n -A PSW2_OUTPUT $(dst $IPSET_VPS) -j RETURN
	$ipt_n -A PSW2_OUTPUT -m mark --mark 0xff/0xff -j RETURN

	$ipt_n -N PSW2_DNS
	if [ $(config_n_get @global[0] dns_redirect "1") = "0" ]; then
		#Only hijack when dest address is local IP
		$ipt_n -I PREROUTING -m set --match-set $IPSET_DIRECT src $(dst $IPSET_LOCAL) -j PSW2_DNS
	else
		$ipt_n -I PREROUTING -m set --match-set $IPSET_DIRECT src -j PSW2_DNS
	fi

	$ipt_m -N PSW2_RULE
	$ipt_m -A PSW2_RULE -j CONNMARK --restore-mark
	$ipt_m -A PSW2_RULE -m mark --mark ${FWMARK} -j RETURN
	$ipt_m -A PSW2_RULE -p tcp -m tcp --syn -j MARK --set-xmark ${FWMARK}
	$ipt_m -A PSW2_RULE -p udp -m conntrack --ctstate NEW,RELATED -j MARK --set-xmark ${FWMARK}
	$ipt_m -A PSW2_RULE -j CONNMARK --save-mark

	$ipt_m -N PSW2
	# Socket Only TCP, UDP Invalid.
	$ipt_m -A PSW2 -p tcp -m socket --transparent -j MARK --set-mark ${FWMARK}
	$ipt_m -A PSW2 -p tcp -m socket --transparent -j ACCEPT
	$ipt_m -A PSW2 $(dst $IPSET_VPS) -j RETURN
	$ipt_m -A PSW2 $(comment "WAN_IP_RETURN") $(dst $IPSET_WAN) -j RETURN
	$ipt_m -A PSW2 -m conntrack --ctdir REPLY -j RETURN

	insert_rule_before "$ipt_m" "PREROUTING" "mwan3" "$(dst $IPSET_DIRECT !) -j PSW2"

	$ipt_m -N PSW2_OUTPUT
	$ipt_m -A PSW2_OUTPUT $(dst $IPSET_VPS) -j RETURN
	$ipt_m -A PSW2_OUTPUT -m conntrack --ctdir REPLY -j RETURN
	$ipt_m -A PSW2_OUTPUT -m mark --mark 0xff/0xff -j RETURN

	[ -z "${PW2_STAGE}" ] && {
		ip rule add fwmark ${FWMARK} table 999 priority 999
		ip route add local 0.0.0.0/0 dev lo table 999
	}

	[ "$accept_icmpv6" = "1" ] && {
		$ip6t_n -N PSW2
		$ip6t_n -A PSW2 $(dst $IPSET_VPS6) -j RETURN
		$ip6t_n -A PREROUTING $(dst $IPSET_DIRECT6 !) -p ipv6-icmp -j PSW2

		$ip6t_n -N PSW2_OUTPUT
		$ip6t_n -A PSW2_OUTPUT $(dst $IPSET_VPS6) -j RETURN
		$ip6t_n -A PSW2_OUTPUT -m mark --mark 0xff/0xff -j RETURN
	}
	
	$ip6t_n -N PSW2_DNS
	if [ $(config_n_get @global[0] dns_redirect "1") = "0" ]; then
		#Only hijack when dest address is local IP
		$ip6t_n -I PREROUTING -m set --match-set $IPSET_DIRECT6 src $(dst $IPSET_LOCAL6) -j PSW2_DNS
	else
		$ip6t_n -I PREROUTING -m set --match-set $IPSET_DIRECT6 src -j PSW2_DNS
	fi

	$ip6t_m -N PSW2_RULE
	$ip6t_m -A PSW2_RULE -j CONNMARK --restore-mark
	$ip6t_m -A PSW2_RULE -m mark --mark ${FWMARK} -j RETURN
	$ip6t_m -A PSW2_RULE -p tcp -m tcp --syn -j MARK --set-xmark ${FWMARK}
	$ip6t_m -A PSW2_RULE -p udp -m conntrack --ctstate NEW,RELATED -j MARK --set-xmark ${FWMARK}
	$ip6t_m -A PSW2_RULE -j CONNMARK --save-mark

	$ip6t_m -N PSW2
	# Socket Only TCP, UDP Invalid.
	$ip6t_m -A PSW2 -p tcp -m socket --transparent -j MARK --set-mark ${FWMARK}
	$ip6t_m -A PSW2 -p tcp -m socket --transparent -j ACCEPT
	$ip6t_m -A PSW2 $(dst $IPSET_VPS6) -j RETURN
	$ip6t_m -A PSW2 $(comment "WAN6_IP_RETURN") $(dst $IPSET_WAN6) -j RETURN
	$ip6t_m -A PSW2 -m conntrack --ctdir REPLY -j RETURN

	insert_rule_before "$ip6t_m" "PREROUTING" "mwan3" "$(dst $IPSET_DIRECT6 !) -j PSW2"

	$ip6t_m -N PSW2_OUTPUT
	$ip6t_m -A PSW2_OUTPUT -m mark --mark 0xff/0xff -j RETURN
	$ip6t_m -A PSW2_OUTPUT $(dst $IPSET_VPS6) -j RETURN
	$ip6t_m -A PSW2_OUTPUT -m conntrack --ctdir REPLY -j RETURN

	[ -n "$RETURN_DNS" ] && {
		for _dns in $(echo $RETURN_DNS | tr ',' ' '); do
			local dns_address=$(echo $_dns | awk -F '#' '{print $1}')
			local dns_port=$(echo $_dns | awk -F '#' '{print $2}')
			local dns_proto=$(echo $_dns | awk -F '#' '{print $3}')
			dns_proto=${dns_proto:-udp}
			if [[ "$dns_address" == *::* ]]; then
				$ip6t_m -I PSW2_OUTPUT -p ${dns_proto} -d ${dns_address} --dport ${dns_port:-53} -j RETURN
				log_i18n 1 "$(i18n "Add direct DNS to %s: %s" "ip6tables" "[${dns_address}]:${dns_port:-53}")"
			else
				$ipt_m -I PSW2_OUTPUT -p ${dns_proto} -d ${dns_address} --dport ${dns_port:-53} -j RETURN
				log_i18n 1 "$(i18n "Add direct DNS to %s: %s" "iptables" "${dns_address}:${dns_port:-53}")"
			fi
		done
	}

	[ -z "${PW2_STAGE}" ] && {
		ip -6 rule add fwmark ${FWMARK} table 999 priority 999
		ip -6 route add local ::/0 dev lo table 999
	}

	# 先启动各实例（核心、前置 DNS、直连写集合 DNS）：默认实例的分流子链要包含启动时登记的直连写集合，
	# 且生成器在分流规则变化时清空集合的动作必须发生在集合填充之前。
	log_i18n 1 "Access Control:"
	acl_node
	ACL_NODE_DONE=1

	# 默认实例的分流子链按全局节点生成；访问控制条目在 load_acl 中跳转到它们。
	local default_redir_port=$(sed -n 's/^redir_port="\(.*\)"$/\1/p' ${TMP_ACL_PATH}/acl_default/var 2>/dev/null)
	unset SHUNT_LIST4 SHUNT_LIST6
	[ -n "${NODE}" ] && gen_shunt_list "${NODE}" SHUNT_LIST4 SHUNT_LIST6
	apply_shunt_chains "${default_redir_port}"

	load_acl

	# 影子启动同步生成直连节点的放行规则，使目标规则完整。
	if [ -n "${PW2_STAGE}" ]; then
		filter_direct_node_list > /dev/null 2>&1
	else
		filter_direct_node_list > /dev/null 2>&1 &
	fi

	[ -z "${IPT_N}" ] && {
		for chain in "PSW2" "PSW2_OUTPUT"; do
			$ipt_n -F $chain 2>/dev/null
			$ipt_n -X $chain 2>/dev/null
		done
	}
	[ -z "${IP6T_N}" ] && {
		for chain in "PSW2" "PSW2_OUTPUT"; do
			$ip6t_n -F $chain 2>/dev/null
			$ip6t_n -X $chain 2>/dev/null
		done
	}

	log_i18n 0 "%s firewall rules load complete!" "iptables"
}

del_firewall_rule() {
	# 循环变量不能叫 ipt：会覆盖 iptables 路径（gen_include 等仍要用）。
	local _ipt_cmd
	for _ipt_cmd in "$ipt_n" "$ipt_m" "$ip6t_n" "$ip6t_m"; do
		for chain in "PREROUTING" "OUTPUT"; do
			for i in $(seq 1 $($_ipt_cmd -nL $chain | grep -c PSW2)); do
				local index=$($_ipt_cmd --line-number -nL $chain | grep PSW2 | head -1 | awk '{print $1}')
				$_ipt_cmd -D $chain $index 2>/dev/null
			done
		done
		# 先删引用分流子链的主链，再删分流子链与辅助链，最后删被分流子链引用的 PSW2_RULE。
		for chain in "PSW2" "PSW2_OUTPUT" "PSW2_DNS" ${SHUNT_CHAINS} ${SHUNT_HELPER_CHAINS} "PSW2_RULE"; do
			$_ipt_cmd -F $chain 2>/dev/null
			$_ipt_cmd -X $chain 2>/dev/null
		done
	done

	ip rule del fwmark ${FWMARK} 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table 999 2>/dev/null

	ip -6 rule del fwmark ${FWMARK} 2>/dev/null
	ip -6 route del local ::/0 dev lo table 999 2>/dev/null

	log_i18n 0 "Delete %s rules is complete." "iptables"
}

flush_ipset() {
	log_i18n 0 "Clear %s." "IPSet"
	for _name in $(ipset list | grep "Name: " | grep "psw2_" | awk '{print $2}'); do
		destroy_ipset ${_name}
	done
}

flush_include() {
	echo '#!/bin/sh' >$FWI
}

gen_include() {
	# 独立调用（热切换全局节点、集合热刷新、差量热重载之后）时没有启动阶段的变量：按当前配置补齐，
	# 否则恢复脚本会按重定向模式恢复 TCP 跳转、漏掉 ICMP 跳转。
	[ -z "$(command -v config_n_get)" ] && . "$UTILS_PATH"
	[ -n "${TCP_PROXY_WAY}" ] || {
		TCP_PROXY_WAY=$(config_n_get @global_forwarding[0] tcp_proxy_way redirect)
		[ "${TCP_PROXY_WAY}" = "tproxy" ] && is_tproxy="TPROXY"
	}
	[ -n "${accept_icmp}" ] || accept_icmp=$(config_n_get @global_forwarding[0] accept_icmp 0)
	[ -n "${accept_icmpv6}" ] || accept_icmpv6=$(config_n_get @global_forwarding[0] accept_icmpv6 0)
	flush_include
	extract_rules() {
		local _ipt="${ipt}"
		[ "$1" == "6" ] && _ipt="${ip6t}"
		[ -z "${_ipt}" ] && return

		echo "*$2"
		${_ipt}-save -t $2 | grep "PSW2" | grep -v "\-j PSW2$" | sed -e "s/^-A \(OUTPUT\|PREROUTING\)/-I \1 1/"
		echo 'COMMIT'
	}
	local __ipt=""
	[ -n "${ipt}" ] && {
		__ipt=$(cat <<- EOF
			${MY_PATH} update_wan_sets
			$ipt-save -c | grep -v "PSW2" | $ipt-restore -c
			$ipt-restore -n <<-EOT
			$(extract_rules 4 nat)
			$(extract_rules 4 mangle)
			EOT

			[ "$accept_icmp" = "1" ] && \$(${MY_PATH} insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "$(dst $IPSET_DIRECT !) -p icmp -j PSW2")
			[ -z "${is_tproxy}" ] && \$(${MY_PATH} insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "$(dst $IPSET_DIRECT !) -p tcp -j PSW2")

			\$(${MY_PATH} insert_rule_before "$ipt_m" "PREROUTING" "mwan3" "$(dst $IPSET_DIRECT !) -j PSW2")
		EOF
		)
	}
	local __ip6t=""
	[ -n "${ip6t}" ] && {
		__ip6t=$(cat <<- EOF
			${MY_PATH} update_wan_sets
			$ip6t-save -c | grep -v "PSW2" | $ip6t-restore -c
			$ip6t-restore -n <<-EOT
			$(extract_rules 6 nat)
			$(extract_rules 6 mangle)
			EOT

			[ "$accept_icmpv6" = "1" ] && $ip6t -t nat -w -A PREROUTING $(dst $IPSET_DIRECT6 !) -p ipv6-icmp -j PSW2

			\$(${MY_PATH} insert_rule_before "$ip6t_m" "PREROUTING" "mwan3" "$(dst $IPSET_DIRECT6 !) -j PSW2")
		EOF
		)
	}
	cat <<-EOF >> $FWI
		${__ipt}

		${__ip6t}
		
		return 0
	EOF
	return 0
}

get_ipt_bin() {
	echo $ipt
}

get_ip6t_bin() {
	echo $ip6t
}

start() {
	[ "$ENABLED_DEFAULT_ACL" == 0 -a "$ENABLED_ACLS" == 0 ] && return
	[ -z "${PW2_STAGE}" ] && : > "${IPT_LOG}"
	add_firewall_rule
	[ -z "${PW2_STAGE}" ] && gen_include
}

stop() {
	[ -z "$(command -v log_i18n)" ] && . "$UTILS_PATH"
	del_firewall_rule
	[ $(config_n_get @global[0] flush_set "0") = "1" ] && {
		uci -q delete ${CONFIG}.@global[0].flush_set
		uci -q commit ${CONFIG}
		flush_ipset
		rm -rf $TMP_PATH2/singbox*
		rm -rf $TMP_PATH2/geo_output
	}
	flush_include
}

arg1=$1
shift
case $arg1 in
RULE_LAST_INDEX)
	RULE_LAST_INDEX "$@"
	;;
insert_rule_before)
	insert_rule_before "$@"
	;;
insert_rule_after)
	insert_rule_after "$@"
	;;
get_ipt_bin)
	get_ipt_bin
	;;
get_ip6t_bin)
	get_ip6t_bin
	;;
filter_direct_node_list)
	[ -z "$(command -v config_n_get)" ] && . "$UTILS_PATH"
	# 直接调用（热重载、Socks 节点切换）时没有启动阶段的变量：按当前 TCP 转发方式决定 TCP 规则所在的表。
	[ "$(config_n_get @global_forwarding[0] tcp_proxy_way redirect)" = "tproxy" ] && is_tproxy="TPROXY"
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
	# 差量热重载提交规则之后：重写防火墙重载时的恢复脚本。
	[ -z "$(command -v log_i18n)" ] && . "$UTILS_PATH"
	gen_include
	;;
clear)
	# 差量热重载的目标状态不再需要透明代理规则：只删除规则，不处理 flush_set。
	[ -z "$(command -v log_i18n)" ] && . "$UTILS_PATH"
	del_firewall_rule
	flush_include
	rm -f "${IPT_LOG}"
	;;
update_wan_sets)
	update_wan_sets "$@"
	;;
stop)
	stop
	;;
start)
	start
	;;
*) ;;
esac
