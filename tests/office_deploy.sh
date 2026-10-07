#!/bin/sh
# 办公室路由器（京东云 RE-CS-02，aarch64）：安装热重载分支的完整应用与 aarch64 核心。
# 操作者自己经这台路由器上网，安装期间会断网，所以整个过程在路由器上独立完成：
#   check    只检查（身份、安装包、语法、新核心能否运行、旧版本的连通性基线），不改动系统；
#   run      备份 → 启动看护进程 → 旧版本停止 → 安装 → 迁移旧版专有的直连 DNS 选项 → 新版本启动 → 健康检查；
#            失败立即回滚并确认旧版本恢复；
#   watch    独立看护（run 在停止旧版本之前启动）：安装进程意外结束或超时则回滚；成功后等待确认（touch commit），
#            超时未确认同样回滚，避免新版本让操作者无法回来却无人处理；
#   rollback 恢复旧文件与配置并启动旧版本（加锁，只执行一次）。
# 状态写在 state（checking/checked/installing/verifying/ok-unconfirmed/committed/rolling-back/rolled-back/failed），
# 过程写在 deploy.log。目录与命令行都不含“passwall2/”：两版 app.sh stop 都会结束命令行含它的进程；
# 等待只用 sleep 5（新版 stop 会结束 sleep 6s/9s/58s）。不用 set -u：半途中止比继续执行再由健康检查兜底更危险。
umask 077
DIR=$(cd "$(dirname "$0")" && pwd)
LOG=$DIR/deploy.log
STATE=$DIR/state
CONFIRM_MINUTES=${CONFIRM_MINUTES:-15}
PAYLOAD=$DIR/payload
BACKUP=$DIR/backup
CONFIGS="passwall2 passwall2_server dhcp firewall"

log() { echo "$(date '+%F %T') $*" >> "$LOG"; }
state() { echo "$1" > "$STATE.tmp" && mv -f "$STATE.tmp" "$STATE"; log "状态：$1"; }
die() { log "中止：$*"; state failed; exit 1; }

identity() {
	[ "$(ubus call system board | jsonfilter -e '@.board_name')" = "jdcloud,re-cs-02" ] || return 1
	[ "$(ubus call system board | jsonfilter -e '@.release.target')" = "qualcommax/ipq60xx" ] || return 1
	[ "$(uname -m)" = "aarch64" ]
}

code() {
	curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 4 --max-time 6 "$1" 2>/dev/null
}

# 连通性：经代理的 Google、直连的百度、操作者所用的 Anthropic API（任何 HTTP 状态码都说明可达），三者并行探测；
# 同时查主 dnsmasq 能否解析国内域名。结果放在全局变量里（不能在 $(...) 子 shell 中调用，否则带不回来）。
probe() {
	code https://www.google.com/generate_204 > "$DIR/probe.google" &
	code https://www.baidu.com/ > "$DIR/probe.baidu" &
	code https://api.anthropic.com/ > "$DIR/probe.anthropic" &
	nslookup www.baidu.com 127.0.0.1 >/dev/null 2>&1 && dns=ok || dns=fail
	wait
	google=$(cat "$DIR/probe.google" 2>/dev/null)
	baidu=$(cat "$DIR/probe.baidu" 2>/dev/null)
	anthropic=$(cat "$DIR/probe.anthropic" 2>/dev/null)
	result="dns=$dns google=$google baidu=$baidu anthropic=$anthropic"
}

reachable() {
	case "$1" in ""|000) return 1 ;; esac
	return 0
}

core_running() {
	for d in /proc/[0-9]*; do
		case "$(tr '\000' ' ' < "$d/cmdline" 2>/dev/null)" in *" run -c "*"$1"*) return 0 ;; esac
	done
	return 1
}

check_payload() {
	[ -s "$DIR/overlay.tar.gz" ] && [ -s "$DIR/overlay.manifest" ] && [ -s "$DIR/overlay.sha256" ] || return 1
	(cd "$DIR" && sha256sum -c overlay.sha256 >/dev/null) || return 1
	rm -rf "$PAYLOAD"
	mkdir -p "$PAYLOAD"
	tar -xzf "$DIR/overlay.tar.gz" -C "$PAYLOAD" || return 1
	while IFS= read -r file; do
		case "$file" in ''|/*|*..*) return 1 ;; esac
		case "$file" in usr/*|etc/init.d/*|etc/hotplug.d/*|www/*) ;; *) log "拒绝的路径：$file"; return 1 ;; esac
		[ -f "$PAYLOAD/$file" ] || return 1
	done < "$DIR/overlay.manifest"
	for file in $(find "$PAYLOAD/usr/lib/lua/luci" "$PAYLOAD/usr/share/passwall2" -type f -name '*.lua'); do
		PW2_FILE="$file" lua -e 'assert(loadfile(os.getenv("PW2_FILE")))' 2>>"$LOG" || { log "Lua 语法错误：$file"; return 1; }
	done
	for file in $(find "$PAYLOAD/usr/share/passwall2" -type f -name '*.sh') $(find "$PAYLOAD/etc" -type f); do
		/bin/sh -n "$file" 2>>"$LOG" || { log "shell 语法错误：$file"; return 1; }
	done
	"$PAYLOAD/usr/bin/sing-box" version >> "$LOG" 2>&1 || return 1
	"$PAYLOAD/usr/bin/sing-box" hot-reload-capabilities >> "$LOG" 2>&1 || return 1
	"$PAYLOAD/usr/bin/xray" version >> "$LOG" 2>&1 || return 1
	"$PAYLOAD/usr/bin/xray" api reloadconfig --local >> "$LOG" 2>&1 || return 1
	# 旧版本拥有、新版本不再提供的文件：安装后删除（先备份）。固件内置的包没有 opkg 文件清单，按 passwall2 自有目录扫描；
	# 新版节点编辑页会加载 client/type 目录下的全部文件，旧类型文件留着会让页面出错。其它插件与用户的 .bak 备份不动。
	{
		sed 's#^/##' /usr/lib/opkg/info/luci-app-passwall2.list 2>/dev/null
		for d in usr/share/passwall2 usr/lib/lua/luci/passwall2 usr/lib/lua/luci/model/cbi/passwall2 usr/lib/lua/luci/view/passwall2 www/luci-static/resources/view/passwall2; do
			[ -d "/$d" ] && find "/$d" -type f | sed 's#^/##'
		done
		[ -f /usr/lib/lua/luci/controller/passwall2.lua ] && echo usr/lib/lua/luci/controller/passwall2.lua
		find /etc/hotplug.d -type f -name '*passwall2*' 2>/dev/null | sed 's#^/##'
	} | grep -v '^etc/config/' | grep -v '^etc/uci-defaults/' | grep -v '\.bak$' | \
		grep -E '^(usr/|etc/init\.d/|etc/hotplug\.d/|www/)' | LC_ALL=C sort -u > "$DIR/old.list"
	LC_ALL=C sort -u "$DIR/overlay.manifest" > "$DIR/new.sorted"
	awk 'NR==FNR {keep[$0]=1; next} !($0 in keep)' "$DIR/new.sorted" "$DIR/old.list" > "$DIR/remove.list"
	return 0
}

# 旧版（LibWrt 改版 26.1.19）用 direct_dns_mode（auto/smartdns/custom）选直连 DNS；新版只认 direct_dns_protocol 与
# direct_dns（协议为 UDP/TCP 时用 direct_dns，否则自动取 dnsmasq 上游或运营商 DNS）。这台路由器的 dnsmasq 上游是旧版
# 固定的 DNS 端口 127.0.0.1#15353，新版不再监听，“自动”在这里不可用，必须按旧模式换算成显式地址。
# 输出“协议 地址”；旧模式本来就是自动获取时为空。
direct_dns_plan() {
	local dns proto
	case "$(uci -q get passwall2.@global[0].direct_dns_mode)" in
	smartdns)
		echo "udp 127.0.0.1:$(uci -q get smartdns.@smartdns[0].port || echo 7053)"
		;;
	custom)
		dns=$(uci -q get passwall2.@global[0].direct_dns | cut -d, -f1 | sed 's/#/:/')
		proto=$(uci -q get passwall2.@global[0].direct_dns_protocol)
		[ "$proto" = "tcp" ] || proto=udp
		[ -n "$dns" ] && echo "$proto $dns"
		;;
	esac
}

migrate_direct_dns() {
	local mode plan
	mode=$(uci -q get passwall2.@global[0].direct_dns_mode) || return 0
	plan=$(direct_dns_plan)
	if [ -n "$plan" ]; then
		uci set passwall2.@global[0].direct_dns_protocol="${plan%% *}"
		uci set passwall2.@global[0].direct_dns="${plan#* }"
	else
		uci -q delete passwall2.@global[0].direct_dns_protocol
	fi
	uci -q delete passwall2.@global[0].direct_dns_mode
	uci commit passwall2
	log "直连 DNS 选项迁移：direct_dns_mode=$mode → ${plan:-自动获取}"
}

rollback() {
	mkdir "$DIR/rollback.lock" 2>/dev/null || { log "回滚已在进行或已完成，跳过。"; return 0; }
	state rolling-back
	log "回滚：用新版本停止（清理新的防火墙与 DNS 结构），恢复旧文件与配置后启动旧版本。"
	/etc/init.d/passwall2 stop >> "$LOG" 2>&1
	/etc/init.d/passwall2_server stop >> "$LOG" 2>&1
	(cd / && tar -xzf "$BACKUP/files.tar.gz") 2>>"$LOG" || log "警告：旧文件解包有错误"
	while IFS= read -r file; do rm -f "/$file"; done < "$BACKUP/added.list"
	for name in $CONFIGS; do
		[ -f "$BACKUP/stopped/$name" ] && cp -p "$BACKUP/stopped/$name" "/etc/config/$name"
	done
	chmod 755 /etc/init.d/passwall2 /etc/init.d/passwall2_server /usr/share/passwall2/*.sh 2>/dev/null
	rm -f /tmp/luci-indexcache /tmp/luci-indexcache.* 2>/dev/null
	rm -rf /tmp/luci-modulecache/ 2>/dev/null
	killall -HUP rpcd 2>/dev/null
	/etc/init.d/passwall2 start >> "$LOG" 2>&1
	/etc/init.d/passwall2_server start >> "$LOG" 2>&1
	local i
	for i in $(seq 1 12); do
		probe
		core_running "/acl/default/global.json" && [ "$google" = "204" ] && break
		sleep 5
	done
	log "回滚后：旧核心$(core_running "/acl/default/global.json" && echo 运行 || echo 未运行)，$result"
	state rolled-back
}

# 每轮最长约 11 秒（并行探测 6 秒 + 等待 5 秒），12 轮约 2 分钟：正常时第一两轮即通过，失败时尽快回滚。
healthy() {
	local i ok core chain rule
	for i in $(seq 1 12); do
		# 看护进程已经开始回滚：不再检查，也不再宣布成功。
		[ -d "$DIR/rollback.lock" ] && return 1
		probe
		core=0 chain=0 rule=0
		core_running "/acl/acl_default.json" && core=1
		nft list chain inet passwall2 PSW2_SHUNT_MARK >/dev/null 2>&1 && chain=1
		ip rule | grep -q 'fwmark 0x50535732 lookup 999' && rule=1
		if [ "$core$chain$rule" = "111" ]; then
			ok=1
			[ "$base_dns" = "ok" ] && [ "$dns" != "ok" ] && ok=0
			reachable "$base_google" && [ "$google" != "204" ] && ok=0
			reachable "$base_baidu" && ! reachable "$baidu" && ok=0
			reachable "$base_anthropic" && ! reachable "$anthropic" && ok=0
			[ "$ok" = 1 ] && { log "健康检查通过（第 $i 次）：$result"; return 0; }
		fi
		sleep 5
	done
	log "健康检查失败：核心=$core 分流子链=$chain 策略路由=$rule $result"
	grep 'DNS' /tmp/log/passwall2.log 2>/dev/null | tail -n 4 | sed 's/^/  | /' >> "$LOG"
	return 1
}

case "${1:-}" in
check)
	: > "$LOG"
	state checking
	identity || die "设备身份不符（应为京东云 RE-CS-02 / qualcommax/ipq60xx / aarch64）"
	check_payload || die "安装包或新核心检查失败，详见日志"
	plan=$(direct_dns_plan)
	if [ -n "$plan" ]; then
		nslookup www.baidu.com "${plan#* }" >/dev/null 2>&1 || die "换算出的直连 DNS ${plan#* } 无法解析国内域名"
		log "直连 DNS 将迁移为：$plan（已验证能解析国内域名）"
	fi
	probe
	log "旧版本连通性基线：$result"
	log "将删除的旧包残留文件 $(wc -l < "$DIR/remove.list") 个：$(tr '\n' ' ' < "$DIR/remove.list")"
	log "检查通过，未改动系统。"
	state checked
	;;
run)
	[ "$(cat "$STATE" 2>/dev/null)" = "checked" ] || die "需要先执行 check"
	identity || die "设备身份不符"
	echo $$ > "$DIR/run.pid"
	state installing
	probe
	base_dns=$dns base_google=$google base_baidu=$baidu base_anthropic=$anthropic
	log "安装前连通性：$result"
	mkdir -p "$BACKUP/original" "$BACKUP/stopped"
	for name in $CONFIGS; do cp -p "/etc/config/$name" "$BACKUP/original/$name" 2>/dev/null; done
	: > "$BACKUP/existing.list"
	: > "$BACKUP/added.list"
	while IFS= read -r file; do
		if [ -e "/$file" ] || [ -L "/$file" ]; then echo "$file" >> "$BACKUP/existing.list"; else echo "$file" >> "$BACKUP/added.list"; fi
	done < "$DIR/overlay.manifest"
	while IFS= read -r file; do
		{ [ -e "/$file" ] || [ -L "/$file" ]; } && echo "$file" >> "$BACKUP/existing.list"
	done < "$DIR/remove.list"
	(cd / && tar -czf "$BACKUP/files.tar.gz" -T "$BACKUP/existing.list") 2>>"$LOG" || die "备份旧文件失败"
	log "已备份 $(wc -l < "$BACKUP/existing.list") 个旧文件，新增 $(wc -l < "$BACKUP/added.list") 个。"
	# 看护进程不继承任何锁，从本目录以相对路径启动（命令行不含 passwall2/）。
	(cd "$DIR" && nohup /bin/sh ./deploy.sh watch </dev/null >/dev/null 2>&1 &)
	sleep 1

	log "旧版本停止（断网开始）。"
	/etc/init.d/passwall2 stop >> "$LOG" 2>&1
	/etc/init.d/passwall2_server stop >> "$LOG" 2>&1
	# 旧版本停止后的配置是用户配置的规范状态（运行时改动已撤销），回滚时恢复到这里。
	for name in $CONFIGS; do cp -p "/etc/config/$name" "$BACKUP/stopped/$name" 2>/dev/null; done
	while IFS= read -r file; do
		mkdir -p "/${file%/*}"
		cp -p "$PAYLOAD/$file" "/$file.pw2-new" && chown root:root "/$file.pw2-new" && mv -f "/$file.pw2-new" "/$file" || log "警告：安装失败 $file"
	done < "$DIR/overlay.manifest"
	while IFS= read -r file; do rm -f "/$file"; done < "$DIR/remove.list"
	chmod 755 /etc/init.d/passwall2 /etc/init.d/passwall2_server /usr/share/passwall2/*.sh /usr/bin/sing-box /usr/bin/xray 2>/dev/null
	# 与安装软件包时的首次运行脚本一致：防火墙 include（fw4 不需要 reload 选项）、服务端配置迁移、清理 LuCI 缓存。
	uci -q batch <<-EOF
		delete firewall.passwall2
		set firewall.passwall2=include
		set firewall.passwall2.type='script'
		set firewall.passwall2.path='/var/etc/passwall2.include'
		commit firewall
	EOF
	lua /usr/lib/lua/luci/passwall2/server_app.lua migrate >> "$LOG" 2>&1
	migrate_direct_dns
	rm -f /tmp/luci-indexcache /tmp/luci-indexcache.* 2>/dev/null
	rm -rf /tmp/luci-modulecache/ 2>/dev/null
	killall -HUP rpcd 2>/dev/null
	log "新版本文件已安装，启动新版本。"
	state verifying
	/etc/init.d/passwall2 start >> "$LOG" 2>&1
	/etc/init.d/passwall2_server start >> "$LOG" 2>&1
	if ! healthy; then
		rollback
		exit 1
	fi
	[ -d "$DIR/rollback.lock" ] && exit 1
	tail -n 40 /tmp/log/passwall2.log 2>/dev/null | sed 's/^/  | /' >> "$LOG"
	state ok-unconfirmed
	log "新版本运行正常；${CONFIRM_MINUTES} 分钟内未执行 touch $DIR/commit 将由看护进程自动回滚。"
	;;
watch)
	log "看护进程启动（PID $$）。"
	i=0
	while [ "$i" -lt 96 ]; do
		s=$(cat "$STATE" 2>/dev/null)
		case "$s" in ok-unconfirmed|committed|rolling-back|rolled-back|failed) break ;; esac
		if ! kill -0 "$(cat "$DIR/run.pid" 2>/dev/null)" 2>/dev/null; then
			log "安装进程意外结束（状态 $s），回滚。"
			rollback
			exit 1
		fi
		sleep 5
		i=$((i + 1))
	done
	s=$(cat "$STATE" 2>/dev/null)
	case "$s" in
		installing|verifying) log "安装超过 8 分钟仍未完成（状态 $s），回滚。"; rollback; exit 1 ;;
		ok-unconfirmed) ;;
		*) exit 0 ;;
	esac
	i=0
	while [ "$i" -lt $((CONFIRM_MINUTES * 12)) ]; do
		[ -f "$DIR/commit" ] && { state committed; log "已确认保留新版本，看护进程退出。"; exit 0; }
		[ "$(cat "$STATE" 2>/dev/null)" = "ok-unconfirmed" ] || exit 0
		sleep 5
		i=$((i + 1))
	done
	log "超时未确认，回滚。"
	rollback
	;;
rollback)
	rollback
	;;
*)
	echo "用法：$0 check|run|watch|rollback" >&2
	exit 2
	;;
esac
