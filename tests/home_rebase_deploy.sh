#!/bin/sh
# 家里路由器：部署变基到上游最新版本后的完整应用与热重载功能。不连接也不修改办公室路由器。
# 覆盖应用文件；删除上游已删除或改名、但仍残留在路由器上的旧版本文件（来自原装包与首轮覆盖）；
# 全部改动先备份，120 分钟内未确认则自动回滚。保留 /etc/config 下的用户配置。
set -eu
umask 077
ROOT=/root/passwall2-hot-reload-test-20261003
STAGE=$ROOT/${1:-rebase-20261004}

[ "$(ubus call system board | jsonfilter -e '@.release.target')" = "x86/64" ] || exit 1
[ "$(ubus call system board | jsonfilter -e '@.model')" = "Microsoft Corporation Virtual Machine" ] || exit 1
[ -f "$ROOT/commit" ] || { echo "首轮部署尚未确认，拒绝继续"; exit 1; }
[ -s "$STAGE/overlay.tar.gz" ] && [ -s "$STAGE/overlay.manifest" ] || exit 1
[ ! -f "$STAGE/installed" ] || { echo "本次部署已安装，拒绝覆盖其备份"; exit 1; }

mkdir -p "$STAGE/payload" "$STAGE/backup"
tar -xzf "$STAGE/overlay.tar.gz" -C "$STAGE/payload"
while IFS= read -r file; do
	case "$file" in ''|/*|*..*) exit 1;; esac
	case "$file" in usr/*|etc/init.d/*|etc/hotplug.d/*|www/*) ;; *) echo "拒绝的路径：$file"; exit 1;; esac
	[ -f "$STAGE/payload/$file" ] || exit 1
done < "$STAGE/overlay.manifest"
for file in $(find "$STAGE/payload/usr/lib/lua/luci" "$STAGE/payload/usr/share/passwall2" -type f -name '*.lua'); do
	PW2_FILE="$file" lua -e 'assert(loadfile(os.getenv("PW2_FILE")))'
done
for file in $(find "$STAGE/payload/usr/share/passwall2" "$STAGE/payload/etc/init.d" -type f -name '*.sh' -o -type f -path '*/init.d/*'); do
	/bin/sh -n "$file"
done

# 旧版本拥有的文件：原装包清单（不含配置）加首轮覆盖新增的文件；不在新清单中的即为残留。
{
	apk info -L luci-app-passwall2 2>/dev/null | grep -v ' contains:$' | grep -v '^$' || true
	cat "$ROOT/backup/new.list" 2>/dev/null || true
} | grep -v '^etc/config/' | grep -E '^(usr/|etc/init\.d/|etc/hotplug\.d/|www/)' | sort -u > "$STAGE/old.list"
sort -u "$STAGE/overlay.manifest" > "$STAGE/new.sorted"
comm -23 "$STAGE/old.list" "$STAGE/new.sorted" 2>/dev/null > "$STAGE/remove.list" || \
	awk 'NR==FNR {keep[$0]=1; next} !($0 in keep)' "$STAGE/new.sorted" "$STAGE/old.list" > "$STAGE/remove.list"
: > "$STAGE/backup/existing.list"
: > "$STAGE/backup/added.list"
while IFS= read -r file; do
	if [ -e "/$file" ] || [ -L "/$file" ]; then echo "$file" >> "$STAGE/backup/existing.list"; else echo "$file" >> "$STAGE/backup/added.list"; fi
done < "$STAGE/overlay.manifest"
while IFS= read -r file; do
	[ -e "/$file" ] || [ -L "/$file" ] && echo "$file" >> "$STAGE/backup/existing.list"
done < "$STAGE/remove.list"
(cd / && tar -czf "$STAGE/backup/files.tar.gz" -T "$STAGE/backup/existing.list")
sha256sum /etc/config/passwall2 > "$STAGE/backup/config.sha256"
# 新版服务端启动时会把旧格式 passwall2_server 配置迁移为 server/user 结构并删除旧防火墙包含，回滚时需要恢复。
cp -p /etc/config/passwall2_server "$STAGE/backup/passwall2_server.config"
uci -q get firewall.passwall2_server >/dev/null && touch "$STAGE/backup/firewall_include" || true
enabled_servers=0
[ "$(uci -q get passwall2_server.@global[0].enable)" = 1 ] && \
	enabled_servers=$(uci -q show passwall2_server | grep -v '^passwall2_server\.global\.' | grep -c "\.enable='1'$" || true)
touch "$STAGE/installed"

cat > "$STAGE/rollback.sh" <<'ROLLBACK'
#!/bin/sh
# 先用新脚本停止（能清理新的防火墙结构），再恢复旧文件、删除新增文件并启动。
set -eu
STAGE=$(cd "$(dirname "$0")" && pwd)
/etc/init.d/passwall2 stop || true
/etc/init.d/passwall2_server stop || true
(cd / && tar -xzf "$STAGE/backup/files.tar.gz")
while IFS= read -r file; do rm -f "/$file"; done < "$STAGE/backup/added.list"
cp -p "$STAGE/backup/passwall2_server.config" /etc/config/passwall2_server
for r in $(uci -q show firewall | sed -n "s/^firewall\.\(passwall2_server_[^.=]*\)=rule$/\1/p"); do uci -q delete "firewall.$r"; done
if [ -f "$STAGE/backup/firewall_include" ]; then
	uci -q set firewall.passwall2_server=include
	uci -q set firewall.passwall2_server.type='script'
	uci -q set firewall.passwall2_server.path='/var/etc/passwall2_server.include'
	uci -q set firewall.passwall2_server.reload='1'
fi
uci -q commit firewall
/etc/init.d/firewall reload || true
rm -f /tmp/luci-indexcache /tmp/luci-indexcache.* 2>/dev/null || true
rm -rf /tmp/luci-modulecache/ 2>/dev/null || true
/etc/init.d/passwall2 start
/etc/init.d/passwall2_server restart || true
touch "$STAGE/rolled-back"
echo "已恢复变基部署之前的应用文件并重新启动。"
ROLLBACK
chmod 700 "$STAGE/rollback.sh"
cat > "$STAGE/watch.sh" <<'WATCH'
#!/bin/sh
STAGE=$(cd "$(dirname "$0")" && pwd)
for i in $(seq 1 720); do
	[ -f "$STAGE/commit" ] || [ -f "$STAGE/rolled-back" ] && exit 0
	sleep 10
done
[ -f "$STAGE/commit" ] || [ -f "$STAGE/rolled-back" ] || "$STAGE/rollback.sh" > "$STAGE/rollback.log" 2>&1
WATCH
chmod 700 "$STAGE/watch.sh"
# 自动回滚守护不能继承服务锁，也不能被 app.sh stop 按 "passwall2/" 匹配结束：从暂存目录以相对路径启动。
(cd "$STAGE" && nohup /bin/sh ./watch.sh </dev/null >/dev/null 2>&1 &)

/etc/init.d/passwall2 stop
while IFS= read -r file; do
	mkdir -p "/${file%/*}"
	cp -p "$STAGE/payload/$file" "/$file.pw2-new"
	chown root:root "/$file.pw2-new"
	mv -f "/$file.pw2-new" "/$file"
done < "$STAGE/overlay.manifest"
while IFS= read -r file; do rm -f "/$file"; done < "$STAGE/remove.list"
chmod 755 /etc/init.d/passwall2 /etc/init.d/passwall2_server /usr/share/passwall2/*.sh 2>/dev/null || true
rm -f /tmp/luci-indexcache /tmp/luci-indexcache.* 2>/dev/null || true
rm -rf /tmp/luci-modulecache/ 2>/dev/null || true
killall -HUP rpcd 2>/dev/null || true
# 启动脚本返回成功不代表透明代理已建立（上次 app_acl.lua 出错时仍以非代理模式“运行完成”）：
# 核对默认实例核心、防火墙链与透明 HTTPS，任一失败立即回滚。
healthy() {
	local i core
	for i in $(seq 1 20); do
		core=""
		for d in /proc/[0-9]*; do
			case "$(tr '\000' ' ' < "$d/cmdline" 2>/dev/null)" in
				*" run -c "*/acl/acl_default.json*) core=1 ;;
			esac
		done
		if [ -n "$core" ] && nft list chain inet passwall2 PSW2_SHUNT_MARK >/dev/null 2>&1 && \
			[ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 https://www.google.com/generate_204 2>/dev/null)" = "204" ]; then
			return 0
		fi
		sleep 2
	done
	return 1
}
if ! /etc/init.d/passwall2 start || ! healthy; then
	echo "新版本启动后健康检查失败，立即回滚。"
	"$STAGE/rollback.sh"
	exit 1
fi
/etc/init.d/passwall2_server restart || true
sleep 3
running_servers=0
for d in /proc/[0-9]*; do
	case "$(tr '\000' ' ' < "$d/cmdline" 2>/dev/null)" in /tmp/etc/passwall2_server/bin/*) running_servers=$((running_servers + 1)) ;; esac
done
[ "$running_servers" -ge "$enabled_servers" ] || echo "警告：服务端只运行了 $running_servers 个进程（迁移前启用 $enabled_servers 个），请检查 /tmp/log/passwall2_server.log"
echo "变基版本已安装并启动；120 分钟内未写入 $STAGE/commit 将自动回滚。删除的残留文件：$(wc -l < "$STAGE/remove.list") 个。"
