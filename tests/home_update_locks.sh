#!/bin/sh
# 家里路由器增量更新：锁机制、配置快照范围、撤回重复 reload；不重启代理核心。
set -eu
umask 077
ROOT=/root/passwall2-hot-reload-test-20261003
STAGE=$ROOT/update-locks-20261004
FILES="etc/init.d/passwall2 usr/share/passwall2/monitor.sh usr/share/passwall2/reload.lua usr/lib/lua/luci/passwall2/api.lua usr/lib/lua/luci/passwall2/reload.lua"

[ "$(ubus call system board | jsonfilter -e '@.release.target')" = "x86/64" ] || exit 1
[ "$(ubus call system board | jsonfilter -e '@.model')" = "Microsoft Corporation Virtual Machine" ] || exit 1
[ -f "$ROOT/commit" ] || { echo "首轮部署尚未确认，拒绝增量更新"; exit 1; }
[ ! -f "$STAGE/installed" ] || { echo "本增量已安装，拒绝覆盖其备份"; exit 1; }

for file in $FILES; do
	[ -s "$STAGE/payload/$file" ] || exit 1
	case "$file" in
		*.lua) PW2_FILE="$STAGE/payload/$file" lua -e 'assert(loadfile(os.getenv("PW2_FILE")))' ;;
		*) /bin/sh -n "$STAGE/payload/$file" ;;
	esac
done

# busybox flock 没有超时参数，用非阻塞重试限定等待时间。
lock_fd() {
	i=0
	while ! flock -xn "$1"; do
		i=$((i + 1))
		[ "$i" -le 60 ] || { echo "等待服务锁超时"; exit 1; }
		sleep 1
	done
}
# 先等旧方案下进行中的服务操作结束，再持新互斥锁完成切换。
exec 7>/var/lock/passwall2.lock
lock_fd 7
exec 6>/var/lock/passwall2.flock
lock_fd 6

mkdir -p "$STAGE/backup"
(cd / && tar -czf "$STAGE/backup/files.tar.gz" $FILES)
for file in $FILES; do
	cp -p "$STAGE/payload/$file" "/$file.pw2-new"
	chown root:root "/$file.pw2-new"
	mv -f "/$file.pw2-new" "/$file"
done
chmod 755 /etc/init.d/passwall2 /usr/share/passwall2/monitor.sh
touch "$STAGE/installed"

# 替换看门狗：结束旧进程及其 sleep 子进程，以新脚本重新启动且不继承任何锁描述符。
for dir in /proc/[0-9]*; do
	case "$(tr '\000' ' ' < "$dir/cmdline" 2>/dev/null)" in
		"/bin/sh /usr/share/passwall2/monitor.sh "*)
			pid=${dir#/proc/}
			for child in /proc/[0-9]*; do
				[ "$(awk '/^PPid:/ {print $2}' "$child/status" 2>/dev/null)" = "$pid" ] && kill "${child#/proc/}" 2>/dev/null || true
			done
			kill "$pid" 2>/dev/null || true
			;;
	esac
done
sleep 1
nohup /usr/share/passwall2/monitor.sh </dev/null >/dev/null 2>&1 6>&- 7>&- &

# 旧方案的常驻锁文件就是新方案的忙碌标记，空闲时移除以恢复订阅与规则更新的判断。
rm -f /var/lock/passwall2.lock
# 当前运行状态与配置一致，用新格式刷新快照，避免首次应用因格式变化完整重启。
lua /usr/share/passwall2/reload.lua snapshot 6>&- 7>&-

flock -u 6
flock -u 7
cat > "$STAGE/rollback.sh" <<'ROLLBACK'
#!/bin/sh
set -eu
STAGE=/root/passwall2-hot-reload-test-20261003/update-locks-20261004
(cd / && tar -xzf "$STAGE/backup/files.tar.gz")
echo "已恢复增量更新前的锁与快照文件；如需让看门狗使用旧脚本，执行 /etc/init.d/passwall2 restart。"
ROLLBACK
chmod 700 "$STAGE/rollback.sh"
echo "增量更新完成；核心未重启，看门狗已替换。回滚：$STAGE/rollback.sh"
