#!/bin/sh
# 家里路由器增量更新：持服务锁替换暂存目录中的文件，全部改动先备份并生成回滚脚本；不重启服务。
# 用法：home_increment_deploy.sh <暂存名>。暂存目录含 payload/ 与 payload.sha256（清单即待替换文件）。
# 不连接也不修改办公室路由器。
set -eu
umask 077
ROOT=/root/passwall2-hot-reload-test-20261003
STAGE=$ROOT/${1:?暂存名}

[ "$(ubus call system board | jsonfilter -e '@.release.target')" = "x86/64" ] || exit 1
[ "$(ubus call system board | jsonfilter -e '@.model')" = "Microsoft Corporation Virtual Machine" ] || exit 1
[ -f "$ROOT/rebase-20261004b/commit" ] || { echo "变基部署尚未确认，拒绝增量更新"; exit 1; }
[ ! -f "$STAGE/installed" ] || { echo "本增量已安装，拒绝覆盖其备份"; exit 1; }

cd "$STAGE/payload"
sha256sum -c ../payload.sha256 >/dev/null
FILES=$(awk '{print $2}' ../payload.sha256)
for file in $FILES; do
	case "$file" in ''|/*|*..*) exit 1 ;; usr/*|etc/init.d/*) ;; *) echo "拒绝的路径：$file"; exit 1 ;; esac
	case "$file" in
		*.lua) PW2_FILE="$file" lua -e 'assert(loadfile(os.getenv("PW2_FILE")))' ;;
		*.sh|etc/init.d/*) /bin/sh -n "$file" ;;
		usr/bin/xray) ./usr/bin/xray api reloadconfig --local >/dev/null ;;
	esac
done

# busybox flock 没有超时参数，用非阻塞重试限定等待时间；持服务锁期间替换，避免与 reload/看门狗交错。
exec 6>/var/lock/passwall2.flock
i=0
while ! flock -xn 6; do
	i=$((i + 1))
	[ "$i" -le 60 ] || { echo "等待服务锁超时"; exit 1; }
	sleep 1
done

mkdir -p "$STAGE/backup"
: > "$STAGE/backup/added.list"
existing=""
for file in $FILES; do
	if [ -e "/$file" ]; then existing="$existing $file"; else echo "$file" >> "$STAGE/backup/added.list"; fi
done
(cd / && tar -czf "$STAGE/backup/files.tar.gz" $existing)
for file in $FILES; do
	mkdir -p "/${file%/*}"
	cp -p "$file" "/$file.pw2-new"
	chown root:root "/$file.pw2-new"
	mv -f "/$file.pw2-new" "/$file"
done
chmod 755 /usr/share/passwall2/*.sh /etc/init.d/passwall2 2>/dev/null || true
[ -f /usr/bin/xray ] && chmod 755 /usr/bin/xray
touch "$STAGE/installed"
flock -u 6

cat > "$STAGE/rollback.sh" <<'ROLLBACK'
#!/bin/sh
# 先用新脚本停止（能清理新的防火墙结构），再恢复本增量之前的文件并启动。
set -eu
STAGE=$(cd "$(dirname "$0")" && pwd)
/etc/init.d/passwall2 stop || true
(cd / && tar -xzf "$STAGE/backup/files.tar.gz")
while IFS= read -r file; do rm -f "/$file"; done < "$STAGE/backup/added.list"
/etc/init.d/passwall2 start
touch "$STAGE/rolled-back"
echo "已恢复本增量之前的文件并重新启动 passwall2。"
ROLLBACK
chmod 700 "$STAGE/rollback.sh"
echo "增量文件已安装（未重启）：$(echo $FILES | wc -w) 个。回滚：$STAGE/rollback.sh"
