#!/bin/sh
# 家里路由器增量更新：全局节点无损热切换（nft 分流子链、直连写集合 DNS、FakeIP 保留）与 Xray FakeDNS 共享。
# 只安装文件并备份；随后由测试端执行一次受控重启以建立分流子链。不连接也不修改办公室路由器。
set -eu
umask 077
ROOT=/root/passwall2-hot-reload-test-20261003
STAGE=$ROOT/global-switch-20261004
FILES="usr/share/passwall2/nftables.sh usr/share/passwall2/app.sh usr/share/passwall2/reload.lua usr/lib/lua/luci/passwall2/reload.lua usr/lib/lua/luci/passwall2/util_sing-box.lua usr/bin/xray"

[ "$(ubus call system board | jsonfilter -e '@.release.target')" = "x86/64" ] || exit 1
[ "$(ubus call system board | jsonfilter -e '@.model')" = "Microsoft Corporation Virtual Machine" ] || exit 1
[ -f "$ROOT/commit" ] || { echo "首轮部署尚未确认，拒绝增量更新"; exit 1; }
[ -f "$ROOT/update-locks-20261004/installed" ] || { echo "锁机制增量未安装，拒绝继续"; exit 1; }
[ ! -f "$STAGE/installed" ] || { echo "本增量已安装，拒绝覆盖其备份"; exit 1; }

for file in $FILES; do
	[ -s "$STAGE/payload/$file" ] || exit 1
	case "$file" in
		*.lua) PW2_FILE="$STAGE/payload/$file" lua -e 'assert(loadfile(os.getenv("PW2_FILE")))' ;;
		*.sh) /bin/sh -n "$STAGE/payload/$file" ;;
		usr/bin/xray) "$STAGE/payload/$file" api reloadconfig --local >/dev/null ;;
	esac
done
(cd "$STAGE/payload" && sha256sum -c ../payload.sha256 >/dev/null)

# busybox flock 没有超时参数，用非阻塞重试限定等待时间；持服务锁期间替换，避免与 reload/看门狗交错。
exec 6>/var/lock/passwall2.flock
i=0
while ! flock -xn 6; do
	i=$((i + 1))
	[ "$i" -le 60 ] || { echo "等待服务锁超时"; exit 1; }
	sleep 1
done

mkdir -p "$STAGE/backup"
(cd / && tar -czf "$STAGE/backup/files.tar.gz" $FILES)
for file in $FILES; do
	cp -p "$STAGE/payload/$file" "/$file.pw2-new"
	chown root:root "/$file.pw2-new"
	mv -f "/$file.pw2-new" "/$file"
done
chmod 755 /usr/share/passwall2/nftables.sh /usr/share/passwall2/app.sh /usr/bin/xray
touch "$STAGE/installed"
flock -u 6

cat > "$STAGE/rollback.sh" <<'ROLLBACK'
#!/bin/sh
# 先用新脚本停止（能清理分流子链），再恢复旧文件并启动。
set -eu
STAGE=/root/passwall2-hot-reload-test-20261003/global-switch-20261004
/etc/init.d/passwall2 stop || true
(cd / && tar -xzf "$STAGE/backup/files.tar.gz")
/etc/init.d/passwall2 start
echo "已恢复全局节点热切换增量之前的文件并重新启动 passwall2。"
ROLLBACK
chmod 700 "$STAGE/rollback.sh"
echo "增量文件已安装（尚未重启）。回滚：$STAGE/rollback.sh"
