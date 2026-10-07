#!/bin/sh
set -eu
umask 077
ROOT=/root/passwall2-hot-reload-test-20261003
[ "$(ubus call system board | jsonfilter -e '@.release.target')" = "x86/64" ] || exit 1
[ "$(ubus call system board | jsonfilter -e '@.model')" = "Microsoft Corporation Virtual Machine" ] || exit 1
[ -s "$ROOT/overlay.tar.gz" ] && [ -s "$ROOT/overlay.manifest" ] || exit 1
mkdir -p "$ROOT/backup" "$ROOT/payload"
if [ -f "$ROOT/backup/complete" ]; then
	[ -f "$ROOT/rolled-back" ] || { printf '已有未完成覆盖，拒绝覆盖最初备份。\n'; exit 1; }
else
: > "$ROOT/backup/existing.list"
: > "$ROOT/backup/new.list"
while IFS= read -r file; do
	case "$file" in ''|/*|*..*) exit 1;; esac
	case "$file" in usr/*|etc/init.d/*|etc/hotplug.d/*|www/*) ;; *) exit 1;; esac
	if [ -e "/$file" ] || [ -L "/$file" ]; then
		printf '%s\n' "$file" >> "$ROOT/backup/existing.list"
	else
		printf '%s\n' "$file" >> "$ROOT/backup/new.list"
	fi
done < "$ROOT/overlay.manifest"
printf '%s\n' etc/config/passwall2 etc/config/dhcp etc/config/passwall2_server >> "$ROOT/backup/existing.list"
(cd / && tar -czf "$ROOT/backup/original.tar.gz" -T "$ROOT/backup/existing.list")
cp /etc/config/passwall2 "$ROOT/backup/passwall2.original"
sha256sum /etc/config/passwall2 > "$ROOT/backup/config.sha256"
fi
rm -f "$ROOT/rolled-back" "$ROOT/commit"
tar -xzf "$ROOT/overlay.tar.gz" -C "$ROOT/payload"
for file in $(find "$ROOT/payload/usr/lib/lua/luci" -type f -name '*.lua'); do
	PW2_FILE="$file" lua -e 'assert(loadfile(os.getenv("PW2_FILE")))'
done
/bin/sh -n "$ROOT/payload/usr/share/passwall2/app.sh"
/bin/sh -n "$ROOT/payload/etc/init.d/passwall2"
touch "$ROOT/backup/complete"
cat > "$ROOT/rollback.sh" <<'ROLLBACK'
#!/bin/sh
set -eu
umask 077
ROOT=/root/passwall2-hot-reload-test-20261003
[ -s "$ROOT/backup/original.tar.gz" ] || exit 1
/etc/init.d/passwall2 stop || true
(cd / && tar -xzf "$ROOT/backup/original.tar.gz")
while IFS= read -r file; do rm -f "/$file"; done < "$ROOT/backup/new.list"
rm -f /tmp/luci-indexcache /tmp/luci-modulecache/*passwall2* 2>/dev/null || true
/etc/init.d/passwall2 start
printf '已恢复覆盖前的应用、核心和家里配置。\n'
touch "$ROOT/rolled-back"
ROLLBACK
chmod 700 "$ROOT/rollback.sh"
cat > "$ROOT/watch.sh" <<'WATCH'
#!/bin/sh
ROOT=/root/passwall2-hot-reload-test-20261003
for i in $(seq 1 720); do
	[ -f "$ROOT/commit" ] && exit 0
	sleep 10
done
[ -f "$ROOT/commit" ] || "$ROOT/rollback.sh" > "$ROOT/rollback.log" 2>&1
WATCH
chmod 700 "$ROOT/watch.sh"
nohup /bin/sh "$ROOT/watch.sh" </dev/null > "$ROOT/watch.log" 2>&1 &
printf '%s\n' "$!" > "$ROOT/watch.pid"
/etc/init.d/passwall2 stop
while IFS= read -r file; do
	mkdir -p "/${file%/*}"
	cp -p "$ROOT/payload/$file" "/$file.pw2-new"
	mv -f "/$file.pw2-new" "/$file"
	chown root:root "/$file"
done < "$ROOT/overlay.manifest"
rm -f /tmp/luci-indexcache /tmp/luci-modulecache/*passwall2* 2>/dev/null || true
if ! /etc/init.d/passwall2 start; then
	"$ROOT/rollback.sh"
	exit 1
fi
printf '家里完整覆盖完成；120 分钟自动回滚已启用，等待验收确认。\n'
