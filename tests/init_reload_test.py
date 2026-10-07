#!/usr/bin/env python3
"""在临时目录中验证 init 重载状态机与实际 flock，不执行路由器操作。"""

import os
import sys
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest


REPO = Path(__file__).resolve().parents[1]
INIT = REPO / "luci-app-passwall2/root/etc/init.d/passwall2"

# 桩 app.sh：记录调用、忙碌标记与 fd 9 继承情况；reload 退出码按调用序号从 RELOAD_CODES 取值。
APP_STUB = r"""#!/bin/sh
if [ "$1" = reload ]; then
	n=$(( $(cat "$ROOT/reload.count" 2>/dev/null || echo 0) + 1 ))
	echo "$n" > "$ROOT/reload.count"
fi
marker=no; [ -f "$ROOT/locks/passwall2.lock" ] && marker=yes
fd9=closed; [ -e /proc/$$/fd/9 ] && fd9=open
printf '%s marker=%s fd9=%s\n' "$1" "$marker" "$fd9" >> "$ROOT/calls"
if [ "$1" = start ]; then
	[ -n "$COMMIT_DURING_START" ] && "$ROOT/trigger.sh" > "$ROOT/trigger.out" 2>&1 &
	[ -n "$APP_DELAY" ] && sleep "$APP_DELAY"
fi
if [ "$1" = reload ]; then
	code=0; i=0
	for c in $RELOAD_CODES; do i=$((i + 1)); [ "$i" -eq "$n" ] && code=$c; done
	exit "$code"
fi
exit 0
"""

# busybox ash 优先解析内建 applet，PATH 包装无效；本机 busybox 缺少 pgrep，用函数把它转给 procps。
# 路由器上 busybox 自带 pgrep 且语义相同；PGREP_MODE=broken 模拟无法判断进程状态。
PGREP_SHIM = (
    'busybox() { if [ "$1" = pgrep ]; then shift; [ "$PGREP_MODE" = broken ] && return 127; /usr/bin/pgrep "$@"; '
    'else command busybox "$@"; fi; }; '
)
PREFIX = (
    '. "$INIT"; ' + PGREP_SHIM + 'LOCK_PATH="$ROOT/locks"; LOCK_FILE="$LOCK_PATH/passwall2.lock"; '
    'FLOCK_FILE="$LOCK_PATH/passwall2.flock"; PENDING_FILE="$LOCK_PATH/passwall2_reload.pending"; '
    'CRON_FILE="$ROOT/cron.lock"; '
)


class InitReloadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="passwall2-init-test-")
        self.root = Path(self.tmp.name)
        (self.root / "usr/share/passwall2").mkdir(parents=True)
        (self.root / "locks").mkdir()
        (self.root / "usr/share/passwall2/utils.sh").write_text(
            "CONFIG=passwall2\nAPP_PATH=$IPKG_INSTROOT/usr/share/passwall2\nLOCK_PATH=$ROOT/locks\n"
            "log() { shift; printf '%s\\n' \"$*\" >> \"$ROOT/log\"; }\nlog_i18n() { log \"$@\"; }\n"
        )
        app = self.root / "usr/share/passwall2/app.sh"
        app.write_text(APP_STUB)
        app.chmod(0o700)
        self.env = dict(os.environ, IPKG_INSTROOT=str(self.root), ROOT=str(self.root), INIT=str(INIT))

    def tearDown(self):
        self.tmp.cleanup()

    def run_action(self, action, wait=2, **extra):
        result = subprocess.run(["busybox", "ash", "-c", PREFIX + f"LOCK_WAIT={wait}; " + action],
                                env=dict(self.env, **extra), capture_output=True, text=True, timeout=90)
        return result.returncode, self.calls()

    def calls(self):
        path = self.root / "calls"
        return path.read_text().splitlines() if path.exists() else []

    def hold_lock(self, seconds):
        holder = subprocess.Popen(["flock", "-x", str(self.root / "locks/passwall2.flock"), "sleep", str(seconds)])
        time.sleep(0.3)
        return holder

    def test_native_success_does_not_stop_service(self):
        code, calls = self.run_action("reload", RELOAD_CODES="0")
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["reload marker=yes fd9=closed"], "子进程不能继承锁描述符")
        self.assertTrue((self.root / "locks/passwall2.flock").exists(), "互斥锁文件必须保持同一 inode")
        self.assertFalse((self.root / "locks/passwall2.lock").exists(), "忙碌标记必须在操作结束后移除")

    def test_invalid_configuration_keeps_service(self):
        code, calls = self.run_action("reload", RELOAD_CODES="1")
        self.assertEqual(code, 1)
        self.assertEqual(calls, ["reload marker=yes fd9=closed"])

    def test_structural_change_uses_full_restart(self):
        code, calls = self.run_action("reload", RELOAD_CODES="2")
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["reload marker=yes fd9=closed", "stop marker=yes fd9=closed",
                                 "start marker=yes fd9=closed"])

    def test_cron_marker_cleared_only_without_start(self):
        for codes, expected in (("0", False), ("1", False), ("2", True)):
            with self.subTest(codes=codes):
                (self.root / "cron.lock").write_text("")
                (self.root / "reload.count").unlink(missing_ok=True)
                self.run_action("reload", RELOAD_CODES=codes)
                # 退出码 2 时由真正的 start 消费标记；这里的桩不处理，因此应保留。
                self.assertEqual((self.root / "cron.lock").exists(), expected)

    def test_brief_holder_is_waited_for(self):
        holder = self.hold_lock(1.5)
        try:
            code, calls = self.run_action("reload", wait=4, RELOAD_CODES="0")
        finally:
            holder.wait(timeout=10)
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["reload marker=yes fd9=closed"], "看门狗短暂持锁时不能丢弃配置应用")

    def test_long_holder_queues_and_next_operation_consumes(self):
        holder = self.hold_lock(7)
        try:
            code, calls = self.run_action("reload", wait=1, RELOAD_CODES="0")
            self.assertEqual(code, 0)
            self.assertEqual(calls, [], "等待超时后应排队，不能并发执行")
            self.assertTrue((self.root / "locks/passwall2_reload.pending").exists())
            self.assertIn("已排队", (self.root / "log").read_text())
        finally:
            holder.wait(timeout=15)
        code, calls = self.run_action("restart", RELOAD_CODES="0")
        self.assertEqual(code, 0)
        self.assertEqual([c.split()[0] for c in calls], ["stop", "start"],
                         "restart 自身读取最新配置，开始时清除排队标记")
        self.assertFalse((self.root / "locks/passwall2_reload.pending").exists())

    def test_commit_during_start_is_drained_before_unlock(self):
        trigger = self.root / "trigger.sh"
        trigger.write_text('#!/bin/sh\n' + PREFIX + 'LOCK_WAIT=1; reload; echo "status=$?"\n')
        trigger.chmod(0o700)
        code, calls = self.run_action("start", APP_DELAY="6", COMMIT_DURING_START="1", RELOAD_CODES="0")
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["start marker=yes fd9=closed", "reload marker=yes fd9=closed"],
                         "启动期间排队的配置必须由启动者在解锁前补做")
        self.assertIn("status=0", (self.root / "trigger.out").read_text())
        self.assertFalse((self.root / "locks/passwall2_reload.pending").exists())

    def test_stale_update_lock_is_removed(self):
        stale = self.root / "locks/passwall2_subscribe.lock"
        stale.write_text("")
        started = time.monotonic()
        code, calls = self.run_action("reload", RELOAD_CODES="0")
        self.assertEqual(code, 0)
        self.assertLess(time.monotonic() - started, 10, "没有订阅进程时不能等待残留锁")
        self.assertFalse(stale.exists())
        self.assertEqual(calls, ["reload marker=yes fd9=closed"])

    def test_unknown_process_state_is_not_treated_as_stale(self):
        lock = self.root / "locks/passwall2_subscribe.lock"
        lock.write_text("")
        remover = threading.Timer(2, lock.unlink)
        remover.start()
        started = time.monotonic()
        code, calls = self.run_action("reload", RELOAD_CODES="0", PGREP_MODE="broken")
        remover.join(timeout=10)
        self.assertEqual(code, 0)
        self.assertGreaterEqual(time.monotonic() - started, 1.5, "无法判断进程状态时不能删除更新锁")
        self.assertEqual(calls, ["reload marker=yes fd9=closed"])

    def test_live_update_lock_is_respected(self):
        lock = self.root / "locks/passwall2_rule_update.lock"
        lock.write_text("")
        script = self.root / "passwall2/rule_update.lua"
        script.parent.mkdir()
        script.write_text("import time\ntime.sleep(4)\n")
        # 命令行与路由器上的调用一致：lua <路径>/passwall2/rule_update.lua log all cron
        updater = subprocess.Popen(["lua", str(script), "log", "all", "cron"], executable=sys.executable)
        try:
            time.sleep(0.3)
            remover = threading.Timer(2, lock.unlink)
            remover.start()
            started = time.monotonic()
            code, calls = self.run_action("reload", RELOAD_CODES="0")
            elapsed = time.monotonic() - started
            remover.join(timeout=10)
        finally:
            updater.wait(timeout=10)
        self.assertEqual(code, 0)
        self.assertGreaterEqual(elapsed, 1.5, "更新任务运行时必须等待其锁释放")
        self.assertEqual(calls, ["reload marker=yes fd9=closed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
