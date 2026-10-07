#!/usr/bin/env python3
"""家里实测定时类选项的热更新；只针对家里路由器。

关闭再打开看门狗（global_delay.start_daemon）：reload 只重建计划任务与后台进程，核心、DNS 与防火墙不变，
看门狗随之停止与重新启动，crontab 内容不变；测试结束配置逐字节恢复。
"""

import time

from home_global_switch_test import ROOT, log_lines, remote, status, ubus_commit

MONITOR = "for d in /proc/[0-9]*; do case \"$(tr '\\0' ' ' < $d/cmdline 2>/dev/null)\" in */usr/share/passwall2/monito[r].sh*) echo ${d#/proc/};; esac; done"


def wait_schedule(before, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = log_lines()[len(before):]
        if any("计划任务" in line or "完整重启" in line or "失败" in line for line in lines):
            time.sleep(3)
            return "\n".join(log_lines()[len(before):])
        time.sleep(1)
    raise AssertionError("reload 未执行：" + "\n".join(log_lines()[len(before):]))


def main():
    baseline = status()
    assert baseline["core"] and baseline["dns"], "家里默认实例未运行"
    section = remote("uci -q show passwall2.@global_delay[0] | head -n 1 | cut -d. -f2 | cut -d= -f1").strip()
    assert section.isalnum() and remote(f"uci -q get passwall2.{section}.start_daemon").strip() == "1", section
    config_hash = remote("sha256sum /etc/config/passwall2").split()[0]
    remote(f"umask 077; cp -p /etc/config/passwall2 {ROOT}/schedule-baseline.config")
    crontab = remote("sort /etc/crontabs/root")
    monitors = remote(MONITOR).split()
    assert len(monitors) == 1, monitors
    try:
        before = log_lines()
        ubus_commit(section, "start_daemon", "0")
        joined = wait_schedule(before)
        assert "计划任务、看门狗与循环更新已按新设置重建" in joined and "完整重启" not in joined, joined
        assert remote(MONITOR).split() == [], "关闭后看门狗仍在运行"
        now = status()
        assert (now["core"], now["dns"], now["main"], now["sub"]) == (baseline["core"], baseline["dns"], baseline["main"], baseline["sub"])
        print("PASS：关闭看门狗：只重建计划任务，看门狗已停止，核心/DNS/防火墙不变。")

        before = log_lines()
        ubus_commit(section, "start_daemon", "1")
        joined = wait_schedule(before)
        assert "计划任务、看门狗与循环更新已按新设置重建" in joined and "完整重启" not in joined, joined
        restarted = remote(MONITOR).split()
        assert len(restarted) == 1 and restarted != monitors, restarted
        assert remote("sort /etc/crontabs/root") == crontab, "crontab 内容发生变化"
        now = status()
        assert (now["core"], now["dns"], now["main"], now["sub"]) == (baseline["core"], baseline["dns"], baseline["main"], baseline["sub"])
        print("PASS：重新打开看门狗：看门狗已重新启动，crontab 内容不变，核心/DNS/防火墙不变。")
    finally:
        if remote(f"uci -q get passwall2.{section}.start_daemon").strip() != "1":
            ubus_commit(section, "start_daemon", "1")
    assert remote("sha256sum /etc/config/passwall2").split()[0] == config_hash, "passwall2 配置未能逐字节恢复"
    print("PASS：passwall2 配置已逐字节恢复。")


if __name__ == "__main__":
    main()
