#!/usr/bin/env python3
"""家里实测：dnsmasq 主实例模式（dns_redirect=0）完整启动后，空跑差量计划应为“无变化”。

影子启动把主实例配置写进暂存文件；缓存标记若按暂存路径计算，完整启动后的每次比较都会把主实例缓存误判为变化
（办公室路由器上线时发现）。流程：经 ubus 切到主实例模式（差量热重载）→ 完整重启 → plan 必须为 none →
切回（差量热重载）；passwall2 配置逐字节恢复，dhcp 按 uci 语义恢复后再逐字节复原。只针对家里路由器。
"""

import time

from home_global_switch_test import ROOT, remote, status
from home_reconcile_test import check_hot, log_lines, set_option, wait_reconcile


def plan():
    return remote("cd /usr/share/pass''wall2 && lua ./reload.lua plan", timeout=180).splitlines()


def changed(lines):
    return [line for line in lines[1:] if not line.endswith(": ") and line not in ("main_dnsmasq: false",)]


def main():
    section = remote("uci -q show passwall2.@global[0] | head -n 1 | cut -d. -f2 | cut -d= -f1").strip()
    assert section.isalnum()
    assert remote("uci -q get passwall2.@global[0].dns_redirect").strip() in ("", "1"), "家里应处于 DNS 劫持模式"
    config_hash = remote("sha256sum /etc/config/passwall2").split()[0]
    dhcp_hash = remote("uci -q show dhcp | sort | sha256sum").split()[0]
    remote(f"umask 077; cp -p /etc/config/passwall2 {ROOT}/mainplan-baseline.config; cp -p /etc/config/dhcp {ROOT}/mainplan-baseline.dhcp")
    try:
        before = log_lines()
        set_option(section, "dns_redirect", "0")
        check_hot(wait_reconcile(before))
        print("  已切到 dnsmasq 主实例模式（差量热重载）。")
        remote("/etc/init.d/passwall2 restart", timeout=240)
        deadline = time.monotonic() + 60
        while not status().get("core"):
            assert time.monotonic() < deadline, "完整重启后核心未运行"
            time.sleep(2)
        lines = plan()
        assert lines[0] == "plan: none", "主实例模式完整启动后 plan 不是 none：" + " | ".join(changed(lines))
        print("  完整重启后空跑计划：plan: none。")
    finally:
        before = log_lines()
        set_option(section, "dns_redirect", "1")
        joined = wait_reconcile(before)
        assert remote("sha256sum /etc/config/passwall2").split()[0] == config_hash, "passwall2 配置未逐字节恢复"
        assert remote("uci -q show dhcp | sort | sha256sum").split()[0] == dhcp_hash, "dhcp 配置未按语义恢复"
        # 上游接入主实例时先删后加 dhcp 的 server 列表，段内选项顺序会变；语义一致后逐字节复原（dnsmasq 无需重载）。
        remote(f"cp -p {ROOT}/mainplan-baseline.dhcp /etc/config/dhcp")
    check_hot(joined)
    assert status().get("dns"), "切回后前置 DNS 未运行"
    print("PASS：主实例模式完整启动后无误报变化；配置已恢复。")


if __name__ == "__main__":
    main()
