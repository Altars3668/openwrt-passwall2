#!/usr/bin/env python3
"""家里实测 LuCI 同款路径：ubus 提交 → procd/ucitrack 触发 reload；只针对家里路由器。"""

import json
import subprocess
import time

from home_memory_probe import SSH, connection, remote, request

ROOT = "/root/passwall2-hot-reload-test-20261003"


def status():
    out = remote(
        "for d in /proc/[0-9]*; do c=$(tr '\\0' ' ' < $d/cmdline 2>/dev/null); case \"$c\" in "
        "'/tmp/etc/passwall2/bin/sing-box run -c /tmp/etc/passwall2/acl/acl_default.json '*) echo core=${d#/proc/};; "
        "'/tmp/etc/passwall2/bin/dnsmasq_acl_default '*) echo dns=${d#/proc/};; esac; done")
    values = dict(line.split("=", 1) for line in out.split())
    rules = json.loads(remote("nft -s -j list table inet passwall2"))["nftables"]
    values["nft"] = json.dumps([item for item in rules if "rule" in item or "chain" in item], sort_keys=True)
    return values


def log_lines():
    return remote("cat /tmp/log/passwall2.log").splitlines()


def wait_reload(before, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = log_lines()[len(before):]
        done = [line for line in lines if "配置重载 [acl_default]" in line or "完整重启" in line or "校验失败" in line]
        if done:
            time.sleep(4)  # 留出时间暴露可能的重复触发
            return log_lines()[len(before):]
        time.sleep(1)
    raise AssertionError("procd 触发器未执行 reload")


def ubus_commit(section, option, value):
    payload = json.dumps({"config": "passwall2", "section": section, "values": {option: value}})
    remote(f"ubus call uci set '{payload}' && ubus call uci commit '{{\"config\":\"passwall2\"}}'")


def assert_stable(before, after):
    assert before["core"] == after["core"], "核心进程被重启"
    assert before["dns"] == after["dns"], "DNS 实例被重启"
    assert before["nft"] == after["nft"], "防火墙链或规则发生变化"


baseline = status()
original = remote("uci -q get passwall2.myshunt.Proxy").strip()
target = "us31003" if original != "us31003" else "SjyWplsT"
remote(f"umask 077; uci export passwall2 > {ROOT}/procd-baseline.uci")
old = connection()
try:
    before = log_lines()
    ubus_commit("myshunt", "Proxy", target)
    new_lines = wait_reload(before)
    reloads = [line for line in new_lines if "配置重载 [acl_default]" in line]
    assert reloads and all("原生热更新" in line for line in reloads), new_lines
    assert len(reloads) == 1, f"重复触发 reload：{new_lines}"
    assert not any("完整重启" in line for line in new_lines), new_lines
    assert_stable(baseline, status())
    request(old)
    with connection() as fresh:
        request(fresh)
    print("PASS：LuCI 同款 ubus 提交由 procd 触发且仅触发一次 reload，分流节点原生切换；旧连接、新连接、核心／DNS／防火墙均保持。")

    before = log_lines()
    ubus_commit("myshunt", "Proxy", original)
    new_lines = wait_reload(before)
    assert [line for line in new_lines if "原生热更新" in line], new_lines
    assert_stable(baseline, status())
    request(old)
    print("PASS：分流节点经 procd 原生恢复。")

    fw_hash = remote("sha256sum /etc/config/firewall /etc/config/dhcp")
    remote(f"umask 077; cp -p /etc/config/firewall {ROOT}/firewall.probe-backup; cp -p /etc/config/dhcp {ROOT}/dhcp.probe-backup")
    try:
        remote("uci set firewall.pw2_reload_probe=rule; uci set firewall.pw2_reload_probe.name=pw2-reload-probe; "
               "uci set firewall.pw2_reload_probe.enabled=0; uci set firewall.pw2_reload_probe.src=wan; uci commit firewall; "
               "uci set dhcp.pw2_reload_probe=domain; uci set dhcp.pw2_reload_probe.name=pw2-reload-probe.invalid; "
               "uci set dhcp.pw2_reload_probe.ip=192.0.2.1; uci commit dhcp")
        before = log_lines()
        result = subprocess.run(SSH + ["/etc/init.d/passwall2 reload"], capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, result.stdout + result.stderr
        new_lines = log_lines()[len(before):]
        assert not any("完整重启" in line for line in new_lines), new_lines
        assert any("无运行时变化" in line for line in new_lines), new_lines
        assert_stable(baseline, status())
        print("PASS：其它脚本改写防火墙规则与 DHCP 域名记录后，reload 不再完整重启。")
    finally:
        # 直接逐字节恢复文件，不在共享 uci 暂存区留下未提交改动。
        remote(f"cp -p {ROOT}/firewall.probe-backup /etc/config/firewall; cp -p {ROOT}/dhcp.probe-backup /etc/config/dhcp")
        assert remote("sha256sum /etc/config/firewall /etc/config/dhcp") == fw_hash, "防火墙或 DHCP 配置未能逐字节恢复"
finally:
    old.close()
    current = remote("uci -q get passwall2.myshunt.Proxy").strip()
    if current != original:
        ubus_commit("myshunt", "Proxy", original)
        time.sleep(8)
assert remote("uci -q get passwall2.myshunt.Proxy").strip() == original
print("PASS：测试改动已恢复，防火墙与 DHCP 配置逐字节一致。")
