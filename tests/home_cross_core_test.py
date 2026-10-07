#!/usr/bin/env python3
"""家里实测跨核心切换全局节点（sing-box 分流节点 ↔ Xray 节点）；只针对家里路由器。

跨核心无法无损：连接与 FakeIP 映射位于旧核心进程内。这里验证兼容路径只替换核心进程：
DNS 实例、主链不变，分流子链原子替换，看门狗条目与实例记录改为新核心，
替换后的核心仍能原生热更新；测试结束恢复原配置并逐字节核对。
"""

import json
import re
import time

from home_global_switch_test import ROOT, SHUNT_CHAINS, log_lines, remote, ubus_commit, wait_reload
from home_memory_probe import connection, request

CORES = {"sing-box": "/tmp/etc/passwall2/bin/sing-box run -c /tmp/etc/passwall2/acl/acl_default.json ",
         "xray": "/tmp/etc/passwall2/bin/xray run -c /tmp/etc/passwall2/acl/acl_default.json "}


def status():
    out = remote(
        "for d in /proc/[0-9]*; do c=$(tr '\\0' ' ' < $d/cmdline 2>/dev/null); case \"$c\" in "
        f"'{CORES['sing-box']}'*) echo sing-box=${{d#/proc/}};; '{CORES['xray']}'*) echo xray=${{d#/proc/}};; "
        "'/tmp/etc/passwall2/bin/dnsmasq_acl_default '*) echo dns=${d#/proc/};; esac; done")
    values = dict(line.split("=", 1) for line in out.split())
    main, sub = {}, {}
    for item in json.loads(remote("nft -j list table inet passwall2"))["nftables"]:
        if "rule" in item:
            rule = item["rule"]
            expr = [e for e in rule["expr"] if "counter" not in e]
            # 直连拨号节点的本机放行规则（注释为“地址:端口”）在切换到新节点时补充、不随切回删除（上游语义），不计入主链比较。
            if re.fullmatch(r"[0-9a-fA-F.:\[\]]+:\d+", str(rule.get("comment", ""))):
                continue
            (sub if rule["chain"] in SHUNT_CHAINS else main).setdefault(rule["chain"], []).append(expr)
    values["main"] = json.dumps(main, sort_keys=True)
    values["sub"] = sub
    record = json.loads(remote("cat /tmp/etc/passwall2/reload/instance_acl_default.json"))
    values["record"] = record["core"]
    values["monitor"] = remote("grep -h 'acl/acl_default.json' /tmp/etc/passwall2/script_func/* | cut -d' ' -f1").split()
    return values


def try_proxy(label):
    try:
        with connection() as fresh:
            request(fresh)
        print(f"PASS：{label} 新连接经代理返回 204。")
        return True
    except Exception as error:  # 节点可用性不由本测试决定，只记录
        print(f"WARN：{label} 新连接未成功（{type(error).__name__}），可能是该上游节点暂不可用。")
        return False


def toggle_cache(section, core, baseline):
    before = log_lines()
    # 远程 DNS 传输方式（TCP/UDP）对两种核心都生成到 DNS 配置中，属于原生热更新范围。
    current = remote("uci -q get passwall2.@global[0].remote_dns_protocol || echo tcp").strip()
    ubus_commit(section, "remote_dns_protocol", "udp" if current != "udp" else "tcp")
    lines = wait_reload(before)
    assert any("配置重载 [acl_default]" in line and "原生热更新" in line for line in lines), lines
    now = status()
    assert now[core] == baseline[core], f"{core} 原生热更新时被重启"
    assert now["dns"] == baseline["dns"], "DNS 实例被重启"
    print(f"PASS：替换后的 {core} 核心仍可原生热更新（PID 未变）。")


def switch(section, node, old_core, new_core, baseline, expect_sub):
    before = log_lines()
    ubus_commit(section, "node", node)
    lines = wait_reload(before, timeout=90)
    joined = "\n".join(lines)
    assert f"跨核心切换（{old_core} → {new_core}）" in joined, joined
    assert "防火墙分流子链已原子替换" in joined and "完整重启" not in joined, joined
    now = status()
    assert new_core in now and old_core not in now, now
    assert now["dns"] == baseline["dns"], "DNS 实例被重启"
    assert now["main"] == baseline["main"], "主链发生变化"
    assert now["record"] == new_core, now["record"]
    # 全局核心经排队启动（ln_run 队列模式不写看门狗条目）；若有条目，必须已指向新核心。
    assert all(entry == CORES[new_core].split()[0] for entry in now["monitor"]), now["monitor"]
    if expect_sub is None:
        assert not any(now["sub"].values()), now["sub"]
    else:
        assert now["sub"] == expect_sub, "分流子链与切换前不一致"
    print(f"PASS：跨核心切换 {old_core} → {new_core}：只替换核心进程，DNS／主链不变，看门狗与实例记录已更新。")
    return now


baseline = status()
assert "sing-box" in baseline and baseline["record"] == "sing-box", baseline
config_hash = remote("sha256sum /etc/config/passwall2").split()[0]
remote(f"umask 077; cp -p /etc/config/passwall2 {ROOT}/cross-core-baseline.config")
section = remote("uci -q show passwall2.@global[0] | head -n 1 | cut -d. -f2 | cut -d= -f1").strip()
original = remote("uci -q get passwall2.@global[0].node").strip()
assert original == "myshunt" and remote("uci -q get passwall2.GJn2Ee97.type").strip() == "Xray"
try:
    on_xray = switch(section, "GJn2Ee97", "sing-box", "xray", baseline, None)
    time.sleep(2)
    try_proxy("Xray 节点")
    toggle_cache(section, "xray", on_xray)
    back = switch(section, original, "xray", "sing-box", baseline, baseline["sub"])
    time.sleep(2)
    assert try_proxy("切回 sing-box 分流节点"), "切回原分流节点后代理不可用"
    fake = remote("nslookup www.google.com 127.0.0.1 | awk '/^Address/ {a=$2} END {print a}'").strip()
    assert fake.startswith("198.18."), f"切回后 FakeIP 未生效：{fake}"
    toggle_cache(section, "sing-box", back)
finally:
    if remote("sha256sum /etc/config/passwall2").split()[0] != config_hash:
        # 先按 LuCI 路径恢复全局节点，让运行状态与配置一致，再逐字节恢复文件并应用一次。
        if remote("uci -q get passwall2.@global[0].node").strip() != original:
            ubus_commit(section, "node", original)
            time.sleep(12)
        remote(f"cp -p {ROOT}/cross-core-baseline.config /etc/config/passwall2")
        remote("/etc/init.d/passwall2 reload >/dev/null 2>&1", check=False, timeout=180)
final_hash = remote("sha256sum /etc/config/passwall2").split()[0]
assert final_hash == config_hash, "配置文件未能逐字节恢复"
final = status()
assert "sing-box" in final and final["record"] == "sing-box" and final["dns"] == baseline["dns"]
print("PASS：测试改动已恢复，passwall2 配置逐字节一致，全局核心为 sing-box。")
