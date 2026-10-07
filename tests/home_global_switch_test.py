#!/usr/bin/env python3
"""家里实测全局节点无损热切换（分流节点 ↔ 普通节点）；只针对家里路由器，不连接办公室路由器。

- 经 LuCI 同款 ubus 提交触发 procd reload；
- 路由器自身经 nft 透明重定向保持一条 TLS keep-alive 连接，另经 SOCKS 隧道保持一条；
- 校验核心与 DNS 进程不变、主链不变、只替换分流子链；切换后旧连接与新连接均可用；
- 切到不使用 FakeDNS 的节点后，切换前分配的 FakeIP 仍能还原域名；
- 测试结束恢复原全局节点，配置文件逐字节一致。
远端命令行避免出现 "passwall2/"：完整重启时 app.sh 会结束命令行含该字符串的进程。
"""

import json
import subprocess
import time

from home_memory_probe import SSH, connection, request

ROOT = "/root/passwall2-hot-reload-test-20261003"
SHUNT_CHAINS = ("PSW2_SHUNT_NAT", "PSW2_SHUNT_MARK", "PSW2_SHUNT_MARK6", "PSW2_SHUNT_ICMP", "PSW2_SHUNT_ICMP6")
REQUEST = r"printf 'GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\n\r\n' > /tmp/pw2t.fifo"


def remote(command, check=True, timeout=90):
    result = subprocess.run(SSH + [command], capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    if check and result.returncode:
        raise AssertionError(f"家里命令失败：{result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def status():
    out = remote(
        "for d in /proc/[0-9]*; do c=$(tr '\\0' ' ' < $d/cmdline 2>/dev/null); case \"$c\" in "
        "'/tmp/etc/passwall2/bin/sing-box run -c /tmp/etc/passwall2/acl/acl_default.json '*) echo core=${d#/proc/};; "
        "'/tmp/etc/passwall2/bin/dnsmasq_acl_default '*) echo dns=${d#/proc/};; esac; done")
    values = dict(line.split("=", 1) for line in out.split())
    main, sub = {}, {}
    for item in json.loads(remote("nft -j list table inet passwall2"))["nftables"]:
        if "rule" in item:
            rule = item["rule"]
            expr = [e for e in rule["expr"] if "counter" not in e]
            (sub if rule["chain"] in SHUNT_CHAINS else main).setdefault(rule["chain"], []).append(expr)
    values["main"] = json.dumps(main, sort_keys=True)
    values["sub"] = sub
    return values


def log_lines():
    return remote("cat /tmp/log/passwall2.log").splitlines()


def wait_reload(before, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = log_lines()[len(before):]
        if any("配置重载 [acl_default]" in line or "完整重启" in line or "失败" in line for line in lines):
            time.sleep(4)  # 暴露可能的重复触发
            return log_lines()[len(before):]
        time.sleep(1)
    raise AssertionError("procd 触发器未执行 reload")


def ubus_commit(section, option, value):
    payload = json.dumps({"config": "passwall2", "section": section, "values": {option: value}})
    remote(f"ubus call uci set '{payload}' && ubus call uci commit '{{\"config\":\"passwall2\"}}'")


def held_requests():
    return remote("grep -c 'HTTP/1.1 204' /tmp/pw2t.out", check=False).strip()


def transparent_request(expected):
    remote(REQUEST)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if held_requests() == str(expected):
            return
        time.sleep(.5)
    raise AssertionError(f"透明代理长连接第 {expected} 次请求失败：" + remote("tail -c 300 /tmp/pw2t.err", check=False))


def switch(section, node, baseline, expect_sub_empty):
    before = log_lines()
    ubus_commit(section, "node", node)
    lines = wait_reload(before)
    joined = "\n".join(lines)
    assert "全局节点热切换" in joined and "防火墙分流子链已原子替换" in joined, joined
    assert any("配置重载 [acl_default]" in line and "原生热更新" in line for line in lines), joined
    assert "完整重启" not in joined and len([l for l in lines if "配置重载 [acl_default]" in l]) == 1, joined
    now = status()
    assert now["core"] == baseline["core"], "核心进程被重启"
    assert now["dns"] == baseline["dns"], "DNS 实例被重启"
    assert now["main"] == baseline["main"], "主链发生变化"
    if expect_sub_empty:
        assert not any(now["sub"].values()), now["sub"]
    return now


def main():
    baseline = status()
    assert baseline["core"] and baseline["dns"] and any(baseline["sub"].values()), "家里全局分流节点未按新结构运行"
    config_hash = remote("sha256sum /etc/config/passwall2").split()[0]
    remote(f"umask 077; cp -p /etc/config/passwall2 {ROOT}/global-switch-baseline.config")
    section = remote("uci -q show passwall2.@global[0] | head -n 1 | cut -d. -f2 | cut -d= -f1").strip()
    original = remote("uci -q get passwall2.@global[0].node").strip()
    assert original == "myshunt" and section.isalnum(), (original, section)
    target = "us31003"
    fake = remote("nslookup www.google.com 127.0.0.1 | awk '/^Address/ {a=$2} END {print a}'").strip()
    assert fake.startswith("198.18."), f"切换前未获得 FakeIP：{fake}"

    remote("rm -f /tmp/pw2t.fifo /tmp/pw2t.out /tmp/pw2t.err; mkfifo /tmp/pw2t.fifo; "
           "(sleep 900 > /tmp/pw2t.fifo &); "
           "(openssl s_client -connect www.google.com:443 -servername www.google.com -quiet < /tmp/pw2t.fifo > /tmp/pw2t.out 2>/tmp/pw2t.err &)")
    socks = connection()
    try:
        time.sleep(3)
        transparent_request(1)
        print("PASS：切换前透明代理 TLS 长连接（nft 重定向 → 核心）与 SOCKS 长连接均可用。")

        switch(section, target, baseline, expect_sub_empty=True)
        transparent_request(2)
        request(socks)
        with connection() as fresh:
            request(fresh)
        restored = remote(f"curl -sS -o /dev/null -w '%{{http_code}}' --max-time 20 --resolve www.google.com:443:{fake} https://www.google.com/generate_204")
        assert restored == "204", f"切换前分配的 FakeIP 无法还原：{restored}"
        print("PASS：全局节点 分流→普通 原生热切换；旧透明/SOCKS 连接、新连接、旧 FakeIP 还原均通过，核心/DNS/主链未变，分流子链已清空。")

        back = switch(section, original, baseline, expect_sub_empty=False)
        assert back["sub"] == baseline["sub"], "切回后分流子链与切换前不一致"
        transparent_request(3)
        request(socks)
        with connection() as fresh:
            request(fresh)
        print("PASS：全局节点 普通→分流 原生热切换；分流子链与切换前逐条一致，旧连接持续可用。")
    finally:
        socks.close()
        # 路由器的 busybox 没有 pkill；字符类写法避免 pgrep -f 匹配到执行本命令的远端 shell 自身。
        remote("for p in $(busybox pgrep -f 'openssl s_clien[t] -connect www.google.com') $(busybox pgrep -f 'slee[p] 900'); do kill $p; done; "
               "rm -f /tmp/pw2t.fifo /tmp/pw2t.out /tmp/pw2t.err", check=False)
        if remote("uci -q get passwall2.@global[0].node").strip() != original:
            ubus_commit(section, "node", original)
            time.sleep(10)

    final_hash = remote("sha256sum /etc/config/passwall2").split()[0]
    if final_hash != config_hash:
        remote(f"cp -p {ROOT}/global-switch-baseline.config /etc/config/passwall2")
        final_hash = remote("sha256sum /etc/config/passwall2").split()[0]
    assert final_hash == config_hash, "配置文件未能逐字节恢复"
    print("PASS：测试改动已恢复，passwall2 配置逐字节一致。")


if __name__ == "__main__":
    main()
