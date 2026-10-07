#!/usr/bin/env python3
"""家里实测节点地址变化的热更新；只针对家里路由器。

新增一个不被任何实例引用的临时节点（地址为当前会得到 FakeIP 的域名，下载地址为文档用 IP）：
reload 不重启核心与 DNS，前置 DNS 的 servers-file 加入该域名并经 SIGHUP 重读，之后经路由器解析得到真实地址；
文档用 IP 进入 psw2_vps。删除临时节点同样热更新。旧的透明代理与 SOCKS 长连接全程可用，配置逐字节恢复。
"""

import json
import time

from home_global_switch_test import ROOT, log_lines, remote, status, transparent_request
from home_memory_probe import connection, request

SECTION = "pw2endpointtest"
DOWNLOAD_IP = "203.0.113.77"
CANDIDATES = ("www.cloudflare.com", "www.wikipedia.org", "www.bing.com", "github.com")
SERVERS = "/tmp/etc/passwall2_tmp/dnsmasq_acl_default.servers"


def resolve(domain):
    out = remote(f"nslookup {domain} 2>/dev/null | awk '/^Address/ && $NF !~ /#/ {{a=$NF}} END {{print a}}'", check=False)
    return out.strip()


def wait_reload(before, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = log_lines()[len(before):]
        if any("配置重载 [acl_default]" in line or "完整重启" in line or "失败" in line for line in lines):
            time.sleep(4)
            return log_lines()[len(before):]
        time.sleep(1)
    raise AssertionError("reload 未执行：" + "\n".join(log_lines()[len(before):]))


def check_hot(lines, baseline):
    joined = "\n".join(lines)
    assert "节点地址变化" in joined, joined
    assert "完整重启" not in joined and "失败" not in joined, joined
    now = status()
    assert now["core"] == baseline["core"], "核心进程被重启"
    assert now["dns"] == baseline["dns"], "DNS 实例被重启"
    assert now["main"] == baseline["main"] and now["sub"] == baseline["sub"], "防火墙规则发生变化"


def ubus(method, payload):
    remote(f"ubus call uci {method} '{json.dumps(payload)}' && ubus call uci commit '{{\"config\":\"passwall2\"}}'")


def main():
    baseline = status()
    assert baseline["core"] and baseline["dns"], "家里默认实例未运行"
    assert remote(f"uci -q get passwall2.{SECTION}", check=False).strip() == "", "残留的临时节点"
    assert remote(f"test -f {SERVERS} && echo yes", check=False).strip() == "yes", "前置 DNS 未使用 servers-file，需先受控重启"
    config_hash = remote("sha256sum /etc/config/passwall2").split()[0]
    remote(f"umask 077; cp -p /etc/config/passwall2 {ROOT}/endpoint-baseline.config")
    domain = next((d for d in CANDIDATES if resolve(d).startswith("198.18.")), None)
    assert domain, "没有找到当前得到 FakeIP 的候选域名"

    remote("rm -f /tmp/pw2t.fifo /tmp/pw2t.out /tmp/pw2t.err; mkfifo /tmp/pw2t.fifo; "
           "(sleep 900 > /tmp/pw2t.fifo &); "
           "(openssl s_client -connect www.google.com:443 -servername www.google.com -quiet < /tmp/pw2t.fifo > /tmp/pw2t.out 2>/tmp/pw2t.err &)")
    socks = connection()
    try:
        time.sleep(3)
        transparent_request(1)
        print(f"PASS：变更前透明代理与 SOCKS 长连接可用；{domain} 当前解析为 FakeIP。")

        before = log_lines()
        ubus("add", {"config": "passwall2", "type": "nodes", "name": SECTION,
                     "values": {"remarks": "endpoint-test", "type": "sing-box", "protocol": "vless", "address": domain,
                                "download_address": DOWNLOAD_IP, "port": "443", "uuid": "00000000-0000-4000-8000-000000000000"}})
        check_hot(wait_reload(before), baseline)
        assert f"server=/.{domain}/" in remote(f"cat {SERVERS}"), "servers-file 未加入新节点域名"
        real = resolve(domain)
        assert real and not real.startswith("198.18."), f"新节点域名仍解析为 FakeIP：{real}"
        remote(f"nft get element inet passwall2 psw2_vps '{{ {DOWNLOAD_IP} }}' >/dev/null")
        transparent_request(2)
        request(socks)
        print(f"PASS：新增节点热更新：核心/DNS/防火墙规则不变，前置 DNS 经 SIGHUP 改由国内 DNS 解析 {domain}（{real}），"
              f"{DOWNLOAD_IP} 已加入 psw2_vps，旧连接可用。")

        before = log_lines()
        ubus("delete", {"config": "passwall2", "section": SECTION})
        check_hot(wait_reload(before), baseline)
        assert f"server=/.{domain}/" not in remote(f"cat {SERVERS}"), "删除节点后 servers-file 仍含该域名"
        transparent_request(3)
        request(socks)
        print("PASS：删除节点热更新，servers-file 已移除该域名，旧连接持续可用。")
    finally:
        socks.close()
        remote("for p in $(busybox pgrep -f 'openssl s_clien[t] -connect www.google.com') $(busybox pgrep -f 'slee[p] 900'); do kill $p; done; "
               "rm -f /tmp/pw2t.fifo /tmp/pw2t.out /tmp/pw2t.err", check=False)
        if remote(f"uci -q get passwall2.{SECTION}", check=False).strip():
            ubus("delete", {"config": "passwall2", "section": SECTION})
    assert remote("sha256sum /etc/config/passwall2").split()[0] == config_hash, "passwall2 配置未能逐字节恢复"
    print("PASS：passwall2 配置已逐字节恢复。")


if __name__ == "__main__":
    main()
