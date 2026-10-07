#!/usr/bin/env python3
"""家里实测差量热重载（原先需要完整重启的配置项）；只针对家里路由器，不连接办公室路由器。

每个场景经 LuCI 同款 ubus 提交触发 procd reload，校验：
- 日志为“差量热重载完成，未完整重启”，没有完整重启；
- 默认实例的核心与前置 DNS 进程按预期保持（直连 DNS 变化时前置 DNS 蓝绿替换为新进程）；
- 路由器上经透明代理的 TLS 长连接与经 SOCKS 的长连接在变更前后都可用；
- 恢复配置后防火墙主链与变更前一致（前置 DNS 换端口的场景按端口归一后比较）；
- 测试结束 passwall2 配置逐字节恢复。
用法：home_reconcile_test.py [场景 ...]，缺省运行全部场景。
"""

import json
import re
import sys
import time

from home_global_switch_test import ROOT, log_lines, remote, status, transparent_request
from home_memory_probe import connection, request

TEST_SOURCE = "192.0.2.123"


def ubus(method, payload):
    remote(f"ubus call uci {method} '{json.dumps(payload)}' && ubus call uci commit '{{\"config\":\"passwall2\"}}'")


def set_option(section, option, value):
    ubus("set", {"config": "passwall2", "section": section, "values": {option: value}})


def wait_reconcile(before, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = log_lines()[len(before):]
        if any(marker in line for line in lines for marker in ("差量热重载完成", "差量比较无运行时变化", "完整重启", "失败", "未执行")):
            time.sleep(4)  # 暴露可能的重复触发
            return "\n".join(log_lines()[len(before):])
        time.sleep(1)
    raise AssertionError("reload 未完成：" + "\n".join(log_lines()[len(before):]))


def check_hot(joined):
    assert "差量热重载完成，未完整重启" in joined, joined
    assert "完整重启" not in joined.replace("未完整重启", "") and "失败" not in joined and "未执行" not in joined, joined
    assert joined.count("差量热重载完成") == 1, joined


def procs():
    out = remote("for d in /proc/[0-9]*; do c=$(tr '\\0' ' ' < $d/cmdline 2>/dev/null); case \"$c\" in "
                 "/tmp/etc/pass[w]all2/bin/*) echo \"${d#/proc/} $c\";; esac; done")
    return [line.split(" ", 1) for line in out.splitlines() if line.strip()]


def normalized_main(main_json, ports):
    text = main_json
    for port, name in ports.items():
        text = re.sub(rf'"port": {port}\b', f'"port": "{name}"', text)
        text = re.sub(rf'\b{port}\b', name, text)
    return text


def stable():
    return dict(line.split(" ", 1) for line in remote("cat /tmp/etc/pass''wall2/stable").splitlines() if " " in line)


class Session:
    def __init__(self):
        self.baseline = status()
        assert self.baseline["core"] and self.baseline["dns"], "家里默认实例未运行"
        self.section = remote("uci -q show passwall2.@global[0] | head -n 1 | cut -d. -f2 | cut -d= -f1").strip()
        self.fwd = remote("uci -q show passwall2.@global_forwarding[0] | head -n 1 | cut -d. -f2 | cut -d= -f1").strip()
        assert self.section.isalnum() and self.fwd.isalnum()
        self.config_hash = remote("sha256sum /etc/config/passwall2").split()[0]
        remote(f"umask 077; cp -p /etc/config/passwall2 {ROOT}/reconcile-baseline.config")
        remote("rm -f /tmp/pw2t.fifo /tmp/pw2t.out /tmp/pw2t.err; mkfifo /tmp/pw2t.fifo; "
               "(sleep 1800 > /tmp/pw2t.fifo &); "
               "(openssl s_client -connect www.google.com:443 -servername www.google.com -quiet < /tmp/pw2t.fifo > /tmp/pw2t.out 2>/tmp/pw2t.err &)")
        self.socks = connection()
        self.requests = 0
        time.sleep(3)
        self.alive("变更前")

    def alive(self, when):
        self.requests += 1
        transparent_request(self.requests)
        request(self.socks)
        with connection() as fresh:
            request(fresh)
        print(f"  {when}：透明代理 TLS 长连接、SOCKS 长连接与新连接均可用。")

    def apply(self, action, expect_hot=True):
        before = log_lines()
        started = time.monotonic()
        action()
        joined = wait_reconcile(before)
        if expect_hot:
            check_hot(joined)
        elapsed = time.monotonic() - started
        summary = [line.split("差量热重载完成，未完整重启：", 1)[1] for line in joined.splitlines() if "差量热重载完成" in line]
        print(f"  {elapsed:.0f} 秒：{summary[0] if summary else joined.splitlines()[-1]}")
        return joined

    def close(self):
        self.socks.close()
        remote("for p in $(busybox pgrep -f 'openssl s_clien[t] -connect www.google.com') $(busybox pgrep -f 'slee[p] 1800'); do kill $p; done; "
               "rm -f /tmp/pw2t.fifo /tmp/pw2t.out /tmp/pw2t.err", check=False)


def scenario_localhost_proxy(s):
    """本机代理关闭再打开：只替换防火墙规则，核心与前置 DNS 不变，已建立的本机透明连接保持。"""
    set_back = remote(f"uci -q get passwall2.{s.section}.localhost_proxy").strip()
    assert set_back == "1"
    s.apply(lambda: set_option(s.section, "localhost_proxy", "0"))
    now = status()
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"]), "核心或前置 DNS 被重启"
    assert "PSW2_OUTPUT_NAT" not in json.dumps(json.loads(now["main"]).get("nat_output", [])), "本机代理规则仍在"
    s.alive("关闭本机代理后（已建立连接）")
    s.apply(lambda: set_option(s.section, "localhost_proxy", "1"))
    now = status()
    assert now["main"] == s.baseline["main"] and now["sub"] == s.baseline["sub"], "恢复后防火墙规则与变更前不一致"
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"])
    s.alive("恢复本机代理后")


def scenario_ports(s):
    """代理端口增加 8443 再恢复：防火墙规则在一个事务中替换。"""
    original = remote(f"uci -q get passwall2.{s.fwd}.tcp_redir_ports").strip()
    s.apply(lambda: set_option(s.fwd, "tcp_redir_ports", original + ",8443"))
    now = status()
    assert "8443" in now["main"] and (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"])
    s.alive("增加代理端口后")
    s.apply(lambda: set_option(s.fwd, "tcp_redir_ports", original))
    now = status()
    assert now["main"] == s.baseline["main"], "恢复后防火墙规则与变更前不一致"
    s.alive("恢复代理端口后")


def scenario_acl_follow(s):
    """新增跟随全局的访问控制条目再删除：只增删防火墙规则（共享分流子链）。"""
    s.apply(lambda: ubus("add", {"config": "passwall2", "type": "acl_rule", "name": "pw2acltest",
                                 "values": {"enabled": "1", "remarks": "pw2-test", "sources": [TEST_SOURCE], "mode": "2"}}))
    now = status()
    assert TEST_SOURCE in now["main"], "新条目的规则未加入"
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"])
    s.alive("新增跟随全局的访问控制后")
    s.apply(lambda: ubus("delete", {"config": "passwall2", "section": "pw2acltest"}))
    now = status()
    assert now["main"] == s.baseline["main"], "删除条目后防火墙规则与变更前不一致"
    s.alive("删除该访问控制后")


def scenario_acl_instance(s):
    """新增使用独立节点的访问控制条目再删除：新实例（核心、前置 DNS）先启动再切防火墙；删除后停止。"""
    node = "us31003"
    assert remote(f"uci -q get passwall2.{node}.type").strip() == "sing-box"
    before = {pid for pid, _ in procs()}
    # 与 LuCI 表单提交的选项一致（代理模式、远程 DNS 等取表单缺省值）。
    values = {"enabled": "1", "remarks": "pw2-test", "sources": [TEST_SOURCE], "mode": "1", "node": node,
              "tcp_redir_ports": "1:65535", "udp_redir_ports": "1:65535", "direct_dns_query_strategy": "UseIP",
              "remote_dns_protocol": "tcp", "remote_dns": "1.1.1.1", "remote_dns_detour": "remote",
              "remote_fakedns": "0", "remote_dns_query_strategy": "UseIPv4", "remote_rewrite_ttl": "30"}
    s.apply(lambda: ubus("add", {"config": "passwall2", "type": "acl_rule", "name": "pw2acltest", "values": values}))
    now = status()
    running = procs()
    new = [cmd for pid, cmd in running if pid not in before]
    assert any("acl/pw2acltest.json" in cmd for cmd in new), new
    assert any("dnsmasq_pw2acltest" in cmd for cmd in new), new
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"]), "默认实例被重启"
    assert TEST_SOURCE in now["main"]
    s.alive("新增独立实例后")
    s.apply(lambda: ubus("delete", {"config": "passwall2", "section": "pw2acltest"}))
    now = status()
    assert not any("pw2acltest" in cmd for _, cmd in procs()), "独立实例未停止"
    assert now["main"] == s.baseline["main"], "删除条目后防火墙规则与变更前不一致"
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"])
    s.alive("删除独立实例后")


def local_dns():
    """前置 DNS 记录的国内 DNS（servers-file 中节点域名的上游；家里节点都是 IP 时 servers-file 为空）。"""
    return remote("cat /tmp/etc/pass''wall2_tmp/dnsmasq_acl_default.local_dns", check=False).strip()


def scenario_direct_dns(s):
    """直连 DNS 改为 223.5.5.5 再恢复：前置 DNS 原地重读节点域名转发（SIGHUP，不重启），核心原生热更新，直连 DNS 放行规则替换。"""
    original = remote(f"uci -q get passwall2.{s.section}.direct_dns").strip()
    before_dns = local_dns()
    assert "223.5.5.5" not in before_dns
    joined = s.apply(lambda: set_option(s.section, "direct_dns", "223.5.5.5"))
    assert "原生热更新" in joined and "SIGHUP" in joined, joined
    now = status()
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"]), "核心或前置 DNS 被重启"
    assert "223.5.5.5" in now["main"], "直连 DNS 放行规则未更新"
    assert local_dns() == "223.5.5.5#53", "前置 DNS 的国内 DNS 记录未更新"
    fake = remote("nslookup www.google.com 127.0.0.1 | awk '/^Address/ {a=$2} END {print a}'").strip()
    assert fake.startswith("198.18."), fake
    s.alive("直连 DNS 变化后")
    s.apply(lambda: set_option(s.section, "direct_dns", original))
    now = status()
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"]), "核心或前置 DNS 被重启"
    assert now["main"] == s.baseline["main"], "恢复后防火墙规则与变更前不一致"
    assert local_dns() == before_dns
    s.alive("恢复直连 DNS 后")


def dhcp_cachesize(value):
    remote(f"uci set dhcp.@dnsmasq[0].cachesize='{value}'; uci commit dhcp; /etc/init.d/dnsmasq restart >/dev/null 2>&1; sleep 2; "
           "/etc/init.d/pass''wall2 reload >/dev/null 2>&1 &")


def scenario_dnsmasq_swap(s):
    """dnsmasq 主实例设置变化（外部输入，缓存条数）再恢复：前置 DNS 蓝绿替换到新端口，就绪后才切换 DNS 劫持规则。"""
    dhcp_hash = remote("sha256sum /etc/config/dhcp").split()[0]
    original = remote("uci -q get dhcp.@dnsmasq[0].cachesize").strip()
    assert original.isdigit()
    ports = stable()
    try:
        joined = s.apply(lambda: dhcp_cachesize(int(original) + 1))
        assert "蓝绿替换：dnsmasq_acl_default" in joined, joined
        now = status()
        moved = stable()
        assert now["core"] == s.baseline["core"], "核心被重启"
        assert now["dns"] != s.baseline["dns"], "前置 DNS 未替换"
        assert moved["acl_default:dnsmasq"] != ports["acl_default:dnsmasq"]
        assert f'"port": {moved["acl_default:dnsmasq"]}' in now["main"], "DNS 劫持未指向新端口"
        assert f'"port": {ports["acl_default:dnsmasq"]}' not in now["main"], "DNS 劫持仍指向旧端口"
        fake = remote("nslookup www.google.com 127.0.0.1 | awk '/^Address/ {a=$2} END {print a}'").strip()
        assert fake.startswith("198.18."), fake
        pid_file = remote("cat /tmp/etc/pass''wall2/acl/acl_default_dnsmasq.pid").strip()
        assert pid_file == now["dns"], (pid_file, now["dns"])
        s.alive("前置 DNS 蓝绿替换后")
        joined = s.apply(lambda: dhcp_cachesize(original))
        assert "蓝绿替换：dnsmasq_acl_default" in joined, joined
    finally:
        if remote("uci -q get dhcp.@dnsmasq[0].cachesize").strip() != original:
            remote(f"uci set dhcp.@dnsmasq[0].cachesize='{original}'; uci commit dhcp; /etc/init.d/dnsmasq restart", check=False)
    assert remote("sha256sum /etc/config/dhcp").split()[0] == dhcp_hash, "dhcp 配置未能逐字节恢复"
    now = status()
    back = stable()
    assert now["core"] == s.baseline["core"], "核心被重启"
    names = {ports["acl_default:dnsmasq"]: "DNSMASQ", back["acl_default:dnsmasq"]: "DNSMASQ"}
    assert normalized_main(now["main"], names) == normalized_main(s.baseline["main"], names), "恢复后防火墙规则与变更前不一致"
    s.alive("恢复 dnsmasq 主实例设置后")


def scenario_socks(s):
    """Socks 实例换到空闲端口再恢复：新端口实例启动（原端口与 frps 冲突），恢复后与变更前一样不运行。"""
    sid = "V4C5p00z"
    port = remote(f"uci -q get passwall2.{sid}.port").strip()
    s.apply(lambda: set_option(sid, "port", "10899"))
    assert remote("netstat -tln | grep -c ':10899 '", check=False).strip() != "0", "新端口未监听"
    now = status()
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"])
    s.alive("Socks 实例换端口后")
    s.apply(lambda: set_option(sid, "port", port))
    assert remote("netstat -tln | grep -c ':10899 '", check=False).strip() == "0", "旧端口实例未停止"
    s.alive("恢复 Socks 实例端口后")


def socks_probe(port):
    return remote(f"curl -sS -o /dev/null -w '%{{http_code}}' --max-time 20 --socks5-hostname 127.0.0.1:{port} https://www.google.com/generate_204",
                  check=False).strip()


def free_router_port(candidates=(1072, 1073, 1075, 11070, 21071)):
    busy = remote("netstat -tuln").split()
    for port in candidates:
        if not any(item.endswith(f":{port}") for item in busy):
            return port
    raise AssertionError("没有空闲的候选端口")


def scenario_socks_port(s):
    """全局 Socks 端口换到空闲端口再恢复：核心原生热更新监听器（进程不变），经旧监听器建立的 SOCKS 长连接保持。"""
    original = remote(f"uci -q get passwall2.{s.section}.node_socks_port").strip()
    assert original == "1070"
    port = free_router_port()
    joined = s.apply(lambda: set_option(s.section, "node_socks_port", str(port)))
    assert "acl_default（原生热更新）" in joined, joined
    now = status()
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"]), "核心或前置 DNS 被重启"
    assert socks_probe(port) == "204", "新 Socks 端口不可用"
    assert socks_probe(1070) != "204", "旧 Socks 端口仍在监听"
    request(s.socks)
    s.requests += 1
    transparent_request(s.requests)
    print(f"  换到 {port} 后：经旧监听器的 SOCKS 长连接与透明代理长连接可用，新端口可用，旧端口已关闭。")
    s.apply(lambda: set_option(s.section, "node_socks_port", original))
    now = status()
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"])
    assert now["main"] == s.baseline["main"]
    s.alive("恢复 Socks 端口后")


def scenario_proxy_way(s):
    """TCP 转发方式 重定向 → TPROXY 再恢复：防火墙规则与核心入站同时变化，核心原生热更新，已建立的连接保持。"""
    original = remote(f"uci -q get passwall2.{s.fwd}.tcp_proxy_way").strip()
    assert original == "redirect"
    joined = s.apply(lambda: set_option(s.fwd, "tcp_proxy_way", "tproxy"))
    assert "acl_default（原生热更新）" in joined, joined
    now = status()
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"]), "核心或前置 DNS 被重启"
    assert "PSW2_OUTPUT_NAT" not in now["main"] and "tproxy" in now["main"], "TPROXY 规则未生效"
    s.alive("改为 TPROXY 后")
    s.apply(lambda: set_option(s.fwd, "tcp_proxy_way", original))
    now = status()
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"])
    assert now["main"] == s.baseline["main"], "恢复后防火墙规则与变更前不一致"
    s.alive("恢复重定向后")


def scenario_client_proxy(s):
    """客户端代理关闭再打开：只替换防火墙规则。"""
    s.apply(lambda: set_option(s.section, "client_proxy", "0"))
    now = status()
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"])
    assert now["main"] != s.baseline["main"]
    s.alive("关闭客户端代理后")
    s.apply(lambda: set_option(s.section, "client_proxy", "1"))
    now = status()
    assert now["main"] == s.baseline["main"], "恢复后防火墙规则与变更前不一致"
    s.alive("恢复客户端代理后")


def scenario_white(s):
    """分流节点开启直连写集合再关闭：启动/停止直连写集合 DNS，核心原生热更新，集合与分流子链在事务中增删。"""
    assert remote("uci -q get passwall2.myshunt.write_ipset_direct").strip() == "0"
    joined = s.apply(lambda: set_option("myshunt", "write_ipset_direct", "1"))
    assert "acl_default（原生热更新）" in joined and "新启动" in joined, joined
    now = status()
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"]), "核心或前置 DNS 被重启"
    assert "psw2_myshunt_white" in json.dumps(now["sub"]), "直连写集合未进入分流子链"
    assert any("dns_acl_default_direct_myshunt.conf" in cmd for _, cmd in procs()), "直连写集合 DNS 未运行"
    s.alive("开启直连写集合后")
    s.apply(lambda: set_option("myshunt", "write_ipset_direct", "0"))
    now = status()
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"])
    assert now["main"] == s.baseline["main"] and now["sub"] == s.baseline["sub"], "恢复后防火墙规则与变更前不一致"
    assert not any("dns_acl_default_direct" in cmd for _, cmd in procs()), "直连写集合 DNS 未停止"
    assert remote("nft list sets inet passwall2 | grep -c myshunt_white", check=False).strip() == "0", "直连写集合未删除"
    s.alive("关闭直连写集合后")


def scenario_geoview(s):
    """分流节点关闭 GeoIP 预加载再打开：规则集合与分流子链在事务中删除与重建，核心不变。"""
    assert remote("uci -q get passwall2.myshunt.enable_geoview_ip").strip() == "1"
    s.apply(lambda: set_option("myshunt", "enable_geoview_ip", "0"))
    now = status()
    assert (now["core"], now["dns"]) == (s.baseline["core"], s.baseline["dns"])
    assert not any(now["sub"].values()), "分流子链仍有规则"
    assert remote("nft list sets inet passwall2 | grep -c psw2_myshunt_", check=False).strip() == "0", "规则集合未删除"
    s.alive("关闭 GeoIP 预加载后")
    s.apply(lambda: set_option("myshunt", "enable_geoview_ip", "1"))
    now = status()
    assert now["main"] == s.baseline["main"] and now["sub"] == s.baseline["sub"], "恢复后防火墙规则与变更前不一致"
    assert int(remote("nft list set inet passwall2 psw2_myshunt_China | grep -o ',' | wc -l").strip()) > 1000, "China 集合未重新载入"
    s.alive("恢复 GeoIP 预加载后")


def scenario_dns_redirect(s):
    """DNS 劫持改为“只拦截发往本机的查询”（接入 dnsmasq 主实例）再恢复：前置 DNS 实例停止/重启，主实例按新配置重启，核心不变。"""
    # 上游接入主实例时先删后加 dhcp 的 server 列表（备份上游），uci 写回后段内选项顺序会变：按 uci 语义比较。
    dhcp_hash = remote("uci -q show dhcp | sort | sha256sum").split()[0]
    remote(f"umask 077; cp -p /etc/config/dhcp {ROOT}/reconcile-baseline.dhcp")
    joined = s.apply(lambda: set_option(s.section, "dns_redirect", "0"))
    assert "dnsmasq 主实例已接入并按新配置重启" in joined, joined
    now = status()
    assert now["core"] == s.baseline["core"], "核心被重启"
    assert not now.get("dns"), "前置 DNS 实例仍在运行"
    fake = remote("nslookup www.google.com 127.0.0.1 | awk '/^Address/ {a=$2} END {print a}'").strip()
    assert fake.startswith("198.18."), fake
    s.alive("接入主实例后")
    joined = s.apply(lambda: set_option(s.section, "dns_redirect", "1"))
    assert "dnsmasq 主实例已按新配置重启" in joined, joined
    now = status()
    assert now["core"] == s.baseline["core"] and now.get("dns"), "核心被重启或前置 DNS 未启动"
    fake = remote("nslookup www.google.com 127.0.0.1 | awk '/^Address/ {a=$2} END {print a}'").strip()
    assert fake.startswith("198.18."), fake
    assert remote("uci -q show dhcp | sort | sha256sum").split()[0] == dhcp_hash, "dhcp 配置未能恢复"
    s.alive("恢复 DNS 劫持后")


def scenario_enable(s):
    """关闭再打开 passwall2：透明代理（核心、前置 DNS、防火墙规则）整体拆除，再整体拉起，全程没有完整重启；
    恢复后规则与变更前一致（稳定端口沿用）。关闭期间经核心的旧连接随之结束，属预期。"""
    s.apply(lambda: set_option(s.section, "enabled", "0"))
    now = status()
    assert not now.get("core") and not now.get("dns"), "关闭后核心或前置 DNS 仍在运行"
    assert not json.loads(now["main"]).get("PSW2_NAT") and not any(now["sub"].values()), "关闭后仍有透明代理规则"
    print("  关闭后：核心与前置 DNS 已停止，透明代理规则已清除。")
    s.apply(lambda: set_option(s.section, "enabled", "1"))
    now = status()
    assert now.get("core") and now.get("dns"), "重新打开后核心或前置 DNS 未运行"
    assert now["main"] == s.baseline["main"] and now["sub"] == s.baseline["sub"], "重新打开后规则与变更前不一致"
    s.baseline.update({"core": now["core"], "dns": now["dns"]})
    # 旧连接经已停止的核心，重新建立测试连接。
    s.close()
    s.__init__.__func__  # noqa: B018
    restarted = Session()
    s.__dict__.update(restarted.__dict__)
    print("  重新打开后：核心与前置 DNS 已启动，规则与变更前一致，新连接可用。")


SCENARIOS = {
    "localhost": scenario_localhost_proxy,
    "ports": scenario_ports,
    "acl": scenario_acl_follow,
    "instance": scenario_acl_instance,
    "dns": scenario_direct_dns,
    "swap": scenario_dnsmasq_swap,
    "socks": scenario_socks,
    "socksport": scenario_socks_port,
    "proxyway": scenario_proxy_way,
    "client": scenario_client_proxy,
    "white": scenario_white,
    "geoview": scenario_geoview,
    "dnsredirect": scenario_dns_redirect,
    "enable": scenario_enable,
}


def main():
    names = sys.argv[1:] or list(SCENARIOS)
    s = Session()
    try:
        for name in names:
            print(f"场景 {name}：{SCENARIOS[name].__doc__.strip()}")
            SCENARIOS[name](s)
            print(f"PASS：{name}")
    finally:
        s.close()
        if remote("sha256sum /etc/config/passwall2").split()[0] != s.config_hash:
            remote(f"cp -p {ROOT}/reconcile-baseline.config /etc/config/passwall2; /etc/init.d/passwall2 reload", check=False)
            raise AssertionError("passwall2 配置未能逐字节恢复，已从备份复原并触发 reload")
    print("PASS：passwall2 配置已逐字节恢复。")


if __name__ == "__main__":
    main()
