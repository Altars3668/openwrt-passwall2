#!/usr/bin/env python3
"""家里实测防火墙集合热刷新；只针对家里路由器。

1. 经 ubus 提交 flush_set=1（与规则更新、保存分流规则、手动清空集合相同的触发方式）：reload 原生完成，
   核心与 DNS 进程、主链、分流子链不变，flush_set 被消费，sing-box 规则集文件被原地重写，GeoIP 集合重新载入。
2. 给全局分流节点用到的一条规则追加测试网段：集合原子加入；恢复后原子移除。
旧的透明代理 TLS 长连接与 SOCKS 长连接全程可用；测试结束 passwall2 配置逐字节恢复。
"""

import json
import time

from home_global_switch_test import ROOT, log_lines, remote, status, transparent_request, ubus_commit
from home_memory_probe import connection, request

TEST_NET = "198.51.100.0/24"


def wait_refresh(before, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = log_lines()[len(before):]
        if any("防火墙集合热刷新" in line or "完整重启" in line or "失败" in line for line in lines):
            time.sleep(4)  # 暴露可能的重复触发
            return log_lines()[len(before):]
        time.sleep(1)
    raise AssertionError("集合热刷新未完成：" + "\n".join(log_lines()[len(before):]))


def check_hot(lines, baseline):
    joined = "\n".join(lines)
    assert "防火墙集合热刷新" in joined, joined
    assert "完整重启" not in joined and "失败" not in joined, joined
    assert len([line for line in lines if "防火墙集合热刷新" in line]) == 1, joined
    now = status()
    assert now["core"] == baseline["core"], "核心进程被重启"
    assert now["dns"] == baseline["dns"], "DNS 实例被重启"
    assert now["main"] == baseline["main"], "主链发生变化"
    assert now["sub"] == baseline["sub"], "分流子链发生变化"
    return joined


def srs_mtimes():
    out = remote("for f in /tmp/etc/passwall2_tmp/singbox_srss/*.srs; do echo \"$(date -r \"$f\" +%s) ${f##*/}\"; done")
    return {name: int(stamp) for stamp, name in (line.split(" ", 1) for line in out.splitlines())}


def set_text(name):
    return remote(f"nft list set inet passwall2 {name}")


def shunt_rule():
    """全局分流节点已指定目标、带 IP 列表的一条规则（与 gen_shunt_list 一致按分组过滤）。"""
    group = remote("uci -q get passwall2.myshunt.shunt_group", check=False).strip()
    for line in remote("uci -q show passwall2 | grep '=shunt_rules$'").splitlines():
        rule = line.split(".")[1].split("=")[0]
        if remote(f"uci -q get passwall2.{rule}.group", check=False).strip() != group:
            continue
        if remote(f"uci -q get passwall2.myshunt.{rule}", check=False).strip() and \
                remote(f"uci -q get passwall2.{rule}.ip_list", check=False).strip():
            return rule
    raise AssertionError("myshunt 没有带 IP 列表的规则")


def main():
    baseline = status()
    assert baseline["core"] and baseline["dns"] and any(baseline["sub"].values()), "家里全局分流节点未按新结构运行"
    assert remote("uci -q get passwall2.myshunt.enable_geoview_ip").strip() == "1"
    config_hash = remote("sha256sum /etc/config/passwall2").split()[0]
    remote(f"umask 077; cp -p /etc/config/passwall2 {ROOT}/refresh-baseline.config")
    section = remote("uci -q show passwall2.@global[0] | head -n 1 | cut -d. -f2 | cut -d= -f1").strip()
    assert section.isalnum(), section
    rule = shunt_rule()
    original_ips = remote(f"uci -q get passwall2.{rule}.ip_list").rstrip("\n")
    assert TEST_NET not in original_ips
    china_before = set_text("psw2_myshunt_China").count(",")
    mtimes = srs_mtimes()
    assert mtimes and china_before > 1000, (mtimes, china_before)

    remote("rm -f /tmp/pw2t.fifo /tmp/pw2t.out /tmp/pw2t.err; mkfifo /tmp/pw2t.fifo; "
           "(sleep 900 > /tmp/pw2t.fifo &); "
           "(openssl s_client -connect www.google.com:443 -servername www.google.com -quiet < /tmp/pw2t.fifo > /tmp/pw2t.out 2>/tmp/pw2t.err &)")
    socks = connection()
    try:
        time.sleep(3)
        transparent_request(1)
        print("PASS：刷新前透明代理 TLS 长连接与 SOCKS 长连接均可用。")

        before = log_lines()
        started = time.monotonic()
        ubus_commit(section, "flush_set", "1")
        joined = check_hot(wait_refresh(before), baseline)
        assert "sing-box 规则集已原地更新" in joined, joined
        assert remote("uci -q get passwall2.@global[0].flush_set", check=False).strip() == "", "flush_set 未被消费"
        refreshed = srs_mtimes()
        stale = [name for name in mtimes if refreshed.get(name, 0) <= mtimes[name]]
        assert not stale, f"规则集未重写：{stale}"
        china_after = set_text("psw2_myshunt_China").count(",")
        assert china_after > 1000, china_after
        transparent_request(2)
        request(socks)
        with connection() as fresh:
            request(fresh)
        print(f"PASS：flush_set 热刷新（{time.monotonic() - started:.0f} 秒）：核心/DNS/主链/子链不变，flush_set 已消费，"
              f"{len(refreshed)} 个规则集原地重写，China 集合重新载入（{china_before} → {china_after} 个分隔符），旧连接可用。")

        before = log_lines()
        payload = json.dumps({"config": "passwall2", "section": rule, "values": {"ip_list": original_ips + "\n" + TEST_NET}})
        remote(f"ubus call uci set '{payload}' && ubus call uci commit '{{\"config\":\"passwall2\"}}'")
        check_hot(wait_refresh(before), baseline)
        assert TEST_NET.split("/")[0] in set_text(f"psw2_myshunt_{rule}"), "测试网段未加入集合"
        transparent_request(3)
        request(socks)
        print(f"PASS：规则 {rule} 的 IP 列表变化热刷新，集合 psw2_myshunt_{rule} 原子加入测试网段，核心/DNS/主链/子链不变。")

        before = log_lines()
        payload = json.dumps({"config": "passwall2", "section": rule, "values": {"ip_list": original_ips}})
        remote(f"ubus call uci set '{payload}' && ubus call uci commit '{{\"config\":\"passwall2\"}}'")
        check_hot(wait_refresh(before), baseline)
        assert TEST_NET.split("/")[0] not in set_text(f"psw2_myshunt_{rule}"), "恢复后测试网段仍在集合中"
        transparent_request(4)
        request(socks)
        print("PASS：恢复规则后集合原子移除测试网段，旧连接持续可用。")
    finally:
        socks.close()
        # 路由器的 busybox 没有 pkill；字符类写法避免 pgrep -f 匹配到执行本命令的远端 shell 自身。
        remote("for p in $(busybox pgrep -f 'openssl s_clien[t] -connect www.google.com') $(busybox pgrep -f 'slee[p] 900'); do kill $p; done; "
               "rm -f /tmp/pw2t.fifo /tmp/pw2t.out /tmp/pw2t.err", check=False)
        if remote(f"uci -q get passwall2.{rule}.ip_list", check=False).rstrip("\n") != original_ips:
            payload = json.dumps({"config": "passwall2", "section": rule, "values": {"ip_list": original_ips}})
            remote(f"ubus call uci set '{payload}' && ubus call uci commit '{{\"config\":\"passwall2\"}}'", check=False)
    final_hash = remote("sha256sum /etc/config/passwall2").split()[0]
    assert final_hash == config_hash, "passwall2 配置未能逐字节恢复"
    print("PASS：passwall2 配置已逐字节恢复。")


if __name__ == "__main__":
    main()
