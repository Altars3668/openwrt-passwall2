#!/usr/bin/env python3
"""只在已授权的家里路由器测试实际配置重载；不连接办公室路由器。"""

import json
import os
import socket
import ssl
import struct
import subprocess
import time

SSH = ["ssh", "-4", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ControlPath=/tmp/passwall2-hot-reload/home-mux/control", "-p", os.environ.get("PW2_HOME_SSH_PORT", "22"), os.environ.get("PW2_HOME_SSH", "root@192.168.1.1")]


def remote(command, check=True):
    result = subprocess.run(SSH + [command], capture_output=True, text=True, timeout=80)
    if check and result.returncode:
        raise AssertionError(f"家里命令失败：{result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


def status():
    command = "lua -e 'local a=require \"luci.passwall2.api\"; local p={}; for n in a.fs.dir(\"/proc\") do if n:match(\"^%d+$\") then local c=a.fs.readfile(\"/proc/\"..n..\"/cmdline\") or \"\"; if c:find(\"run\",1,true) and c:find(\"-c\",1,true) and c:find(a.TMP_ACL_PATH..\"/acl_default.json\",1,true) then p[#p+1]=n end end end; print(a.jsonc.stringify({core=p,dns=a.fs.readfile(a.TMP_ACL_PATH..\"/acl_default_dnsmasq.pid\"),node=a.uci:get(\"passwall2\",\"myshunt\",\"Proxy\"),ttl=a.uci:get(\"passwall2\",\"@global[0]\",\"remote_rewrite_ttl\")}))'"
    result = json.loads(remote(command).stdout)
    nft = json.loads(remote("nft -s -j list table inet passwall2").stdout)
    result["config"] = [item for item in nft["nftables"] if "rule" in item or "chain" in item]
    return result


def receive(sock, count):
    out = b""
    while len(out) < count:
        part = sock.recv(count - len(out))
        if not part:
            raise EOFError("测试连接被关闭")
        out += part
    return out


def connection():
    # 只对建立连接重试，排除上游节点瞬时抖动；已建立连接在 reload 后的可用性不重试。
    for attempt in range(3):
        try:
            return open_connection()
        except (OSError, ssl.SSLError, EOFError, AssertionError):
            if attempt == 2:
                raise
            time.sleep(2)


def open_connection():
    sock = socket.create_connection(("127.0.0.1", 21070), timeout=15)
    sock.sendall(b"\x05\x01\x00")
    assert receive(sock, 2) == b"\x05\x00"
    domain = b"www.google.com"
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + struct.pack("!H", 443))
    header = receive(sock, 4)
    assert header[1] == 0
    receive(sock, {1: 4, 4: 16}.get(header[3], 0))
    if header[3] == 3:
        receive(sock, receive(sock, 1)[0])
    receive(sock, 2)
    return ssl.create_default_context().wrap_socket(sock, server_hostname="www.google.com")


def request(sock):
    sock.sendall(b"GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: keep-alive\r\n\r\n")
    data = b""
    while b"\r\n\r\n" not in data:
        part = sock.recv(4096)
        if not part:
            raise EOFError("已有 TLS 长连接被配置重载中断")
        data += part
    if not data.startswith(b"HTTP/1.1 204"):
        raise AssertionError(data[:100].decode(errors="replace"))


def reload():
    result = remote("/etc/init.d/passwall2 reload", check=False)
    return result.returncode


def assert_stable(before, after):
    assert before["core"] == after["core"], (before["core"], after["core"])
    assert before["dns"] == after["dns"], "DNS 实例被重启"
    assert before["config"] == after["config"], "防火墙链发生变化"


before = status()
assert before["core"], "家里全局核心未启动"
remote("umask 077; uci export passwall2 > /root/passwall2-hot-reload-test-20261003/test-baseline.uci")
old = connection()
try:
    request(old)
    # 远程 DNS 改写 TTL 只影响核心 DNS 规则，属于原生热更新范围。
    new_ttl = "31" if before.get("ttl") != "31" else "29"
    remote(f"uci set passwall2.@global[0].remote_rewrite_ttl='{new_ttl}'; uci commit passwall2")
    assert reload() == 0
    after = status()
    assert_stable(before, after)
    request(old)
    with connection() as new:
        request(new)
    print("PASS：远程 DNS TTL 配置原生热更新，旧 TLS 连接、新 HTTPS、核心与 DNS PID、防火墙链均保持。")
    original = before["node"]
    assert original and original.replace("_", "").isalnum()
    new_node = "us31003" if original != "us31003" else "SjyWplsT"
    remote(f"uci set passwall2.myshunt.Proxy='{new_node}'; uci commit passwall2")
    assert reload() == 0
    after_node = status()
    assert_stable(before, after_node)
    request(old)
    with connection() as new:
        request(new)
    print("PASS：家里分流代理节点原生切换，旧长连接和新连接均通过，核心／DNS／防火墙未重建。")
finally:
    old.close()
    restore = remote("uci import passwall2 < /root/passwall2-hot-reload-test-20261003/test-baseline.uci; uci commit passwall2", check=False)
    if restore.returncode or reload() != 0:
        raise AssertionError("测试配置恢复失败，保持自动回滚保护，不确认部署。")
final = status()
assert_stable(before, final)
assert final["node"] == before["node"]
print("PASS：测试配置已经原生恢复，用户原分流节点保留。")
