#!/usr/bin/env python3
"""测量家里生产 sing-box 每保留一代运行实例的内存成本；结束后恢复原配置。"""

import json
import os
import socket
import ssl
import struct
import subprocess
import time

SSH = ["ssh", "-4", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o",
       "ControlPath=/tmp/passwall2-hot-reload/home-mux/control", "-p", os.environ.get("PW2_HOME_SSH_PORT", "22"), os.environ.get("PW2_HOME_SSH", "root@192.168.1.1")]
ROOT = "/root/passwall2-hot-reload-test-20261003"
GENERATIONS = 4


def remote(command, check=True):
    result = subprocess.run(SSH + [command], capture_output=True, text=True, timeout=90)
    if check and result.returncode:
        raise AssertionError(f"家里命令失败：{result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def memory():
    # 从命令行开头精确匹配，避免把执行本命令的远端 shell 误当作核心进程。
    out = remote("for d in /proc/[0-9]*; do c=$(tr '\\0' ' ' < $d/cmdline 2>/dev/null); "
                 "case \"$c\" in '/tmp/etc/passwall2/bin/sing-box run -c /tmp/etc/passwall2/acl/acl_default.json '*) "
                 "grep -E '^(VmRSS|VmHWM)' $d/status; echo pid=${d#/proc/};; esac; done; grep MemAvailable /proc/meminfo")
    values = {}
    for line in out.splitlines():
        if line.startswith("pid="):
            values["pid"] = line[4:]
        elif ":" in line:
            key, value = line.split(":", 1)
            values[key] = int(value.split()[0])
    return values


def receive(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError("连接被关闭")
        data += part
    return data


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
    sock = socket.create_connection(("127.0.0.1", 21070), timeout=20)
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
    tls = ssl.create_default_context().wrap_socket(sock, server_hostname="www.google.com")
    request(tls)
    return tls


def request(sock):
    sock.sendall(b"GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: keep-alive\r\n\r\n")
    data = b""
    while b"\r\n\r\n" not in data:
        part = sock.recv(4096)
        if not part:
            raise EOFError("旧连接被中断")
        data += part
    assert data.startswith(b"HTTP/1.1 204"), data[:80]


def toggle(value):
    remote(f"uci set passwall2.@global[0].remote_rewrite_ttl='{value}'; uci commit passwall2")
    status = subprocess.run(SSH + ["/etc/init.d/passwall2 reload"], capture_output=True, text=True, timeout=90)
    assert status.returncode == 0, status.stdout + status.stderr


def main():
    baseline_value = remote("uci -q get passwall2.@global[0].remote_rewrite_ttl || echo 30").strip()
    remote(f"umask 077; uci export passwall2 > {ROOT}/memory-baseline.uci")
    held = []
    samples = [("baseline", memory())]
    pid = samples[0][1]["pid"]
    try:
        value = baseline_value
        for index in range(GENERATIONS):
            held.append(connection())
            value = "31" if value != "31" else "29"
            toggle(value)
            time.sleep(3)
            sample = memory()
            assert sample["pid"] == pid, "核心进程被重启"
            samples.append((f"retained {index + 1}", sample))
        for sock in held:
            request(sock)
    finally:
        for sock in held:
            sock.close()
        # 只按导出内容恢复，不额外写入缺省值，避免给用户配置增加原本没有的选项。
        remote(f"uci import passwall2 < {ROOT}/memory-baseline.uci; uci commit passwall2")
        status = subprocess.run(SSH + ["/etc/init.d/passwall2 reload"], capture_output=True, text=True, timeout=90)
        assert status.returncode == 0, status.stdout + status.stderr
    for wait in (10, 30):
        time.sleep(wait)
        samples.append((f"released +{wait}s", memory()))
    for name, sample in samples:
        print(f"{name:>16}: RSS={sample['VmRSS'] / 1024:6.1f} MiB  HWM={sample['VmHWM'] / 1024:6.1f} MiB  "
              f"MemAvailable={sample['MemAvailable'] / 1024:6.1f} MiB")
    growth = (samples[GENERATIONS][1]["VmRSS"] - samples[0][1]["VmRSS"]) / GENERATIONS / 1024
    print(f"每保留一代平均增加约 {growth:.1f} MiB RSS；核心 PID 未变：{pid}")


if __name__ == "__main__":
    main()
