#!/usr/bin/env python3
"""在家里起隔离 Xray 实例验收，不重启正在提供服务的 sing-box。"""

import json
import os
import socket
import struct
import subprocess
import time

SSH = ["ssh", "-4", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ControlPath=/tmp/passwall2-hot-reload/home-mux/control", "-p", os.environ.get("PW2_HOME_SSH_PORT", "22"), os.environ.get("PW2_HOME_SSH", "root@192.168.1.1")]
ROOT = "/root/passwall2-hot-reload-test-20261003/xray-isolated"


def run(command, data=None):
    result = subprocess.run(SSH + [command], input=data, text=True, capture_output=True, timeout=45)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout


def receive(sock, count):
    value = b""
    while len(value) < count:
        data = sock.recv(count - len(value))
        if not data:
            raise EOFError("隔离 Xray 长连接意外断开")
        value += data
    return value


def connect():
    sock = socket.create_connection(("127.0.0.1", 21970), timeout=10)
    sock.sendall(b"\x05\x01\x00")
    assert receive(sock, 2) == b"\x05\x00"
    sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", 80))
    header = receive(sock, 4)
    assert header[1] == 0
    receive(sock, 4 if header[3] == 1 else 16)
    receive(sock, 2)
    return sock


def exchange(sock, expected):
    sock.sendall(b"check\n")
    data = b""
    while not data.endswith(b"\n"):
        data += receive(sock, 1)
    assert data == expected + b"\n", data


config = {
    "log": {"loglevel": "warning"},
    "api": {"tag": "control", "listen": "127.0.0.1:21972", "services": ["HandlerService"]},
    "inbounds": [{"tag": "in", "protocol": "socks", "listen": "127.0.0.1", "port": 21971, "settings": {"auth": "noauth"}}],
    "outbounds": [{"tag": "out", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:21981"}}],
    "routing": {"rules": [{"network": "tcp,udp", "outboundTag": "out"}]},
}
run(f"umask 077; mkdir -p {ROOT}; netstat -tln | grep -E ':(21971|21972|21981|21982) ' && exit 1 || true")
for marker, port in (("A", 21981), ("B", 21982)):
    script = "#!/bin/sh\nwhile IFS= read -r line; do printf '%s\\n' '" + marker + "'; done\n"
    run(f"umask 077; cat > {ROOT}/echo-{marker}.sh; chmod 700 {ROOT}/echo-{marker}.sh", script)
    run(f"nohup socat TCP-LISTEN:{port},bind=127.0.0.1,reuseaddr,fork EXEC:{ROOT}/echo-{marker}.sh > {ROOT}/echo-{marker}.log 2>&1 </dev/null & echo $! > {ROOT}/echo-{marker}.pid")
run(f"umask 077; cat > {ROOT}/initial.json", json.dumps(config))
run(f"nohup /usr/bin/xray run -c {ROOT}/initial.json > {ROOT}/core.log 2>&1 </dev/null & echo $! > {ROOT}/core.pid")
forwarded = False
old = None
try:
    for _ in range(30):
        result = subprocess.run(SSH + ["/usr/bin/xray api reloadconfig --server=127.0.0.1:21972 --check"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            break
        time.sleep(.1)
    else:
        raise AssertionError("家里隔离 Xray 控制接口未就绪")
    subprocess.run(SSH[:-1] + ["-O", "forward", "-L", "127.0.0.1:21970:127.0.0.1:21971", SSH[-1]], check=True)
    forwarded = True
    old = connect()
    exchange(old, b"A")
    config["outbounds"][0]["settings"]["redirect"] = "127.0.0.1:21982"
    run(f"umask 077; cat > {ROOT}/next.json", json.dumps(config))
    run(f"/usr/bin/xray api reloadconfig --server=127.0.0.1:21972 {ROOT}/next.json")
    exchange(old, b"A")
    with connect() as new:
        exchange(new, b"B")
    print("PASS：家里静态 Xray 原生重载，旧连接仍到 A，新连接到 B；生产 sing-box 未重启。")
finally:
    if old:
        old.close()
    run(f"for f in {ROOT}/core.pid {ROOT}/echo-A.pid {ROOT}/echo-B.pid; do [ -f \"$f\" ] && kill \"$(cat \"$f\")\" 2>/dev/null || true; done")
    if forwarded:
        subprocess.run(SSH[:-1] + ["-O", "cancel", "-L", "127.0.0.1:21970:127.0.0.1:21971", SSH[-1]], check=True)
