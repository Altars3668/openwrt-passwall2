#!/usr/bin/env python3
"""本机真实核心验收：旧连接不掉线，新连接切换，坏配置不影响当前实例。"""

import copy
import json
import os
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path


SING_BOX = os.environ.get("SING_BOX_BIN")
XRAY = os.environ.get("XRAY_BIN")


def receive(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError("连接提前关闭")
        data += part
    return data


def address(sock, kind):
    if kind == 1:
        return receive(sock, 4)
    if kind == 4:
        return receive(sock, 16)
    if kind == 3:
        return receive(sock, receive(sock, 1)[0])
    raise ValueError("无效 SOCKS 地址类型")


class Upstream(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UpstreamHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(10)
        greeting = receive(sock, 2)
        receive(sock, greeting[1])
        sock.sendall(b"\x05\x00")
        header = receive(sock, 4)
        address(sock, header[3])
        receive(sock, 2)
        sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01")
        stream = sock.makefile("rb")
        while line := stream.readline():
            sock.sendall(self.server.marker + b":" + line)
            if line == b"current\n":
                break


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def socks_connection(port, domain=None, destination_port=80, target_ip="127.0.0.1"):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.sendall(b"\x05\x01\x00")
    if receive(sock, 2) != b"\x05\x00":
        raise AssertionError("SOCKS 握手失败")
    target = b"\x01" + socket.inet_aton(target_ip) if domain is None else b"\x03" + bytes([len(domain)]) + domain.encode()
    sock.sendall(b"\x05\x01\x00" + target + struct.pack("!H", destination_port))
    header = receive(sock, 4)
    if header[1] != 0:
        raise AssertionError("SOCKS 连接失败")
    address(sock, header[3])
    receive(sock, 2)
    return sock


def write_geosite(directory, domain, code="PW2TEST"):
    """写一个只含一条 full 域名的 geosite 数据文件（GeoSiteList → GeoSite → Domain 的 protobuf 编码）。"""
    entry = b"\x08\x03" + b"\x12" + bytes([len(domain)]) + domain.encode()
    site = b"\x0a" + bytes([len(code)]) + code.encode() + b"\x12" + bytes([len(entry)]) + entry
    path = Path(directory) / "pw2test.dat"
    (Path(directory) / "pw2test.dat.tmp").write_bytes(b"\x0a" + bytes([len(site)]) + site)
    (Path(directory) / "pw2test.dat.tmp").replace(path)


def exchange(sock, payload):
    sock.sendall(payload + b"\n")
    data = b""
    while not data.endswith(b"\n"):
        part = sock.recv(1024)
        if not part:
            raise EOFError("长连接被重载关闭")
        data += part
    return data.rstrip(b"\n")


class CoreFixture:
    def __init__(self, kind, fakeip=False, env=None, geosite=None):
        self.kind = kind
        self.tmp = tempfile.TemporaryDirectory(prefix="passwall2-core-test-")
        self.path = Path(self.tmp.name)
        self.port, self.api_port = free_port(), free_port()
        self.upstreams = []
        for marker in (b"A", b"B"):
            server = Upstream(("127.0.0.1", 0), UpstreamHandler)
            server.marker = marker
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.upstreams.append(server)
        first = self.upstreams[0].server_address[1]
        if kind == "sing-box":
            self.binary = SING_BOX
            self.config = {
                "hot_reload": True,
                "log": {"disabled": True},
                "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": self.port}],
                "outbounds": [{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": first}],
                "route": {"final": "proxy"},
                "experimental": {"clash_api": {"external_controller": f"127.0.0.1:{self.api_port}", "secret": "local-test-only"}},
            }
        else:
            self.binary = XRAY
            self.config = {
                "log": {"loglevel": "none"},
                "api": {"tag": "control", "listen": f"127.0.0.1:{self.api_port}", "services": ["HandlerService"]},
                "inbounds": [{"protocol": "socks", "tag": "in", "listen": "127.0.0.1", "port": self.port, "settings": {"auth": "noauth", "udp": True}}],
                "outbounds": [{"protocol": "socks", "tag": "proxy", "settings": {"servers": [{"address": "127.0.0.1", "port": first}]}}],
                "routing": {"rules": [{"network": "tcp,udp", "outboundTag": "proxy"}]},
            }
        if env:
            self.config["env"] = dict(env)
        if geosite and kind == "xray":
            # 与 Passwall2 一致经 env 指定规则数据目录；geosite 中的域名走 A，其余走 B。
            second = self.upstreams[1].server_address[1]
            self.config["env"] = {"XRAY_LOCATION_ASSET": str(geosite)}
            self.config["outbounds"].append({"protocol": "socks", "tag": "other", "settings": {"servers": [{"address": "127.0.0.1", "port": second}]}})
            self.config["routing"]["rules"] = [
                {"domain": ["ext:pw2test.dat:PW2TEST"], "outboundTag": "proxy"},
                {"network": "tcp,udp", "outboundTag": "other"},
            ]
        if fakeip and kind == "xray":
            # Xray 的 FakeDNS：DNS 经 dns 出站应答假地址，SOCKS 入站按 fakedns 嗅探还原域名再按域名路由。
            self.dns_port = free_port()
            self.config["fakedns"] = [{"ipPool": "198.18.0.0/16", "poolSize": 65535}]
            self.config["dns"] = {"servers": ["fakedns"]}
            self.config["inbounds"][0]["sniffing"] = {"enabled": True, "destOverride": ["fakedns"], "metadataOnly": True}
            self.config["inbounds"].append({"protocol": "dokodemo-door", "tag": "dns-in", "listen": "127.0.0.1", "port": self.dns_port,
                                            "settings": {"address": "1.1.1.1", "port": 53, "network": "udp"}})
            self.config["outbounds"] += [{"protocol": "dns", "tag": "dns-out"}, {"protocol": "blackhole", "tag": "block"}]
            self.config["routing"]["rules"] = [
                {"inboundTag": ["dns-in"], "outboundTag": "dns-out"},
                {"domain": ["domain:reload.test"], "outboundTag": "proxy"},
                {"network": "tcp,udp", "outboundTag": "block"},
            ]
        elif fakeip:
            self.dns_port = free_port()
            self.config["dns"] = {
                "servers": [
                    {"type": "hosts", "tag": "local", "predefined": {"bootstrap.test": ["127.0.0.1"]}},
                    {"type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/16", "inet6_range": "fc00::/18"},
                ],
                "rules": [{"query_type": ["A", "AAAA"], "action": "route", "server": "fake"}],
                "final": "local",
            }
            self.config["inbounds"].append({"type": "direct", "tag": "dns-test", "listen": "127.0.0.1", "listen_port": self.dns_port})
            self.config["route"]["rules"] = [{"inbound": "dns-test", "action": "hijack-dns"}]
            self.config["experimental"]["cache_file"] = {"enabled": True, "store_fakeip": True, "path": str(self.path / "fakeip.db")}
        self.log = open(self.path / "core.log", "wb")
        self.write("initial.json", self.config)
        self.process = subprocess.Popen([self.binary, "run", "-c", str(self.path / "initial.json")], stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError((self.path / "core.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", self.api_port), timeout=.2):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise AssertionError("核心控制接口启动超时")
        self.original_pid = self.process.pid

    def write(self, name, value):
        path = self.path / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def switch_config(self):
        result = copy.deepcopy(self.config)
        second = self.upstreams[1].server_address[1]
        if self.kind == "sing-box":
            result["outbounds"][0]["server_port"] = second
        else:
            result["outbounds"][0]["settings"]["servers"][0]["port"] = second
        return result

    def reload(self, config=None):
        if self.kind == "sing-box":
            request = urllib.request.Request(
                f"http://127.0.0.1:{self.api_port}/configs/hot-reload",
                data=None if config is None else json.dumps(config).encode(),
                method="GET" if config is None else "PUT",
                headers={"Authorization": "Bearer local-test-only", "Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    return response.status, json.load(response)
            except urllib.error.HTTPError as error:
                return error.code, json.load(error)
        args = [self.binary, "api", "reloadconfig", f"--server=127.0.0.1:{self.api_port}", "--timeout=10"]
        if config is None:
            args.append("--check")
        else:
            args.append(str(self.write("next.json", config)))
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
        return result.returncode, result.stdout + result.stderr

    def reload_geodata(self, config=None):
        args = [self.binary, "api", "reloadconfig", f"--server=127.0.0.1:{self.api_port}", "--timeout=10", "--geodata"]
        if config is not None:
            args.append(str(self.write("next.json", config)))
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
        return result.returncode, result.stdout + result.stderr

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        for server in self.upstreams:
            server.shutdown()
            server.server_close()
        self.log.close()
        output = (self.path / "core.log").read_text(errors="replace")
        self.tmp.cleanup()
        if "WARNING: DATA RACE" in output:
            raise AssertionError(output)
        if self.process.returncode == 66:
            raise AssertionError("竞态检测核心以退出码 66 结束")


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        stream = self.request.makefile("rb")
        while line := stream.readline():
            self.request.sendall(self.server.marker + b":" + line)


def fake_dns_query(port, domain):
    labels = b"".join(bytes([len(part)]) + part.encode() for part in domain.split(".")) + b"\x00"
    message = struct.pack("!HHHHHH", 1234, 0x100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(message, ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
    if struct.unpack_from("!H", data, 6)[0] != 1:
        raise AssertionError("FakeIP DNS 应答异常")
    return socket.inet_ntoa(data[-4:])


class CoreReloadTest(unittest.TestCase):
    @unittest.skipUnless(SING_BOX, "需要 SING_BOX_BIN")
    def test_singbox_fakeip_mapping_survives_reload(self):
        fixture = CoreFixture("sing-box", fakeip=True)
        self.addCleanup(fixture.close)
        first = fake_dns_query(fixture.dns_port, "first.reload.test")
        second = fake_dns_query(fixture.dns_port, "second.reload.test")
        self.assertNotEqual(first, second)
        old = socks_connection(fixture.port, target_ip=first)
        self.addCleanup(old.close)
        self.assertEqual(exchange(old, b"old-fake"), b"A:old-fake")
        for index in range(6):
            config = fixture.switch_config() if index % 2 == 0 else fixture.config
            status, result = fixture.reload(config)
            self.assertEqual(status, 200, result)
            self.assertEqual(fake_dns_query(fixture.dns_port, "first.reload.test"), first)
            third = fake_dns_query(fixture.dns_port, f"next-{index}.reload.test")
            self.assertNotIn(third, (first, second))
            self.assertEqual(exchange(old, b"retained-fake"), b"A:retained-fake")
            with socks_connection(fixture.port, target_ip=first) as new:
                expected = b"B" if index % 2 == 0 else b"A"
                self.assertEqual(exchange(new, b"current"), expected + b":current")
            time.sleep(.05)
        bad = fixture.switch_config()
        bad["dns"]["servers"][1]["inet4_range"] = "198.19.0.0/16"
        status, _ = fixture.reload(bad)
        self.assertEqual(status, 409)
        self.assertEqual(fake_dns_query(fixture.dns_port, "first.reload.test"), first)

    @unittest.skipUnless(XRAY, "需要 XRAY_BIN")
    def test_xray_fakedns_mapping_survives_reload(self):
        fixture = CoreFixture("xray", fakeip=True)
        self.addCleanup(fixture.close)
        first = fake_dns_query(fixture.dns_port, "first.reload.test")
        second = fake_dns_query(fixture.dns_port, "second.reload.test")
        self.assertNotEqual(first, second)
        old = socks_connection(fixture.port, target_ip=first)
        self.addCleanup(old.close)
        self.assertEqual(exchange(old, b"old-fake"), b"A:old-fake")
        for index in range(6):
            config = fixture.switch_config() if index % 2 == 0 else fixture.config
            status, result = fixture.reload(config)
            self.assertEqual(status, 0, result)
            # Xray 按时间戳分配假地址，新地址池不会恰好复现旧映射；顺序反查以排除巧合。
            self.assertEqual(fake_dns_query(fixture.dns_port, "second.reload.test"), second)
            self.assertEqual(fake_dns_query(fixture.dns_port, "first.reload.test"), first)
            third = fake_dns_query(fixture.dns_port, f"next-{index}.reload.test")
            self.assertNotIn(third, (first, second))
            self.assertEqual(exchange(old, b"retained-fake"), b"A:retained-fake")
            with socks_connection(fixture.port, target_ip=first) as new:
                expected = b"B" if index % 2 == 0 else b"A"
                self.assertEqual(exchange(new, b"current"), expected + b":current")
            time.sleep(.05)
        bad = fixture.switch_config()
        bad["fakedns"][0]["ipPool"] = "198.19.0.0/16"
        status, _ = fixture.reload(bad)
        self.assertEqual(status, 2)
        self.assertEqual(fake_dns_query(fixture.dns_port, "first.reload.test"), first)

    @unittest.skipUnless(XRAY, "需要 XRAY_BIN")
    def test_xray_env_unchanged_allows_reload(self):
        # Passwall2 的 Xray 配置总带 env（XRAY_LOCATION_ASSET）：与进程环境一致时必须允许热重载，变化时要求重启。
        fixture = CoreFixture("xray", env={"PW2_RELOAD_TEST": "one"})
        self.addCleanup(fixture.close)
        old = socks_connection(fixture.port)
        self.addCleanup(old.close)
        self.assertEqual(exchange(old, b"before"), b"A:before")
        status, result = fixture.reload(fixture.switch_config())
        self.assertEqual(status, 0, result)
        with socks_connection(fixture.port) as new:
            self.assertEqual(exchange(new, b"new"), b"B:new")
        self.assertEqual(exchange(old, b"after"), b"A:after")
        changed = fixture.switch_config()
        changed["env"] = {"PW2_RELOAD_TEST": "two"}
        status, result = fixture.reload(changed)
        self.assertEqual(status, 2, result)
        self.assertIn("env PW2_RELOAD_TEST changed", result)

    @unittest.skipUnless(XRAY, "需要 XRAY_BIN")
    def test_xray_geodata_reload_updates_geosite_rules(self):
        # 规则数据更新后：只重载配置会沿用按“文件:代码”缓存的旧匹配器；--geodata 原地重建，PID 与旧连接不变。
        assets = tempfile.TemporaryDirectory(prefix="passwall2-geo-test-")
        self.addCleanup(assets.cleanup)
        write_geosite(assets.name, "old.reload.test")
        fixture = CoreFixture("xray", geosite=assets.name)
        self.addCleanup(fixture.close)

        def route(domain):
            with socks_connection(fixture.port, domain=domain) as sock:
                return exchange(sock, b"current")[:1]

        self.assertEqual(route("old.reload.test"), b"A")
        self.assertEqual(route("new.reload.test"), b"B")
        old = socks_connection(fixture.port, domain="old.reload.test")
        self.addCleanup(old.close)
        self.assertEqual(exchange(old, b"before"), b"A:before")
        write_geosite(assets.name, "new.reload.test")
        status, result = fixture.reload(fixture.config)
        self.assertEqual(status, 0, result)
        self.assertEqual(route("new.reload.test"), b"B", "配置重载不会读取新的规则数据")
        status, result = fixture.reload_geodata()
        self.assertEqual(status, 0, result)
        self.assertIn('"geodata":true', result)
        self.assertEqual(route("new.reload.test"), b"A")
        self.assertEqual(route("old.reload.test"), b"B")
        self.assertEqual(exchange(old, b"after"), b"A:after")
        self.assertIsNone(fixture.process.poll())
        self.assertEqual(fixture.process.pid, fixture.original_pid)
        status, result = fixture.reload_geodata(fixture.config)
        self.assertEqual(status, 0, result)
        self.assertIn('"applied":true', result)
        (Path(assets.name) / "pw2test.dat").write_bytes(b"\x0a\xff\xff")
        status, result = fixture.reload_geodata()
        self.assertEqual(status, 1, result)
        self.assertEqual(route("new.reload.test"), b"A", "规则数据损坏时保持原数据")

    @unittest.skipUnless(SING_BOX, "需要 SING_BOX_BIN")
    def test_singbox_unused_fakeip_keeps_cached_addresses(self):
        # 对应全局节点从使用 FakeDNS 的分流节点切到普通节点：FakeIP 服务保留但不再被规则引用。
        fixture = CoreFixture("sing-box", fakeip=True)
        self.addCleanup(fixture.close)
        echo_port = free_port()
        server = Upstream(("127.0.0.2", echo_port), EchoHandler)
        server.marker = b"REAL"
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        mapped = fake_dns_query(fixture.dns_port, "keep.reload.test")
        plain = copy.deepcopy(fixture.config)
        plain["dns"]["servers"][0]["predefined"].update({"keep.reload.test": ["127.0.0.2"], "real.reload.test": ["127.0.0.3"]})
        plain["dns"]["rules"] = []
        plain["outbounds"] = [{"type": "direct", "tag": "proxy", "domain_resolver": "local"}]
        status, result = fixture.reload(plain)
        self.assertEqual(status, 200, result)
        self.assertEqual(fake_dns_query(fixture.dns_port, "real.reload.test"), "127.0.0.3")
        with socks_connection(fixture.port, target_ip=mapped, destination_port=echo_port) as connection:
            self.assertEqual(exchange(connection, b"restored"), b"REAL:restored")
        status, result = fixture.reload(fixture.config)
        self.assertEqual(status, 200, result)
        self.assertEqual(fake_dns_query(fixture.dns_port, "keep.reload.test"), mapped)

    def repeated_kind(self, kind):
        fixture = CoreFixture(kind)
        self.addCleanup(fixture.close)
        ok = 200 if kind == "sing-box" else 0
        status, result = fixture.reload(fixture.switch_config())
        self.assertEqual(status, ok, result)
        old = socks_connection(fixture.port)
        self.addCleanup(old.close)
        self.assertEqual(exchange(old, b"stage-one"), b"B:stage-one")
        for index in range(20):
            target = fixture.config if index % 2 == 0 else fixture.switch_config()
            status, result = fixture.reload(target)
            self.assertEqual(status, ok, result)
            self.assertEqual(exchange(old, b"retained"), b"B:retained")
            with socks_connection(fixture.port) as new:
                expected = b"A" if index % 2 == 0 else b"B"
                self.assertEqual(exchange(new, b"current"), expected + b":current")
            time.sleep(.05)
        self.assertIsNone(fixture.process.poll())

    def dangling_kind(self, kind):
        fixture = CoreFixture(kind)
        self.addCleanup(fixture.close)
        bad = fixture.switch_config()
        if kind == "sing-box":
            bad["route"]["final"] = "missing-outbound"
        else:
            bad["routing"]["rules"][0]["outboundTag"] = "missing-outbound"
        status, result = fixture.reload(bad)
        self.assertNotEqual(status, 200 if kind == "sing-box" else 0, result)
        with socks_connection(fixture.port) as connection:
            self.assertEqual(exchange(connection, b"unchanged"), b"A:unchanged")

    def dns_kind(self, kind):
        fixture = CoreFixture(kind)
        self.addCleanup(fixture.close)
        echo_port = free_port()
        for ip, marker in (("127.0.0.1", b"DNS-A"), ("127.0.0.2", b"DNS-B")):
            server = Upstream((ip, echo_port), EchoHandler)
            server.marker = marker
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
        config = copy.deepcopy(fixture.config)
        if kind == "sing-box":
            config["dns"] = {"servers": [{"type": "hosts", "tag": "local", "predefined": {"reload.test": ["127.0.0.1"]}}], "final": "local"}
            config["outbounds"] = [{"type": "direct", "tag": "proxy", "domain_resolver": "local"}]
        else:
            config["dns"] = {"hosts": {"reload.test": "127.0.0.1"}, "servers": ["localhost"]}
            config["outbounds"] = [{"protocol": "freedom", "tag": "proxy", "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}}]
        ok = 200 if kind == "sing-box" else 0
        status, result = fixture.reload(config)
        self.assertEqual(status, ok, result)
        old = socks_connection(fixture.port, "reload.test", echo_port)
        self.addCleanup(old.close)
        self.assertEqual(exchange(old, b"initial-dns"), b"DNS-A:initial-dns")
        new_config = copy.deepcopy(config)
        if kind == "sing-box":
            new_config["dns"]["servers"][0]["predefined"]["reload.test"] = ["127.0.0.2"]
        else:
            new_config["dns"]["hosts"]["reload.test"] = "127.0.0.2"
        status, result = fixture.reload(new_config)
        self.assertEqual(status, ok, result)
        self.assertEqual(exchange(old, b"old-dns"), b"DNS-A:old-dns")
        with socks_connection(fixture.port, "reload.test", echo_port) as new:
            self.assertEqual(exchange(new, b"new-dns"), b"DNS-B:new-dns")

    @unittest.skipUnless(SING_BOX, "需要 SING_BOX_BIN")
    def test_singbox_repeated_switch_and_drain(self):
        self.repeated_kind("sing-box")

    @unittest.skipUnless(XRAY, "需要 XRAY_BIN")
    def test_xray_repeated_switch_and_drain(self):
        self.repeated_kind("xray")

    @unittest.skipUnless(SING_BOX, "需要 SING_BOX_BIN")
    def test_singbox_dangling_route_rejected(self):
        self.dangling_kind("sing-box")

    @unittest.skipUnless(XRAY, "需要 XRAY_BIN")
    def test_xray_dangling_route_rejected(self):
        self.dangling_kind("xray")

    @unittest.skipUnless(SING_BOX, "需要 SING_BOX_BIN")
    def test_singbox_dns_replacement(self):
        self.dns_kind("sing-box")

    @unittest.skipUnless(XRAY, "需要 XRAY_BIN")
    def test_xray_dns_replacement(self):
        self.dns_kind("xray")

    def run_kind(self, kind):
        fixture = CoreFixture(kind)
        self.addCleanup(fixture.close)
        ok = 200 if kind == "sing-box" else 0
        status, result = fixture.reload()
        self.assertEqual(status, ok, result)
        old = socks_connection(fixture.port)
        self.addCleanup(old.close)
        self.assertEqual(exchange(old, b"before"), b"A:before")
        status, result = fixture.reload(fixture.switch_config())
        self.assertEqual(status, ok, result)
        self.assertIsNone(fixture.process.poll())
        self.assertEqual(fixture.process.pid, fixture.original_pid)
        self.assertEqual(exchange(old, b"after"), b"A:after")
        with socks_connection(fixture.port) as new:
            self.assertEqual(exchange(new, b"new"), b"B:new")
        bad = fixture.switch_config()
        bad["outbounds"][0]["type" if kind == "sing-box" else "protocol"] = "nonexistent-protocol"
        status, _ = fixture.reload(bad)
        self.assertNotEqual(status, ok)
        self.assertEqual(exchange(old, b"invalid"), b"A:invalid")
        with socks_connection(fixture.port) as new:
            self.assertEqual(exchange(new, b"still-new"), b"B:still-new")
        # 静态部分（这里是日志）变化仍需要重启核心，原实例与旧连接不受影响。
        static = fixture.switch_config()
        if kind == "sing-box":
            static["log"] = {"level": "error"}
        else:
            static["log"] = {"loglevel": "error"}
        status, result = fixture.reload(static)
        self.assertEqual(status, 409 if kind == "sing-box" else 2, result)
        self.assertEqual(exchange(old, b"structural"), b"A:structural")
        self.assertIsNone(fixture.process.poll())

    def listener_kind(self, kind):
        """入站（监听器）变化原生热重载：换端口、新增与删除入站；冲突时整体回滚；经旧监听器建立的连接不受影响。"""
        fixture = CoreFixture(kind)
        self.addCleanup(fixture.close)
        ok = 200 if kind == "sing-box" else 0
        key = "listen_port" if kind == "sing-box" else "port"
        old = socks_connection(fixture.port)
        self.addCleanup(old.close)
        self.assertEqual(exchange(old, b"before"), b"A:before")
        moved, extra = free_port(), free_port()
        config = fixture.switch_config()
        config["inbounds"][0][key] = moved
        added = copy.deepcopy(config["inbounds"][0])
        added["tag"], added[key] = "extra", extra
        config["inbounds"].append(added)
        status, result = fixture.reload(config)
        self.assertEqual(status, ok, result)
        self.assertEqual(fixture.process.pid, fixture.original_pid)
        self.assertEqual(exchange(old, b"after"), b"A:after")
        for port in (moved, extra):
            with socks_connection(port) as new:
                self.assertEqual(exchange(new, b"new"), b"B:new")
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", fixture.port), timeout=1).close()
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        self.addCleanup(blocker.close)
        busy = copy.deepcopy(fixture.config)
        busy["inbounds"] = copy.deepcopy(config["inbounds"])
        busy["inbounds"][1][key] = blocker.getsockname()[1]
        status, result = fixture.reload(busy)
        self.assertNotEqual(status, ok, result)
        with socks_connection(extra) as kept:
            self.assertEqual(exchange(kept, b"kept"), b"B:kept")
        with socks_connection(moved) as kept:
            self.assertEqual(exchange(kept, b"kept"), b"B:kept")
        # 换 tag 沿用端口（重定向改 TPROXY 时的情形）：旧入站先关闭，新入站才能绑定同一端口。
        renamed = copy.deepcopy(config)
        renamed["inbounds"][1]["tag"] = "extra-renamed"
        status, result = fixture.reload(renamed)
        self.assertEqual(status, ok, result)
        with socks_connection(extra) as conn:
            self.assertEqual(exchange(conn, b"renamed"), b"B:renamed")
        removed = copy.deepcopy(config)
        del removed["inbounds"][1]
        status, result = fixture.reload(removed)
        self.assertEqual(status, ok, result)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", extra), timeout=1).close()
        with socks_connection(moved) as new:
            self.assertEqual(exchange(new, b"final"), b"B:final")
        self.assertEqual(exchange(old, b"end"), b"A:end")
        self.assertIsNone(fixture.process.poll())

    @unittest.skipUnless(SING_BOX, "需要 SING_BOX_BIN")
    def test_singbox_listener_changes(self):
        self.listener_kind("sing-box")

    @unittest.skipUnless(XRAY, "需要 XRAY_BIN")
    def test_xray_listener_changes(self):
        self.listener_kind("xray")

    @unittest.skipUnless(SING_BOX, "需要 SING_BOX_BIN")
    def test_singbox_connections_and_rollback(self):
        self.run_kind("sing-box")

    @unittest.skipUnless(XRAY, "需要 XRAY_BIN")
    def test_xray_connections_and_rollback(self):
        self.run_kind("xray")


if __name__ == "__main__":
    unittest.main(verbosity=2)
