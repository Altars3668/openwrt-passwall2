#!/usr/bin/env python3
"""iptables 分流子链验收：在 sudo 创建的独立网络命名空间中加载 iptables/ip6tables 规则，不触碰本机防火墙。

1. 展开分流子链跳转、去掉一次性标记规则后，新规则与上游（PW2_UPSTREAM_REF）规则逐条等价；
2. shunt_switch 只替换分流子链内容，主链保持不变，并可往返切换；
3. refresh_sets 用 ipset swap 重建由规则派生的集合，主链与子链不变；
4. stop 删除全部 PSW2 链（含分流子链与辅助链），旧规则缺少子链时拒绝切换。

需要 iptables-legacy、busybox、免密 sudo，以及 ipset（PW2_IPSET_ROOT 指向解包的 ipset 与 libipset，
默认 /tmp/passwall2-hot-reload/ipset-pkg/root）。
"""

import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import nft_shunt_test as base

ROOT = base.ROOT
SCRIPT = "luci-app-passwall2/root/usr/share/passwall2/iptables.sh"
REDIR_PORT = base.REDIR_PORT
FWMARK = "0x50535732"
ITEM_CHAINS = {"PSW2_SHUNT_NAT", "PSW2_SHUNT_ICMP", "PSW2_SHUNT_ICMP6", "PSW2_SHUNT_MARK", "PSW2_SHUNT_MARK6"}
HELPER_CHAINS = {"PSW2_SHUNT_DIRECT", "PSW2_SHUNT_RETURN"}
IPSET_ROOT = Path(os.environ.get("PW2_IPSET_ROOT", "/tmp/passwall2-hot-reload/ipset-pkg/root"))

IPSET_WRAPPER = f"""#!/bin/sh
export LD_LIBRARY_PATH={IPSET_ROOT}/usr/lib/x86_64-linux-gnu
exec {IPSET_ROOT}/usr/sbin/ipset "$@"
"""

# 上游按 lsmod 判断 ip6tables 的 nat/mangle 表是否可用；声明可用以覆盖 IPv6 规则（内核按需加载模块）。
FAKE_LSMOD = "#!/bin/sh\nprintf 'ip6table_nat 16384 0\\nip6table_mangle 16384 0\\n'\n"

WHITE_SETS = ["set_cache_var node_shunt1_direct_ipset4 psw2_shunt1_white", "set_cache_var node_shunt1_direct_ipset6 psw2_shunt1_white6"]

DUMP = ("iptables-legacy-save > $TEST_ROOT/{name}.v4; ip6tables-legacy-save > $TEST_ROOT/{name}.v6; "
        "ipset list > $TEST_ROOT/{name}.ipset")


def available():
    return base.sudo_available() and shutil.which("iptables-legacy") and (IPSET_ROOT / "usr/sbin/ipset").exists()


class Netns(base.Netns):
    def __init__(self, script_text, variant):
        super().__init__(script_text, variant)
        (self.work / "nftables.sh").unlink()
        (self.work / "iptables.sh").write_text(script_text)
        for name, text in (("ipset", IPSET_WRAPPER), ("lsmod", FAKE_LSMOD)):
            tool = self.work / "bin" / name
            tool.write_text(text)
            tool.chmod(0o755)


def environment(variant, acl, order=("own", "lan")):
    env = base.environment(variant, acl, order)
    env.update({"USE_TABLES": "iptables", "nftflag": "0"})
    return env


def parse(text):
    """iptables-save 输出 → {表: {链: [规则]}}；规则为 (匹配段的集合, 目标)，匹配段与顺序无关。"""
    tables, table = {}, None
    for line in text.splitlines():
        if line.startswith("*"):
            table = tables.setdefault(line[1:], {})
        elif line.startswith(":"):
            table.setdefault(line[1:].split()[0], [])
        elif line.startswith("-A "):
            tokens = shlex.split(line)
            table.setdefault(tokens[1], []).append(normalize(tokens[2:]))
    return tables


def normalize(tokens):
    target = ()
    for flag in ("-j", "-g"):
        if flag in tokens:
            index = tokens.index(flag)
            tokens, target = tokens[:index], tuple(tokens[index:])
            break
    segments, current, i = [], None, 0
    while i < len(tokens):
        token = tokens[i]
        if token == "-m":
            current = ["-m", tokens[i + 1]]
            segments.append(current)
            i += 2
        elif token == "!" and tokens[i + 1].startswith("--") and current is not None:
            current += ["!", tokens[i + 1]]
            i += 2
        elif token == "!" or (token.startswith("-") and not token.startswith("--")):
            negate = token == "!"
            option = tokens[i + 1] if negate else token
            value_index = i + 2 if negate else i + 1
            segments.append(["!", option, tokens[value_index]] if negate else [option, tokens[value_index]])
            current = None
            i = value_index + 1
        else:
            current.append(token)
            i += 1
    return frozenset(tuple(segment) for segment in segments), target


GUARD = ("-m", "connmark", "!", "--mark", FWMARK)
MARKER = ("-m", "mark", "--mark", "0x80000000/0x80000000")


def flatten(tables, redirect=False):
    """把跳转到分流子链的规则展开成上游写法：子链里 goto 置标记链等价于主链 RETURN，去掉标记检查规则。

    redirect=True 时去掉 IPv6 mangle 客户端链（PSW2）中 TCP 展开出的代理项：上游在重定向模式下给这里的代理项用了 nat 的
    REDIRECT 动作，ip6tables 在 mangle 表拒绝这些规则（直连项的 RETURN 合法、仍在；同一处的兜底是 -j PSW2_RULE），
    新版统一打标记，是有意修正。
    """
    result = {}
    for name, chains in tables.items():
        flat = {}
        for chain, rules in chains.items():
            if chain in ITEM_CHAINS or chain in HELPER_CHAINS:
                continue
            out = []
            for segments, target in rules:
                if MARKER in segments and target == ("-g", "PSW2_SHUNT_RETURN"):
                    continue
                if len(target) == 2 and target[0] == "-j" and target[1] in ITEM_CHAINS:
                    prefix = segments - {GUARD}
                    for item_segments, item_target in chains[target[1]]:
                        if item_target == ("-g", "PSW2_SHUNT_DIRECT"):
                            item_target = ("-j", "RETURN")
                        elif redirect and chain == "PSW2" and target[1] == "PSW2_SHUNT_MARK6" and ("-p", "tcp") in segments:
                            continue
                        out.append((prefix | item_segments, item_target))
                    continue
                out.append((segments, target))
            flat[chain] = out
        result[name] = flat
    return result


@unittest.skipUnless(available(), "需要 iptables-legacy、busybox、免密 sudo 与 ipset（只在独立网络命名空间内操作）")
class IptablesShuntTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.new = (ROOT / SCRIPT).read_text()
        ref = os.environ.get("PW2_UPSTREAM_REF", "origin/main")
        cls.upstream = subprocess.run(["git", "-C", str(ROOT), "show", f"{ref}:{SCRIPT}"], capture_output=True, text=True, check=True).stdout

    def load(self, text, variant, acl, extra_steps=(), order=("own", "lan")):
        netns = Netns(text, environment(variant, acl, order))
        self.addCleanup(netns.close)
        steps = list(WHITE_SETS) + base.acl_setup(variant, acl) + [
            "set -- start", ". ./iptables.sh", DUMP.format(name="start"),
        ] + list(extra_steps)
        netns.run(steps, base.BASE_DB.format(icmp=variant["ICMP"], local=variant["LOCALHOST_PROXY"]))
        return netns

    def dump(self, netns, name):
        return {"v4": parse((netns.root / f"{name}.v4").read_text()), "v6": parse((netns.root / f"{name}.v6").read_text())}

    def test_equivalent_to_upstream(self):
        for variant in base.VARIANTS:
            for acl in (False, True):
                with self.subTest(variant=variant, acl=acl):
                    upstream = self.dump(self.load(self.upstream, variant, acl), "start")
                    new = self.dump(self.load(self.new, variant, acl), "start")
                    for family in ("v4", "v6"):
                        expected, actual = upstream[family], flatten(new[family], variant["TCP_PROXY_WAY"] == "redirect")
                        self.assertEqual(sorted(actual), sorted(expected), family)
                        for table in expected:
                            self.assertEqual(sorted(actual[table]), sorted(expected[table]), (family, table))
                            for chain in expected[table]:
                                self.assertEqual(actual[table][chain], expected[table][chain], (family, table, chain))
                    names = (Path(self.load(self.new, variant, acl).root) / "start.ipset").read_text()
                    self.assertIn("psw2_shunt1_rproxy", names)

    def test_default_entry_keeps_global_lists_after_other_acl(self):
        # 上游按“节点是否已生成过列表”跳过计算，列表变量沿用上一条目：跟随全局的条目在前、独立节点条目在后时，
        # 默认条目会错误地使用后者（shunt2）的分流列表。新版默认条目跳转到按全局节点生成的分流子链。
        variant = {"TCP_PROXY_WAY": "redirect", "PROXY_IPV6": "0", "ICMP": "0", "LOCALHOST_PROXY": "0"}
        order = ("lan", "own")
        upstream = self.dump(self.load(self.upstream, variant, True, order=order), "start")["v4"]["nat"]["PSW2"]
        new = self.dump(self.load(self.new, variant, True, order=order), "start")["v4"]["nat"]

        def default_sets(rules):
            return {seg[3] for segments, _ in rules if ("-m", "comment", "--comment", "Default") in segments
                    for seg in segments if seg[:3] == ("-m", "set", "--match-set")}

        self.assertTrue(any(name.startswith("psw2_shunt2") for name in default_sets(upstream)))
        flat = flatten({"nat": new})["nat"]["PSW2"]
        self.assertFalse(any(name.startswith("psw2_shunt2") for name in default_sets(flat)))
        self.assertIn("psw2_shunt1_rproxy", default_sets(flat))

    def test_switch_replaces_only_sub_chains(self):
        variant = {"TCP_PROXY_WAY": "tproxy", "PROXY_IPV6": "1", "ICMP": "1", "LOCALHOST_PROXY": "1"}
        steps = [
            f"busybox sh ./iptables.sh shunt_switch n1 {REDIR_PORT}", DUMP.format(name="n1"),
            f"busybox sh ./iptables.sh shunt_switch shunt2 {REDIR_PORT}", DUMP.format(name="shunt2"),
            f"busybox sh ./iptables.sh shunt_switch shunt1 {REDIR_PORT}", DUMP.format(name="back"),
            "busybox sh ./iptables.sh shunt_ready", "cp $TEST_ROOT/passwall2.include $TEST_ROOT/include.back",
            "set -- stop", "( . ./iptables.sh )", DUMP.format(name="stopped"),
        ]
        netns = self.load(self.new, variant, True, steps)
        start, normal, other, back = (self.dump(netns, name) for name in ("start", "n1", "shunt2", "back"))

        def main(dump):
            return {family: {table: {chain: rules for chain, rules in chains.items() if chain not in ITEM_CHAINS}
                             for table, chains in tables.items()} for family, tables in dump.items()}

        def items(dump):
            return {family: {table: {chain: rules for chain, rules in chains.items() if chain in ITEM_CHAINS}
                             for table, chains in tables.items()} for family, tables in dump.items()}

        for dump in (normal, other, back):
            self.assertEqual(main(dump), main(start))
        self.assertEqual(items(back), items(start))
        self.assertFalse(any(rules for tables in items(normal).values() for chains in tables.values() for rules in chains.values()))
        text = repr(items(other))
        self.assertIn("psw2_shunt2_rdirect", text)
        self.assertNotIn("psw2_shunt1_", text)
        # 主链里不再直接引用全局节点的分流集合（独立实例 own 仍用 shunt2 的静态规则）。
        main_text = repr(main(start))
        self.assertNotIn("psw2_shunt1_", main_text)
        self.assertIn("psw2_shunt2_", main_text)
        self.assertIn("PSW2_SHUNT_MARK", main_text)
        stopped = self.dump(netns, "stopped")
        leftover = [chain for tables in stopped.values() for chains in tables.values() for chain in chains if chain.startswith("PSW2")]
        self.assertEqual(leftover, [])
        include = Path(netns.root / "include.back").read_text()
        self.assertIn("PSW2_SHUNT_MARK", include)

    def test_refresh_rebuilds_rule_sets(self):
        variant = {"TCP_PROXY_WAY": "tproxy", "PROXY_IPV6": "1", "ICMP": "0", "LOCALHOST_PROXY": "1"}
        steps = [
            "ipset add psw2_shunt1_rproxy 203.0.113.0/24", "ipset add psw2_shunt2_rproxy 203.0.113.0/24",
            "ipset add psw2_shunt1_white 198.18.0.9", "ipset add psw2_direct 203.0.114.1", "ipset add psw2_vps 192.0.2.99",
            "sed -i 's#9.9.9.0/24#9.9.40.0/24#' $FAKE_UCI_DB",
            f"GEO_VERSION=2 busybox sh ./iptables.sh refresh_sets shunt1 {REDIR_PORT} 1; echo $? > $TEST_ROOT/status",
            DUMP.format(name="refreshed"),
        ]
        netns = self.load(self.new, variant, True, steps)
        self.assertEqual((netns.root / "status").read_text().strip(), "0")
        start, refreshed = self.dump(netns, "start"), self.dump(netns, "refreshed")
        self.assertEqual(refreshed, start, "主链与分流子链不变")
        sets = (netns.root / "refreshed.ipset").read_text()

        def members(name):
            block = sets.split(f"Name: {name}\n", 1)[1].split("\nName: ", 1)[0]
            return block.split("Members:\n", 1)[1]

        for name in ("psw2_shunt1_rproxy", "psw2_shunt2_rproxy"):
            text = members(name)
            self.assertIn("9.9.40.0/24", text, name)
            self.assertIn("9.9.3.0/24", text, name)
            self.assertNotIn("9.9.9.0/24", text, name)
            self.assertNotIn("9.9.8.0/24", text, name)
            self.assertNotIn("203.0.113.0", text, name)
        self.assertNotIn("198.18.0.9", members("psw2_shunt1_white"))
        self.assertNotIn("203.0.114.1", members("psw2_direct"))
        self.assertIn("192.0.2.99", members("psw2_vps"), "psw2_vps 只补充不清空")
        self.assertNotIn("psw2_r", "\n".join(line for line in sets.splitlines() if line.startswith("Name: ")), "临时集合已销毁")

    def test_packets_follow_shunt_classification(self):
        # 报文级验证（本机代理、重定向模式）：代理端口与直连端口各有监听，连接结果说明 nat OUTPUT 的实际走向。
        # 9.9.9.1 在代理集合，9.9.6.1 在直连集合，9.9.5.1 属于默认（走代理），1.2.3.4 不在集合内由兜底代理，
        # 8080 不在代理端口内保持直连。新旧脚本结果一致；热切换到普通节点后直连集合不再生效，切回后恢复。
        variant = {"TCP_PROXY_WAY": "redirect", "PROXY_IPV6": "0", "ICMP": "0", "LOCALHOST_PROXY": "1"}
        server = ("import socket,sys,threading\n"
                  "def serve(port,word):\n"
                  " s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',port));s.listen(16)\n"
                  " while True:\n  c,_=s.accept();c.sendall(word);c.close()\n"
                  "for p,w in ((int(sys.argv[1]),b'proxy'),(80,b'direct'),(8080,b'direct')):\n"
                  " threading.Thread(target=serve,args=(p,w),daemon=True).start()\n"
                  "threading.Event().wait()\n")
        probe = ("import socket,sys\n"
                 "out=[]\n"
                 "for target in sys.argv[1:]:\n"
                 " host,port=target.split(':')\n"
                 " try:\n  c=socket.create_connection((host,int(port)),timeout=3);out.append(target+'='+c.recv(16).decode());c.close()\n"
                 " except OSError as e: out.append(target+'=error')\n"
                 "print(' '.join(out))\n")
        targets = "9.9.9.1:80 9.9.6.1:80 9.9.5.1:80 1.2.3.4:80 1.2.3.4:8080"
        network = [
            "ip link set lo up", "ip link add dummy0 type dummy", "ip link set dummy0 up",
            "ip addr add 9.9.6.1/32 dev dummy0", "ip addr add 1.2.3.4/32 dev dummy0", "ip route add default dev dummy0",
            f"printf '%s' \"{server}\" > $TEST_ROOT/server.py", f"printf '%s' \"{probe}\" > $TEST_ROOT/probe.py",
            # 网络命名空间不隔离进程：只按记录的 PID 结束监听进程，不能用 pkill -f（root 会匹配到宿主上的进程）。
            f"(python3 $TEST_ROOT/server.py {REDIR_PORT} >/dev/null 2>&1 & echo $! > $TEST_ROOT/server.pid)", "sleep 1",
        ]

        def run(text, extra):
            netns = Netns(text, environment(variant, False))
            self.addCleanup(netns.close)
            steps = list(WHITE_SETS) + base.acl_setup(variant, False) + network + [
                "set -- start", ". ./iptables.sh >/dev/null 2>&1",
                f"python3 $TEST_ROOT/probe.py {targets} > $TEST_ROOT/probe.start",
            ] + extra + ["kill $(cat $TEST_ROOT/server.pid) 2>/dev/null; true"]
            netns.run(steps, base.BASE_DB.format(icmp="0", local="1"))
            return netns

        expected = "9.9.9.1:80=proxy 9.9.6.1:80=direct 9.9.5.1:80=proxy 1.2.3.4:80=proxy 1.2.3.4:8080=direct"
        upstream = run(self.upstream, [])
        self.assertEqual((upstream.root / "probe.start").read_text().strip(), expected, "上游脚本的基准行为")
        new = run(self.new, [
            f"busybox sh ./iptables.sh shunt_switch n1 {REDIR_PORT} >/dev/null 2>&1",
            f"python3 $TEST_ROOT/probe.py {targets} > $TEST_ROOT/probe.n1",
            f"busybox sh ./iptables.sh shunt_switch shunt1 {REDIR_PORT} >/dev/null 2>&1",
            f"python3 $TEST_ROOT/probe.py {targets} > $TEST_ROOT/probe.back",
        ])
        self.assertEqual((new.root / "probe.start").read_text().strip(), expected)
        self.assertEqual((new.root / "probe.n1").read_text().strip(), expected.replace("9.9.6.1:80=direct", "9.9.6.1:80=proxy"))
        self.assertEqual((new.root / "probe.back").read_text().strip(), expected)

    def test_switch_refuses_without_sub_chains(self):
        variant = {"TCP_PROXY_WAY": "redirect", "PROXY_IPV6": "0", "ICMP": "0", "LOCALHOST_PROXY": "1"}
        netns = Netns(self.new, environment(variant, False))
        self.addCleanup(netns.close)
        (netns.work / "upstream.sh").write_text(self.upstream)
        netns.run(WHITE_SETS + base.acl_setup(variant, False) + [
            "set -- start", ". ./upstream.sh", DUMP.format(name="before"),
            f"busybox sh ./iptables.sh shunt_switch n1 {REDIR_PORT}; echo $? > $TEST_ROOT/status",
            DUMP.format(name="after"),
        ], base.BASE_DB.format(icmp="0", local="1"))
        self.assertEqual((netns.root / "status").read_text().strip(), "2")
        self.assertEqual(self.dump(netns, "after"), self.dump(netns, "before"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
