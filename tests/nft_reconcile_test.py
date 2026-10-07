#!/usr/bin/env python3
"""差量热重载的防火墙部分：在 sudo 创建的独立网络命名空间中验证，不触碰本机防火墙。

先按配置 A 正常加载规则（正式表），再按配置 B 做影子启动（规则写入不挂钩子的影子表），
用 reconcile.lua 生成一个 nft 事务提交到正式表，结果必须与直接按 B 启动的规则逐条一致；
配置不变时事务判定为无变化；影子表中的规则不处理报文；事务失败时正式表不变。
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import nft_shunt_test as base

ROOT = base.ROOT
SCRIPT = base.SCRIPT

# 影子启动用 PW2_TMP_PATH 指向暂存目录；缓存目录保持正式路径（与 utils.sh 一致）。
FAKE_UTILS = base.FAKE_UTILS.replace(
    "TMP_PATH=$TEST_ROOT/tmp/etc/passwall2\nTMP_PATH2=${TMP_PATH}_tmp",
    "TMP_PATH=${PW2_TMP_PATH:-$TEST_ROOT/tmp/etc/passwall2}\nTMP_PATH2=$TEST_ROOT/tmp/etc/passwall2_tmp")
assert "PW2_TMP_PATH" in FAKE_UTILS

DRIVER = r"""
local root, repo = arg[1], arg[2]
local R = dofile(repo .. "/luci-app-passwall2/luasrc/passwall2/reconcile.lua")
local function read(path) local f = io.open(path) if not f then return "" end local s = f:read("*a") f:close() return s end
local function write(path, text) local f = assert(io.open(path, "w")) f:write(text) f:close() end
local base, preserved = {}, {}
for line in read(root .. "/stage/nft_base_chains"):gmatch("[^\n]+") do
	local name, spec = line:match("^([^|]+)|(.*)$")
	if name then base[name] = spec end
end
for name in read(root .. "/stage/preserved_sets"):gmatch("%S+") do preserved[name] = true end
local desired, current = R.parse_nft(read(root .. "/stage.nft")), R.parse_nft(read(root .. "/current.nft"))
local script, summary = R.nft_commit(desired, current, { table = "inet passwall2", base = base, preserved = preserved })
if not script then io.stderr:write(summary .. "\n") os.exit(1) end
write(root .. "/commit.nft", script)
local obsolete = {}
for _, name in ipairs(summary.sets_obsolete) do obsolete[#obsolete + 1] = "delete set inet passwall2 " .. name end
write(root .. "/obsolete.nft", table.concat(obsolete, "\n") .. "\n")
write(root .. "/summary.txt", (summary.changed and "changed" or "same") .. "\n" .. table.concat(summary.sets_refreshed, " ") .. "\n")
"""


def variant(**overrides):
    value = {"TCP_PROXY_WAY": "redirect", "PROXY_IPV6": "0", "ICMP": "0", "LOCALHOST_PROXY": "1", "ACL": False,
             "NODE": "shunt1", "PORTS": "22,80,443", "DNS_REDIRECT": "1", "RETURN_DNS": "119.29.29.29"}
    value.update(overrides)
    return value


def env_lines(v):
    env = base.environment(v, v["ACL"])
    env.update({"NODE": v["NODE"], "RETURN_DNS": v["RETURN_DNS"]})
    return [f"export {key}='{value}'" for key, value in env.items()]


# 与 nft_shunt_test.acl_setup 相同的文件，代理端口与全局节点可变。
def setup_lines(v):
    steps = list(base.WHITE_SETS) + [
        base.var_file("acl_default", {"flag": "acl_default", "remarks": "Default", "tcp_redir_ports": v["PORTS"],
                                      "udp_redir_ports": "1:65535", "node": v["NODE"], "local_proxy": v["LOCALHOST_PROXY"],
                                      "client_proxy": "1", "use": "acl_default", "node_remarks": "S", "redir_port": base.REDIR_PORT}),
        "echo any > $TMP_ACL_PATH/acl_default/source_list",
        "set_cache_var ACL_acl_default_dns_port 11400",
    ]
    if v["ACL"]:
        steps += [
            base.var_file("lan", {"flag": "lan", "remarks": "LAN guest", "client_proxy": "1", "local_proxy": "0",
                                  "node": v["NODE"], "use": "acl_default", "node_remarks": "S", "redir_port": base.REDIR_PORT}),
            "echo 'ip:192.168.1.50' > $TMP_ACL_PATH/lan/source_list",
            base.var_file("own", {"flag": "own", "remarks": "Own", "tcp_redir_ports": "80,443", "client_proxy": "1",
                                  "local_proxy": "0", "node": "shunt2", "use": "own", "node_remarks": "S2", "redir_port": "11201"}),
            "echo 'mac:02:00:00:00:00:01' > $TMP_ACL_PATH/own/source_list",
            "set_cache_var ACL_own_dns_port 11401",
        ]
    return steps


def uci_db(v):
    db = base.BASE_DB.format(icmp=v["ICMP"], local=v["LOCALHOST_PROXY"])
    db = db.replace("passwall2.cfg_global.node='shunt1'", f"passwall2.cfg_global.node='{v['NODE']}'")
    db = db.replace("passwall2.cfg_global.dns_redirect='1'", f"passwall2.cfg_global.dns_redirect='{v['DNS_REDIRECT']}'")
    return db


class Namespace:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pw2-reconcile-")
        self.root = Path(self.tmp.name)
        self.work = self.root / "work"
        (self.work / "bin").mkdir(parents=True)
        (self.work / "nftables.sh").write_text((ROOT / SCRIPT).read_text())
        (self.work / "utils.sh").write_text(FAKE_UTILS)
        for name, text in (("uci", base.FAKE_UCI), ("jsonfilter", base.FAKE_JSONFILTER)):
            tool = self.work / "bin" / name
            tool.write_text(text)
            tool.chmod(0o755)
        (self.root / "driver.lua").write_text(DRIVER)

    def run(self, steps, check=True):
        include = f"firewall.passwall2=include\nfirewall.passwall2.path='{self.root}/passwall2.include'\n"
        for name in ("a", "b"):
            path = self.root / f"uci_{name}.db"
            if path.exists():
                path.write_text(path.read_text() + include)
        body = "\n".join([f"export TEST_ROOT={self.root}", f"export PATH={self.work}/bin:$PATH", "cd " + str(self.work)] + steps)
        script = self.root / "run.sh"
        script.write_text(body + "\n")
        result = subprocess.run(
            ["sudo", "-n", "unshare", "--net", "busybox", "sh", "-c",
             f"busybox sh {script}; status=$?; chown -R {os.getuid()}:{os.getgid()} {self.root}; exit $status"],
            capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
        if check and result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return result

    def dump(self, name):
        return json.loads((self.root / name).read_text())

    def close(self):
        self.tmp.cleanup()


def start_steps(v, db_name):
    return ["("] + env_lines(v) + [f"export FAKE_UCI_DB=$TEST_ROOT/{db_name}", ". ./utils.sh", "mkdir -p $TMP_PATH $TMP_ACL_PATH $LOCK_PATH"] + \
        setup_lines(v) + ["set -- start", ". ./nftables.sh", ")"]


def stage_steps(v):
    return ["(", "export PW2_STAGE=1 PW2_TMP_PATH=$TEST_ROOT/stage"] + env_lines(v) + \
        ["export FAKE_UCI_DB=$TEST_ROOT/uci_b.db", ". ./utils.sh", "mkdir -p $TMP_PATH $TMP_ACL_PATH $LOCK_PATH"] + \
        setup_lines(v) + ["set -- start", ". ./nftables.sh", ")"]


def rules(dump):
    return {name: [[e for e in expr if not base.is_counter(e)] for expr in exprs] for name, exprs in base.chains(dump).items()}


def strip_expires(value):
    """元素的剩余寿命随时间变化，比较时去掉。"""
    if isinstance(value, dict):
        return {k: strip_expires(v) for k, v in value.items() if k != "expires"}
    if isinstance(value, list):
        return [strip_expires(v) for v in value]
    return value


def set_elements(dump):
    result = {}
    for item in dump["nftables"]:
        if "set" in item:
            result[item["set"]["name"]] = sorted(json.dumps(strip_expires(e), sort_keys=True) for e in item["set"].get("elem", []))
    return result


# 只比较内容完全由启动流程决定的集合；psw2_vps 由后台补充（时机不定），直连写集合由 DNS 写入。
def comparable(name):
    return not name.startswith("psw2_vps") and not name.endswith(("_white", "_white6"))


PAIRS = [
    ("本机代理关闭", variant(), variant(LOCALHOST_PROXY="0")),
    ("本机代理开启", variant(LOCALHOST_PROXY="0"), variant()),
    ("TCP 改为 TPROXY", variant(), variant(TCP_PROXY_WAY="tproxy")),
    ("TPROXY 改回重定向", variant(TCP_PROXY_WAY="tproxy", PROXY_IPV6="1"), variant(PROXY_IPV6="1")),
    ("开启 IPv6", variant(), variant(PROXY_IPV6="1")),
    ("开启 ICMP", variant(), variant(ICMP="1", PROXY_IPV6="1")),
    ("增加访问控制", variant(), variant(ACL=True)),
    ("删除访问控制", variant(ACL=True, ICMP="1"), variant(ICMP="1")),
    ("代理端口变化", variant(), variant(PORTS="80,443,8443")),
    ("全局节点换为另一分流节点", variant(ACL=True), variant(ACL=True, NODE="shunt2")),
    ("DNS 劫持只拦截本机地址", variant(), variant(DNS_REDIRECT="0")),
    ("直连 DNS 变化", variant(), variant(RETURN_DNS="223.5.5.5,119.29.29.29#53#tcp")),
]


@unittest.skipUnless(base.sudo_available() and subprocess.run(["which", "lua"], capture_output=True).returncode == 0,
                     "需要 nft、busybox、lua 与免密 sudo（只在独立网络命名空间内操作）")
class ReconcileTest(unittest.TestCase):
    def reconcile(self, a, b, extra=()):
        ns = Namespace()
        self.addCleanup(ns.close)
        (ns.root / "uci_a.db").write_text(uci_db(a))
        (ns.root / "uci_b.db").write_text(uci_db(b))
        steps = start_steps(a, "uci_a.db") + [
            "nft list table inet passwall2 > $TEST_ROOT/current.nft",
            "nft -j list table inet passwall2 > $TEST_ROOT/before.json",
        ] + stage_steps(b) + [
            "nft list table inet passwall2_stage > $TEST_ROOT/stage.nft",
            f"lua $TEST_ROOT/driver.lua $TEST_ROOT {ROOT}",
        ] + list(extra) + [
            "nft -f $TEST_ROOT/commit.nft",
            "nft -f $TEST_ROOT/obsolete.nft",
            "nft delete table inet passwall2_stage",
            "nft -j list table inet passwall2 > $TEST_ROOT/reconciled.json",
        ]
        ns.run(steps)
        return ns

    def fresh(self, b):
        ns = Namespace()
        self.addCleanup(ns.close)
        (ns.root / "uci_a.db").write_text(uci_db(b))
        ns.run(start_steps(b, "uci_a.db") + ["nft -j list table inet passwall2 > $TEST_ROOT/fresh.json"])
        return ns.dump("fresh.json")

    def assert_same_state(self, reconciled, fresh):
        self.assertEqual(rules(reconciled), rules(fresh))
        got, want = set_elements(reconciled), set_elements(fresh)
        self.assertEqual(sorted(got), sorted(want))
        for name in want:
            if comparable(name):
                self.assertEqual(got[name], want[name], name)

    def test_reconcile_matches_fresh_start(self):
        for title, a, b in PAIRS:
            with self.subTest(title):
                ns = self.reconcile(a, b)
                self.assertEqual((ns.root / "summary.txt").read_text().split("\n")[0], "changed", title)
                self.assert_same_state(ns.dump("reconciled.json"), self.fresh(b))

    def test_unchanged_config_is_noop(self):
        for title, a, _ in PAIRS[:4] + PAIRS[6:7]:
            with self.subTest(title):
                ns = self.reconcile(a, a)
                self.assertEqual((ns.root / "summary.txt").read_text().split("\n")[0], "same", title)
                self.assertEqual(rules(ns.dump("reconciled.json")), rules(ns.dump("before.json")))

    def test_stage_table_is_inert_and_preserves_rule_sets(self):
        # 影子表的基础链不挂钩子；已存在的规则集合在影子表中为空并记录为沿用，正式表内容不变。
        ns = Namespace()
        self.addCleanup(ns.close)
        a = variant(ACL=True)
        (ns.root / "uci_a.db").write_text(uci_db(a))
        (ns.root / "uci_b.db").write_text(uci_db(a))
        ns.run(start_steps(a, "uci_a.db") + ["nft -j list table inet passwall2 > $TEST_ROOT/before.json"] + stage_steps(a) +
               ["nft -j list table inet passwall2_stage > $TEST_ROOT/stage.json",
                "nft -j list table inet passwall2 > $TEST_ROOT/after.json"])
        stage = ns.dump("stage.json")
        hooks = [item["chain"] for item in stage["nftables"] if "chain" in item and "hook" in item["chain"]]
        self.assertEqual(hooks, [])
        preserved = (ns.root / "stage/preserved_sets").read_text().split()
        self.assertIn("psw2_shunt1_rproxy", preserved)
        self.assertEqual(set_elements(stage)["psw2_shunt1_rproxy"], [])
        self.assertTrue(set_elements(stage)["psw2_local"])
        self.assertEqual(rules(ns.dump("before.json")), rules(ns.dump("after.json")))
        self.assertEqual(set_elements(ns.dump("before.json")), set_elements(ns.dump("after.json")))
        self.assertFalse((ns.root / "passwall2.include").exists() and "passwall2_stage" in (ns.root / "passwall2.include").read_text())

    def test_failed_transaction_leaves_rules_untouched(self):
        broken = ["echo 'add rule inet passwall2 PSW2_NAT ip daddr 300.0.0.1 counter return' >> $TEST_ROOT/commit.nft",
                  "if nft -f $TEST_ROOT/commit.nft 2>/dev/null; then echo applied > $TEST_ROOT/status; else echo rejected > $TEST_ROOT/status; fi",
                  "nft -j list table inet passwall2 > $TEST_ROOT/after_fail.json",
                  "sed -i '$d' $TEST_ROOT/commit.nft"]
        ns = self.reconcile(variant(), variant(LOCALHOST_PROXY="0"), broken)
        self.assertEqual((ns.root / "status").read_text().strip(), "rejected")
        self.assertEqual(rules(ns.dump("after_fail.json")), rules(ns.dump("before.json")))


if __name__ == "__main__":
    unittest.main()
