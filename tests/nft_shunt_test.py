#!/usr/bin/env python3
"""全局分流子链验收：在 sudo 创建的独立网络命名空间中加载 nftables 规则，不触碰本机防火墙。

1. 展开子链跳转后，新规则与上游（HEAD）规则逐条等价；
2. shunt_switch 只替换子链内容，主链保持不变，并可往返切换；
3. stop 删除全部 PSW2 链（含子链与 PSW2_RULE）；
4. refresh_sets 在一个 nft 事务中重建由规则派生的集合，失败时不做任何改动。
"""

import itertools
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = "luci-app-passwall2/root/usr/share/passwall2/nftables.sh"
REDIR_PORT = "1041"
FWMARK = 0x50535732
SHUNT_CHAINS = {"PSW2_SHUNT_NAT", "PSW2_SHUNT_MARK", "PSW2_SHUNT_MARK6", "PSW2_SHUNT_ICMP", "PSW2_SHUNT_ICMP6"}

FAKE_UCI = r"""#!/bin/sh
# 测试用 uci：只支持 get/show，数据来自 $FAKE_UCI_DB（uci show 格式，值中的 \n 表示换行）。
while [ $# -gt 0 ]; do
	case "$1" in
		-q) shift ;;
		-p) shift 2 ;;
		*) break ;;
	esac
done
[ "$1" = get ] || [ "$1" = show ] || exit 1
exec awk -v mode="$1" -v key="$2" '
{
	eq = index($0, "="); lhs = substr($0, 1, eq - 1); rhs = substr($0, eq + 1)
	n = split(lhs, part, ".")
	if (n == 2) { k = part[1] "." rhs; anon[part[1] ".@" rhs "[" (count[k] + 0) "]"] = lhs; count[k]++ }
	line[NR] = $0; left[NR] = lhs; right[NR] = rhs
}
END {
	m = split(key, kp, ".")
	if (m >= 2 && substr(kp[2], 1, 1) == "@") {
		base = kp[1] "." kp[2]
		if (!(base in anon)) exit 1
		key = anon[base]
		for (i = 3; i <= m; i++) key = key "." kp[i]
	}
	for (i = 1; i <= NR; i++) {
		if (mode == "get" && left[i] == key) {
			v = right[i]; gsub(/^\047|\047$/, "", v); gsub(/\\n/, "\n", v); print v; exit 0
		}
		if (mode == "show" && (left[i] == key || index(left[i], key ".") == 1)) { print line[i]; found = 1 }
	}
	exit found ? 0 : 1
}' "$FAKE_UCI_DB"
"""

FAKE_JSONFILTER = r"""#!/usr/bin/env python3
# 测试用 jsonfilter：只支持 -s JSON -e '$.key[*]' 与 '$.key[*].field'。
import json, re, sys
args = sys.argv[1:]
data = json.loads(args[args.index("-s") + 1]) if "-s" in args else json.load(sys.stdin)
expr = args[args.index("-e") + 1]
m = re.fullmatch(r"\$\.(\w+)\[\*\](?:\.(\w+))?", expr)
if not m:
    sys.exit(1)
for item in data.get(m.group(1), []):
    value = item.get(m.group(2)) if m.group(2) else item
    if value is not None:
        print(value)
"""

# 替代 utils.sh：保留 nftables.sh 用到的配置读取函数，其余外部依赖用确定性桩函数。
FAKE_UTILS = r"""
CONFIG=passwall2
TMP_PATH=$TEST_ROOT/tmp/etc/passwall2
TMP_PATH2=${TMP_PATH}_tmp
TMP_ACL_PATH=$TMP_PATH/acl
TMP_IFACE_PATH=$TMP_PATH/iface
LOCK_PATH=$TEST_ROOT/lock
LOG_FILE=$TEST_ROOT/passwall2.log
config_get_type() { local ret=$(uci -q get "${CONFIG}.${1}" 2>/dev/null); echo "${ret:=$2}"; }
config_n_get() { local ret=$(uci -q get "${CONFIG}.${1}.${2}" 2>/dev/null); echo "${ret:=$3}"; }
config_t_get() { local index=${4:-0}; local ret=$(uci -q get "${CONFIG}.@${1}[${index}].${2}" 2>/dev/null); echo "${ret:=${3}}"; }
get_cache_var() { [ -n "$1" ] && [ -s "$TMP_PATH/var" ] && echo $(grep "^$1=" "$TMP_PATH/var" | awk -F '=' '{print $2}' | tail -n 1 | awk -F'"' '{print $2}'); }
del_cache_var() { sed -i "/$1=/d" $TMP_PATH/var 2>/dev/null; }
set_cache_var() { local key=$1; shift; del_cache_var $key; [ -n "$*" ] && echo "${key}=\"$*\"" >> $TMP_PATH/var; }
log() { shift; echo "$*" >> "$LOG_FILE"; }
log_i18n() { shift; echo "$*" >> "$LOG_FILE"; }
i18n() { echo "$*"; }
first_type() { [ "$1" = geoview ] && { echo /bin/true; return; }; command -v "$1"; }
get_geoip() {
	# GEO_VERSION 模拟规则数据更新后的 geoip.dat。
	case "${GEO_VERSION:-1},$1,$2" in
		1,*testp*,ipv4) echo 9.9.8.0/24 ;;
		2,*testp*,ipv4) echo 9.9.3.0/24 ;;
		*,*testp*,ipv6) echo 2001:db8:8::/48 ;;
		*,*testd*,ipv4) echo 9.9.7.0/24 ;;
		*,*testd*,ipv6) echo 2001:db8:7::/48 ;;
	esac
}
get_host_ip() { [ "$1" = ipv4 ] && echo "$2" | grep -E '^[0-9.]+$'; }
get_local_ips() { [ "$1" = ip4 ] && echo 192.168.1.1 || echo fd00::1; }
get_wan_ips() { [ "$1" = ip4 ] && echo 198.51.100.2; }
has_1_65535() { local val="$1"; val=${val//:/-}; case ",$val," in *,1-65535,*) return 0 ;; *) return 1 ;; esac; }
network_get_gateway() { eval "$1=''"; }
network_get_device() { eval "$1=''"; }
acl_node() { :; }
"""

BASE_DB = """passwall2.cfg_global=global
passwall2.cfg_global.enabled='1'
passwall2.cfg_global.node='shunt1'
passwall2.cfg_global.dns_redirect='1'
passwall2.cfg_global.localhost_proxy='{local}'
passwall2.cfg_global.client_proxy='1'
passwall2.cfg_fwd=global_forwarding
passwall2.cfg_fwd.accept_icmp='{icmp}'
passwall2.cfg_fwd.accept_icmpv6='{icmp}'
passwall2.cfg_fwd.tcp_redir_ports='22,80,443'
passwall2.cfg_fwd.udp_redir_ports='1:65535'
passwall2.n1=nodes
passwall2.n1.type='sing-box'
passwall2.n1.protocol='vless'
passwall2.n1.address='192.0.2.10'
passwall2.n2=nodes
passwall2.n2.type='sing-box'
passwall2.n2.protocol='vless'
passwall2.n2.address='192.0.2.20'
passwall2.shunt1=nodes
passwall2.shunt1.type='sing-box'
passwall2.shunt1.protocol='_shunt'
passwall2.shunt1.enable_geoview_ip='1'
passwall2.shunt1.default_node='n1'
passwall2.shunt1.rproxy='n2'
passwall2.shunt1.rdirect='_direct'
passwall2.shunt1.rdefault='_default'
passwall2.shunt2=nodes
passwall2.shunt2.type='sing-box'
passwall2.shunt2.protocol='_shunt'
passwall2.shunt2.enable_geoview_ip='1'
passwall2.shunt2.default_node='_direct'
passwall2.shunt2.rproxy='_direct'
passwall2.shunt2.rdirect='n1'
passwall2.shunt2.rdefault='_default'
passwall2.rproxy=shunt_rules
passwall2.rproxy.ip_list='9.9.9.0/24\\n2001:db8:9::/48\\ngeoip:testp'
passwall2.rdirect=shunt_rules
passwall2.rdirect.ip_list='9.9.6.0/24\\ngeoip:testd'
passwall2.rdefault=shunt_rules
passwall2.rdefault.ip_list='9.9.5.0/24'
passwall2.lan=acl_rule
passwall2.lan.enabled='1'
passwall2.lan.remarks='LAN guest'
passwall2.own=acl_rule
passwall2.own.enabled='1'
passwall2.own.remarks='Own'
"""


def sudo_available():
    if not shutil.which("nft") or not shutil.which("busybox"):
        return False
    return subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0


class Netns:
    """一次 sudo unshare --net：在全新网络命名空间内顺序执行脚本片段并导出规则集。"""

    def __init__(self, script_text, variant):
        self.tmp = tempfile.TemporaryDirectory(prefix="pw2-nft-")
        self.root = Path(self.tmp.name)
        self.work = self.root / "work"
        (self.work / "bin").mkdir(parents=True)
        (self.work / "nftables.sh").write_text(script_text)
        (self.work / "utils.sh").write_text(FAKE_UTILS)
        for name, text in (("uci", FAKE_UCI), ("jsonfilter", FAKE_JSONFILTER)):
            tool = self.work / "bin" / name
            tool.write_text(text)
            tool.chmod(0o755)
        self.variant = variant

    def run(self, steps, db):
        (self.root / "uci.db").write_text(db + f"firewall.passwall2=include\nfirewall.passwall2.path='{self.root}/passwall2.include'\n")
        env_lines = [f"export TEST_ROOT={self.root}", f"export FAKE_UCI_DB={self.root}/uci.db", f"export PATH={self.work}/bin:$PATH"]
        for key, value in self.variant.items():
            env_lines.append(f"export {key}='{value}'")
        body = "\n".join(env_lines + ["cd " + str(self.work), ". ./utils.sh", "mkdir -p $TMP_PATH $TMP_ACL_PATH $LOCK_PATH"] + steps)
        script = self.root / "run.sh"
        script.write_text(body + "\n")
        result = subprocess.run(
            ["sudo", "-n", "unshare", "--net", "busybox", "sh", "-c",
             f"busybox sh {script}; status=$?; chown -R {os.getuid()}:{os.getgid()} {self.root}; exit $status"],
            capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return result

    def dump(self, name):
        return json.loads((self.root / name).read_text())

    def close(self):
        self.tmp.cleanup()


def chains(dump):
    result = {}
    for item in dump["nftables"]:
        if "chain" in item:
            result.setdefault(item["chain"]["name"], [])
        if "rule" in item:
            result.setdefault(item["rule"]["chain"], []).append(item["rule"]["expr"])
    return result


def sets(dump):
    return sorted(item["set"]["name"] for item in dump["nftables"] if "set" in item)


def is_counter(expr):
    return "counter" in expr


def guard(expr):
    match = expr.get("match")
    return bool(match) and match.get("op") == "!=" and match.get("left") == {"ct": {"key": "mark"}} and match.get("right") == FWMARK


def dead(expr):
    """同时匹配 IPv4 与 IPv6 地址的规则永远不会命中（上游 ACL 的 ICMPv6 规则带 IPv4 来源时 nft 直接拒绝）。"""
    protocols = {e["match"]["left"]["payload"]["protocol"] for e in expr
                 if isinstance(e.get("match", {}).get("left"), dict) and "payload" in e["match"]["left"]}
    return {"ip", "ip6"} <= protocols


def flatten(dump):
    """把跳转到分流子链的规则展开成上游的写法：子链 accept 等价于主链 return。"""
    table = chains(dump)
    result = {}
    for name, rules in table.items():
        if name in SHUNT_CHAINS:
            continue
        flat = []
        for expr in rules:
            expr = [e for e in expr if not is_counter(e)]
            target = expr[-1].get("jump", {}).get("target") if expr else None
            if target not in SHUNT_CHAINS:
                flat.append(expr)
                continue
            prefix = [e for e in expr[:-1] if not guard(e)]
            assert len(prefix) == len(expr) - 1 - (1 if target.startswith("PSW2_SHUNT_MARK") else 0), (name, expr)
            for sub in table[target]:
                sub = [e for e in sub if not is_counter(e)]
                sub = [{"return": None} if e == {"accept": None} else e for e in sub]
                combined = prefix + [e for e in sub if e not in prefix]
                if not dead(combined):
                    flat.append(combined)
        result[name] = flat
    return result


def upstream_flat(dump):
    return {name: [[e for e in expr if not is_counter(e)] for expr in rules] for name, rules in chains(dump).items()}


VARIANTS = [
    dict(zip(("TCP_PROXY_WAY", "PROXY_IPV6", "ICMP", "LOCALHOST_PROXY"), combo))
    for combo in itertools.product(("redirect", "tproxy"), ("0", "1"), ("0", "1"), ("1", "0"))
]


def environment(variant, acl, order=("own", "lan")):
    entries = (list(order) if acl else []) + ["acl_default"]
    acl_json = json.dumps({"acl": [{"flag": flag} for flag in entries],
                           "node_order": ([flag for flag in entries if flag != "lan"])})
    return {
        "ENABLED_DEFAULT_ACL": "1", "ENABLED_ACLS": "1" if acl else "0", "NODE": "shunt1",
        "TCP_PROXY_WAY": variant["TCP_PROXY_WAY"], "PROXY_IPV6": variant["PROXY_IPV6"],
        "RETURN_DNS": "119.29.29.29", "USE_TABLES": "nftables", "nftflag": "1", "ACL_JSON": acl_json,
    }


def var_file(path, values):
    lines = "".join(f'{key}="{value}"\n' for key, value in values.items())
    return f"mkdir -p $TMP_ACL_PATH/{path}; printf '%s' '{lines}' > $TMP_ACL_PATH/{path}/var"


# 与 app_acl.lua 的 acl_app 写出的文件一致：默认条目追加在访问控制条目之后。
def acl_setup(variant, acl):
    steps = [
        var_file("acl_default", {"flag": "acl_default", "remarks": "Default", "tcp_redir_ports": "22,80,443",
                                 "udp_redir_ports": "1:65535", "node": "shunt1", "local_proxy": variant["LOCALHOST_PROXY"],
                                 "client_proxy": "1", "use": "acl_default", "node_remarks": "S1", "redir_port": REDIR_PORT}),
        "echo any > $TMP_ACL_PATH/acl_default/source_list",
        "set_cache_var ACL_acl_default_dns_port 11400",
    ]
    if acl:
        steps += [
            var_file("lan", {"flag": "lan", "remarks": "LAN guest", "client_proxy": "1", "local_proxy": "0",
                             "node": "shunt1", "use": "acl_default", "node_remarks": "S1", "redir_port": REDIR_PORT}),
            "echo 'ip:192.168.1.50' > $TMP_ACL_PATH/lan/source_list",
            var_file("own", {"flag": "own", "remarks": "Own", "tcp_redir_ports": "80,443", "client_proxy": "1",
                             "local_proxy": "0", "node": "shunt2", "use": "own", "node_remarks": "S2", "redir_port": "11201"}),
            "echo 'mac:02:00:00:00:00:01' > $TMP_ACL_PATH/own/source_list",
            "set_cache_var ACL_own_dns_port 11401",
        ]
    return steps


WHITE_SETS = ["set_cache_var node_shunt1_direct_nftset4 psw2_shunt1_white", "set_cache_var node_shunt1_direct_nftset6 psw2_shunt1_white6"]


@unittest.skipUnless(sudo_available(), "需要 nft、busybox 与免密 sudo（只在独立网络命名空间内操作）")
class ShuntChainTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.new = (ROOT / SCRIPT).read_text()
        base = os.environ.get("PW2_UPSTREAM_REF", "origin/main")
        cls.upstream = subprocess.run(["git", "-C", str(ROOT), "show", f"{base}:{SCRIPT}"], capture_output=True, text=True, check=True).stdout

    def load(self, text, variant, acl, extra_steps=(), order=("own", "lan")):
        env = environment(variant, acl, order)
        netns = Netns(text, env)
        self.addCleanup(netns.close)
        steps = list(WHITE_SETS) + acl_setup(variant, acl) + [
            "set -- start", ". ./nftables.sh",
            "nft -j list table inet passwall2 > $TEST_ROOT/start.json",
        ] + list(extra_steps)
        netns.run(steps, BASE_DB.format(icmp=variant["ICMP"], local=variant["LOCALHOST_PROXY"]))
        return netns

    def test_equivalent_to_upstream(self):
        for variant in VARIANTS:
            for acl in (False, True):
                with self.subTest(variant=variant, acl=acl):
                    upstream = upstream_flat(self.load(self.upstream, variant, acl).dump("start.json"))
                    dump = self.load(self.new, variant, acl).dump("start.json")
                    flat = flatten(dump)
                    self.assertEqual(sorted(flat), sorted(name for name in upstream))
                    for name in upstream:
                        self.assertEqual(flat[name], upstream[name], name)
                    self.assertIn("psw2_shunt1_rproxy", sets(dump))

    def test_default_entry_keeps_global_lists_after_other_acl(self):
        # 上游按“节点是否已生成过列表”跳过计算，变量沿用上一条目：
        # 跟随全局的条目在前、独立节点条目在后时，默认条目会错误地使用后者（shunt2）的分流列表。
        variant = {"TCP_PROXY_WAY": "redirect", "PROXY_IPV6": "0", "ICMP": "0", "LOCALHOST_PROXY": "0"}
        order = ("lan", "own")
        upstream = upstream_flat(self.load(self.upstream, variant, True, order=order).dump("start.json"))
        flat = flatten(self.load(self.new, variant, True, order=order).dump("start.json"))

        def default_sets(rules):
            names = set()
            for rule in rules:
                text = json.dumps(rule)
                if '"saddr"' not in text and '"ether"' not in text:
                    names.update(part.split('"')[0] for part in text.split('"@')[1:])
            return names

        self.assertTrue({"psw2_shunt2_rproxy"} & default_sets(upstream["PSW2_NAT"]))
        self.assertFalse(any(name.startswith("psw2_shunt2") for name in default_sets(flat["PSW2_NAT"])))
        self.assertIn("psw2_shunt1_rproxy", default_sets(flat["PSW2_NAT"]))

    def test_switch_replaces_only_sub_chains(self):
        variant = {"TCP_PROXY_WAY": "redirect", "PROXY_IPV6": "1", "ICMP": "1", "LOCALHOST_PROXY": "1"}
        switch = [
            f"busybox sh ./nftables.sh shunt_switch n1 {REDIR_PORT}", "nft -j list table inet passwall2 > $TEST_ROOT/n1.json",
            f"busybox sh ./nftables.sh shunt_switch shunt2 {REDIR_PORT}", "nft -j list table inet passwall2 > $TEST_ROOT/shunt2.json",
            f"busybox sh ./nftables.sh shunt_switch shunt1 {REDIR_PORT}", "nft -j list table inet passwall2 > $TEST_ROOT/back.json",
            "busybox sh ./nftables.sh shunt_ready",
            "set -- stop", "( . ./nftables.sh )", "nft -j list table inet passwall2 > $TEST_ROOT/stopped.json",
        ]
        netns = self.load(self.new, variant, True, switch)
        start, normal, other, back = (chains(netns.dump(name)) for name in ("start.json", "n1.json", "shunt2.json", "back.json"))

        def strip(table):
            return {name: [[e for e in expr if not is_counter(e)] for expr in rules] for name, rules in table.items() if name not in SHUNT_CHAINS}

        # 默认条目必须真的跳转到子链，主链里不再直接引用全局节点的分流集合（独立实例 own 仍用 shunt2 的静态规则）。
        main_text = json.dumps(strip(start))
        for chain in ("PSW2_SHUNT_NAT", "PSW2_SHUNT_MARK", "PSW2_SHUNT_MARK6", "PSW2_SHUNT_ICMP", "PSW2_SHUNT_ICMP6"):
            self.assertIn(f'"target": "{chain}"', main_text, chain)
        self.assertNotIn("psw2_shunt1_", main_text)
        self.assertIn("psw2_shunt2_", main_text)
        for table in (normal, other, back):
            self.assertEqual(strip(table), strip(start))
        for name in SHUNT_CHAINS:
            self.assertEqual(normal[name], [], name)
            self.assertEqual(strip({"x": back[name]}), strip({"x": start[name]}), name)
        text = json.dumps(start["PSW2_SHUNT_NAT"])
        self.assertIn("psw2_shunt1_rproxy", text)
        self.assertIn("psw2_shunt1_white", text)
        other_text = json.dumps(other)
        self.assertIn("psw2_shunt2_rdirect", other_text)
        self.assertNotIn("psw2_shunt1_", json.dumps({name: other[name] for name in SHUNT_CHAINS}))
        # shunt2 的 rproxy 直连、rdirect 走代理，默认直连：动作必须随分类改变。
        nat = [[e for e in expr if not is_counter(e)] for expr in other["PSW2_SHUNT_NAT"]]
        verdicts = {json.dumps(expr[-2]): expr[-1] for expr in nat}
        self.assertEqual(verdicts[json.dumps({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "@psw2_shunt2_rproxy"}})], {"accept": None})
        self.assertIn("redirect", verdicts[json.dumps({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "@psw2_shunt2_rdirect"}})])
        stopped = chains(netns.dump("stopped.json"))
        self.assertFalse([name for name in stopped if name.startswith("PSW2_")], stopped)
        include = (netns.root / "tmp/etc/passwall2/PSW2_RULE.nft").read_text()
        self.assertIn("psw2_shunt1_rproxy", include)

    def test_refresh_rebuilds_rule_sets_in_one_transaction(self):
        variant = {"TCP_PROXY_WAY": "tproxy", "PROXY_IPV6": "1", "ICMP": "1", "LOCALHOST_PROXY": "1"}
        stale = [
            "nft add element inet passwall2 psw2_shunt1_rproxy '{ 203.0.113.0/24 }'",
            "nft add element inet passwall2 psw2_shunt2_rproxy '{ 203.0.113.0/24 }'",
            "nft add element inet passwall2 psw2_shunt1_white '{ 198.18.0.9 }'",
            "nft add element inet passwall2 psw2_direct '{ 203.0.114.1 }'",
            "nft add element inet passwall2 psw2_vps '{ 192.0.2.99 }'",
            "nft -j list table inet passwall2 > $TEST_ROOT/stale.json",
        ]
        refresh = [
            "sed -i 's#9.9.9.0/24#9.9.40.0/24#' $FAKE_UCI_DB",
            f"GEO_VERSION=2 busybox sh ./nftables.sh refresh_sets shunt1 {REDIR_PORT} 1; echo $? > $TEST_ROOT/status",
            "nft -j list table inet passwall2 > $TEST_ROOT/refreshed.json",
            # 非法地址让事务失败：集合与子链必须保持原样。
            "sed -i 's#9.9.40.0/24#300.9.40.0/24#' $FAKE_UCI_DB",
            "nft add element inet passwall2 psw2_shunt1_white '{ 198.18.0.10 }'",
            "nft -j list table inet passwall2 > $TEST_ROOT/before_fail.json",
            f"busybox sh ./nftables.sh refresh_sets n1 {REDIR_PORT} 0; echo $? > $TEST_ROOT/fail_status",
            "nft -j list table inet passwall2 > $TEST_ROOT/after_fail.json",
        ]
        netns = self.load(self.new, variant, True, stale + refresh)
        self.assertEqual((netns.root / "status").read_text().strip(), "0", (netns.root / "passwall2.log").read_text() if (netns.root / "passwall2.log").exists() else "")

        def elements(dump, name):
            for item in dump["nftables"]:
                if "set" in item and item["set"]["name"] == name:
                    return json.dumps(item["set"].get("elem", []))
            raise AssertionError(name)

        def strip(table, keep_sub=False):
            return {name: [[e for e in expr if not is_counter(e)] for expr in rules] for name, rules in table.items()
                    if keep_sub or name not in SHUNT_CHAINS}

        start, refreshed = netns.dump("start.json"), netns.dump("refreshed.json")
        # 主链与子链都不变（同一全局节点、同样的集合名）。
        self.assertEqual(strip(chains(refreshed), True), strip(chains(start), True))
        for name in ("psw2_shunt1_rproxy", "psw2_shunt2_rproxy"):
            text = elements(refreshed, name)
            self.assertIn("9.9.40.0", text, name)
            self.assertIn("9.9.3.0", text, name)
            self.assertNotIn("9.9.9.0", text, name)
            self.assertNotIn("9.9.8.0", text, name)
            self.assertNotIn("203.0.113.0", text, name)
        self.assertIn("2001:db8:8::", elements(refreshed, "psw2_shunt1_rproxy6"))
        self.assertNotIn("198.18.0.9", elements(refreshed, "psw2_shunt1_white"))
        self.assertNotIn("203.0.114.1", elements(refreshed, "psw2_direct"))
        self.assertIn("192.0.2.99", elements(refreshed, "psw2_vps"), "psw2_vps 只补充不清空")
        script = (netns.root / "tmp/etc/passwall2/refresh_sets.nft").read_text()
        self.assertIn("flush set inet passwall2 psw2_shunt2_rproxy", script)
        self.assertIn("flush chain inet passwall2 PSW2_SHUNT_MARK", script)
        include = (netns.root / "tmp/etc/passwall2/PSW2_RULE.nft").read_text()
        self.assertIn("9.9.40.0", include)

        self.assertEqual((netns.root / "fail_status").read_text().strip(), "1")
        before, after = netns.dump("before_fail.json"), netns.dump("after_fail.json")
        self.assertEqual(strip(chains(after), True), strip(chains(before), True))
        for name in ("psw2_shunt1_rproxy", "psw2_shunt1_white", "psw2_direct"):
            self.assertEqual(elements(after, name), elements(before, name), name)

    def test_packets_follow_shunt_classification(self):
        # 报文级验证（本机代理、重定向模式）：代理端口与直连端口各有监听，连接结果说明 nat 输出链的实际走向，
        # 验证子链中的 accept 与上游主链中的 return 等价。9.9.9.1 在代理集合，9.9.6.1 在直连集合，9.9.5.1 属于默认（走代理），
        # 1.2.3.4 不在集合内由兜底代理，8080 不在代理端口内保持直连；热切换到普通节点后直连集合不再生效，切回后恢复。
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
            steps = list(WHITE_SETS) + acl_setup(variant, False) + network + [
                "set -- start", ". ./nftables.sh >/dev/null 2>&1",
                f"python3 $TEST_ROOT/probe.py {targets} > $TEST_ROOT/probe.start",
            ] + extra + ["kill $(cat $TEST_ROOT/server.pid) 2>/dev/null; true"]
            netns.run(steps, BASE_DB.format(icmp="0", local="1"))
            return netns

        expected = "9.9.9.1:80=proxy 9.9.6.1:80=direct 9.9.5.1:80=proxy 1.2.3.4:80=proxy 1.2.3.4:8080=direct"
        upstream = run(self.upstream, [])
        self.assertEqual((upstream.root / "probe.start").read_text().strip(), expected, "上游脚本的基准行为")
        new = run(self.new, [
            f"busybox sh ./nftables.sh shunt_switch n1 {REDIR_PORT} >/dev/null 2>&1",
            f"python3 $TEST_ROOT/probe.py {targets} > $TEST_ROOT/probe.n1",
            f"busybox sh ./nftables.sh shunt_switch shunt1 {REDIR_PORT} >/dev/null 2>&1",
            f"python3 $TEST_ROOT/probe.py {targets} > $TEST_ROOT/probe.back",
        ])
        self.assertEqual((new.root / "probe.start").read_text().strip(), expected)
        self.assertEqual((new.root / "probe.n1").read_text().strip(), expected.replace("9.9.6.1:80=direct", "9.9.6.1:80=proxy"))
        self.assertEqual((new.root / "probe.back").read_text().strip(), expected)

    def test_switch_refuses_without_sub_chains(self):
        # 升级前由旧脚本加载的规则没有子链：shunt_switch 必须返回 2，让 reload 走完整重启。
        variant = {"TCP_PROXY_WAY": "redirect", "PROXY_IPV6": "0", "ICMP": "0", "LOCALHOST_PROXY": "1"}
        netns = Netns(self.new, environment(variant, False))
        self.addCleanup(netns.close)
        (netns.work / "upstream.sh").write_text(self.upstream)
        netns.run(WHITE_SETS + acl_setup(variant, False) + [
            "set -- start", ". ./upstream.sh",
            "nft -j list table inet passwall2 > $TEST_ROOT/before.json",
            f"busybox sh ./nftables.sh shunt_switch n1 {REDIR_PORT}; echo $? > $TEST_ROOT/status",
            "nft -j list table inet passwall2 > $TEST_ROOT/after.json",
        ], BASE_DB.format(icmp="0", local="1"))
        self.assertEqual((netns.root / "status").read_text().strip(), "2")
        self.assertEqual(upstream_flat(netns.dump("after.json")), upstream_flat(netns.dump("before.json")))

if __name__ == "__main__":
    unittest.main(verbosity=2)
