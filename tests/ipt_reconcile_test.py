#!/usr/bin/env python3
"""差量热重载的 iptables 后端：在 sudo 创建的独立网络命名空间中验证，不触碰本机防火墙。

先按配置 A 正常加载规则（iptables.sh 同时记录规则配方 ipt.log），再按配置 B 做影子启动（命令只记录，-L 查询由
reconcile.lua 模拟），由模拟重放得到目标规则，生成 ipset 计划与按表原子提交的 iptables-restore --noflush 输入；
提交后的规则与集合必须与直接按 B 启动一致，配置不变时判定为无变化。需要 iptables-legacy 与 ipset（见 ipt_shunt_test）。
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import ipt_shunt_test as ipt
import nft_reconcile_test as nr

ROOT = nr.ROOT
SCRIPT = ipt.SCRIPT
RECONCILE = ROOT / "luci-app-passwall2/luasrc/passwall2/reconcile.lua"

DRIVER = r"""
local root, module = arg[1], arg[2]
local R = dofile(module)
local function read(path) local f = io.open(path) if not f then return "" end local s = f:read("*a") f:close() return s end
local function write(path, text) local f = assert(io.open(path, "w")) f:write(text) f:close() end
local base = {}
for _, family in ipairs({ "4", "6" }) do
	for name, model in pairs(R.ipt_strip(R.ipt_parse_save(read(root .. "/stage/ipt_snapshot_" .. family)))) do base[family .. " " .. name] = model end
end
local stage_entries = R.ipt_log(read(root .. "/stage/ipt.log"))
local desired = R.ipt_replay(base, stage_entries)
local current = R.ipt_replay(base, R.ipt_log(read(root .. "/tmp/etc/passwall2/ipt.log")))
write(root .. "/summary.txt", R.ipt_equal(desired, current) and "same\n" or "changed\n")
for _, family in ipairs({ "4", "6" }) do
	write(root .. "/restore" .. family .. ".txt", R.ipt_restore_script(desired, R.ipt_parse_save(read(root .. "/current" .. family .. ".save")), family) or "")
end
local preserved = {}
for name in read(root .. "/stage/preserved_sets"):gmatch("%S+") do preserved[name] = true end
local plan = R.ipset_plan(R.ipset_model(stage_entries), R.ipset_parse_list(read(root .. "/current.ipset")),
	{ preserved = preserved, referenced = R.ipt_referenced_sets(desired) })
local pre, post = {}, {}
for _, item in ipairs(plan.create) do
	pre[#pre + 1] = "ipset -! create " .. item.name .. " " .. item.spec
	for _, element in ipairs(item.elements) do pre[#pre + 1] = "ipset -! add " .. item.name .. " " .. element end
end
for _, item in ipairs(plan.swap) do
	local tmp = R.ipset_temp_name(item.name)
	pre[#pre + 1] = "ipset -q destroy " .. tmp
	pre[#pre + 1] = "ipset create " .. tmp .. " " .. item.spec
	for _, element in ipairs(item.elements) do pre[#pre + 1] = "ipset -! add " .. tmp .. " " .. element end
	pre[#pre + 1] = "ipset swap " .. tmp .. " " .. item.name
	pre[#pre + 1] = "ipset destroy " .. tmp
end
for _, item in ipairs(plan.add) do
	for _, element in ipairs(item.elements) do pre[#pre + 1] = "ipset -! add " .. item.name .. " " .. element end
end
for _, name in ipairs(plan.obsolete) do post[#post + 1] = "ipset destroy " .. name end
write(root .. "/ipset_pre.sh", table.concat(pre, "\n") .. "\n")
write(root .. "/ipset_post.sh", table.concat(post, "\n") .. "\n")
"""


class Namespace(nr.Namespace):
    def __init__(self):
        super().__init__()
        (self.work / "nftables.sh").unlink()
        (self.work / "iptables.sh").write_text((ROOT / SCRIPT).read_text())
        for name, text in (("ipset", ipt.IPSET_WRAPPER), ("lsmod", ipt.FAKE_LSMOD)):
            tool = self.work / "bin" / name
            tool.write_text(text)
            tool.chmod(0o755)
        (self.root / "driver.lua").write_text(DRIVER)


def env_lines(v):
    env = ipt.environment(v, v["ACL"])
    env.update({"NODE": v["NODE"], "RETURN_DNS": v["RETURN_DNS"]})
    return [f"export {key}='{value}'" for key, value in env.items()]


def setup_lines(v):
    steps = nr.setup_lines(v)
    return list(ipt.WHITE_SETS) + [step for step in steps if step not in nr.base.WHITE_SETS]


def start_steps(v, db):
    return ["("] + env_lines(v) + [f"export FAKE_UCI_DB=$TEST_ROOT/{db}", ". ./utils.sh", "mkdir -p $TMP_PATH $TMP_ACL_PATH $LOCK_PATH"] + \
        setup_lines(v) + ["set -- start", ". ./iptables.sh", ")"]


def stage_steps(v):
    return ["(", f"export PW2_STAGE=1 PW2_TMP_PATH=$TEST_ROOT/stage PW2_RECONCILE_LUA={RECONCILE}"] + env_lines(v) + \
        ["export FAKE_UCI_DB=$TEST_ROOT/uci_b.db", ". ./utils.sh", "mkdir -p $TMP_PATH $TMP_ACL_PATH $LOCK_PATH"] + \
        setup_lines(v) + ["set -- start", ". ./iptables.sh", ")"]


# 与执行器一致：完整启动时会失败的单条命令（上游在端口为空、IPv4 来源写进 ip6tables 等情形下生成）
# 在 restore 中按出错行删除后重试，结果与逐条执行时失败被跳过相同。
APPLY_RESTORE = r"""apply_restore() {
	[ -s "$2" ] || return 0
	for i in $(seq 1 50); do
		out=$($1 --noflush < "$2" 2>&1) && return 0
		line=$(echo "$out" | sed -n 's/.*Error occurred at line: \([0-9]*\).*/\1/p')
		[ -n "$line" ] || { echo "$out" >&2; return 1; }
		sed -n "${line}p" "$2" >> "$2.dropped"
		sed -i "${line}d" "$2"
	done
	return 1
}"""

DUMP = "iptables-legacy-save > $TEST_ROOT/{name}.v4; ip6tables-legacy-save > $TEST_ROOT/{name}.v6; ipset list > $TEST_ROOT/{name}.ipset"


def parse_ipset(text):
    """ipset list → {集合: 排序后的元素}；元素去掉 timeout 等附加字段（剩余寿命随时间变化）。"""
    sets, name, members = {}, None, False
    for line in text.splitlines():
        if line.startswith("Name: "):
            name, members = line[6:].strip(), False
            sets[name] = []
        elif line.startswith("Members:"):
            members = True
        elif not line.strip():
            members = False
        elif members and name:
            element = line.split()[0]
            sets[name].append(element[:-3] if element.endswith("/32") else element)
    return {key: sorted(value) for key, value in sets.items()}


def state(ns, name):
    tables = {"v4": ipt.parse((ns.root / f"{name}.v4").read_text()), "v6": ipt.parse((ns.root / f"{name}.v6").read_text())}
    return tables, parse_ipset((ns.root / f"{name}.ipset").read_text())


@unittest.skipUnless(ipt.available() and subprocess.run(["which", "lua"], capture_output=True).returncode == 0,
                     "需要 iptables-legacy、ipset、busybox、lua 与免密 sudo（只在独立网络命名空间内操作）")
class IptablesReconcileTest(unittest.TestCase):
    def reconcile(self, a, b):
        ns = Namespace()
        self.addCleanup(ns.close)
        (ns.root / "uci_a.db").write_text(nr.uci_db(a))
        (ns.root / "uci_b.db").write_text(nr.uci_db(b))
        steps = start_steps(a, "uci_a.db") + [
            DUMP.format(name="before"),
            "mkdir -p $TEST_ROOT/stage",
            "iptables-legacy-save > $TEST_ROOT/stage/ipt_snapshot_4; ip6tables-legacy-save > $TEST_ROOT/stage/ipt_snapshot_6",
        ] + stage_steps(b) + [
            DUMP.format(name="staged"),
            "iptables-legacy-save > $TEST_ROOT/current4.save; ip6tables-legacy-save > $TEST_ROOT/current6.save; ipset list > $TEST_ROOT/current.ipset",
            f"lua $TEST_ROOT/driver.lua $TEST_ROOT {RECONCILE}",
            "sh $TEST_ROOT/ipset_pre.sh",
            APPLY_RESTORE,
            "apply_restore iptables-legacy-restore $TEST_ROOT/restore4.txt || exit 1",
            "apply_restore ip6tables-legacy-restore $TEST_ROOT/restore6.txt || exit 1",
            "sh $TEST_ROOT/ipset_post.sh",
            DUMP.format(name="reconciled"),
        ]
        ns.run(steps)
        return ns

    def fresh(self, b):
        ns = Namespace()
        self.addCleanup(ns.close)
        (ns.root / "uci_a.db").write_text(nr.uci_db(b))
        ns.run(start_steps(b, "uci_a.db") + [DUMP.format(name="fresh")])
        return ns

    def assert_same(self, got, want):
        got_tables, got_sets = got
        want_tables, want_sets = want
        self.assertEqual(got_tables, want_tables)
        self.assertEqual(sorted(got_sets), sorted(want_sets))
        for name, members in want_sets.items():
            if not name.startswith("psw2_vps") and not name.endswith(("_white", "_white6")):
                self.assertEqual(got_sets[name], members, name)

    def test_reconcile_matches_fresh_start(self):
        for title, a, b in nr.PAIRS:
            with self.subTest(title):
                ns = self.reconcile(a, b)
                self.assertEqual((ns.root / "summary.txt").read_text().strip(), "changed", title)
                self.assert_same(state(ns, "reconciled"), state(self.fresh(b), "fresh"))

    def test_unchanged_config_is_noop_and_stage_is_inert(self):
        for title, a, _ in nr.PAIRS[:3] + nr.PAIRS[6:7]:
            with self.subTest(title):
                ns = self.reconcile(a, a)
                self.assertEqual((ns.root / "summary.txt").read_text().strip(), "same", title)
                # 影子启动没有改动系统中的规则与集合。
                self.assertEqual(state(ns, "staged"), state(ns, "before"))
                self.assert_same(state(ns, "reconciled"), state(ns, "before"))


if __name__ == "__main__":
    unittest.main()
