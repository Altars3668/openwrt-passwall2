-- 差量热重载纯逻辑（reconcile.lua）的单元测试：lua tests/reconcile_logic_test.lua <仓库根目录>
local R = dofile(arg[1] .. "/luci-app-passwall2/luasrc/passwall2/reconcile.lua")
local passed = 0
local function check(name, fn)
	local ok, err = pcall(fn)
	if not ok then error(name .. ": " .. tostring(err)) end
	passed = passed + 1
end
local function eq(a, b, message)
	if a ~= b then error((message or "") .. "\n期望：" .. tostring(b) .. "\n实际：" .. tostring(a), 2) end
end

check("路径改写：长前缀优先，JSON 转义写法同样改写", function()
	local rewrite = R.rewriter({ ["/tmp/etc/passwall2/reload/stage/dnsmasq_cache"] = "/tmp/etc/passwall2_tmp",
		["/tmp/etc/passwall2/reload/stage"] = "/tmp/etc/passwall2" })
	eq(rewrite("conf-dir=/tmp/etc/passwall2/reload/stage/acl/x.d"), "conf-dir=/tmp/etc/passwall2/acl/x.d")
	eq(rewrite("servers-file=/tmp/etc/passwall2/reload/stage/dnsmasq_cache/dnsmasq_a.servers"), "servers-file=/tmp/etc/passwall2_tmp/dnsmasq_a.servers")
	eq(rewrite([["output":"\/tmp\/etc\/passwall2\/reload\/stage\/acl\/a.log"]]), [["output":"\/tmp\/etc\/passwall2\/acl\/a.log"]])
	eq(rewrite("100%"), "100%")
	local value = R.rewrite_value({ config_file = "/tmp/etc/passwall2/reload/stage/acl/a.json", args = { n = 1 } }, rewrite)
	eq(value.config_file, "/tmp/etc/passwall2/acl/a.json")
	eq(value.args.n, 1)
end)

local LISTING = [[
table inet passwall2_stage {
	set psw2_local {
		type ipv4_addr
		flags interval,timeout
		auto-merge
		elements = { 127.0.0.1, 192.168.1.1,
			     198.51.100.0/24 timeout 365d expires 364d23h59m }
	}
	set psw2_vps {
		type ipv4_addr
		flags interval,timeout
		auto-merge
	}
	chain dstnat {
		ip saddr @psw2_local jump PSW2_DNS
	}
	chain PSW2_DNS {
		meta l4proto udp udp dport 53 counter packets 3 bytes 120 redirect to :2005 comment "LAN {guest}"
		tcp dport { 22, 80,
			443 } counter packets 0 bytes 0 return
	}
}
]]

check("解析规则集：集合元素跨行、链规则含匿名集合与引号中的花括号", function()
	local model = R.parse_nft(LISTING)
	eq(table.concat(model.set_order, ","), "psw2_local,psw2_vps")
	eq(#model.sets.psw2_local.elements, 3)
	eq(R.element_key(model.sets.psw2_local.elements[3]), "198.51.100.0/24 timeout 365d")
	eq(table.concat(model.sets.psw2_local.lines, ";"), "type ipv4_addr;flags interval,timeout;auto-merge")
	eq(#model.sets.psw2_vps.elements, 0)
	eq(table.concat(model.chain_order, ","), "dstnat,PSW2_DNS")
	eq(#model.chains.PSW2_DNS.rules, 2)
	eq(R.rule_key(model.chains.PSW2_DNS.rules[1]), [[meta l4proto udp udp dport 53 counter redirect to :2005 comment "LAN {guest}"]])
	eq(model.chains.PSW2_DNS.rules[2], "tcp dport { 22, 80, 443 } counter packets 0 bytes 0 return")
end)

local CURRENT = [[
table inet passwall2 {
	set psw2_local {
		type ipv4_addr
		flags interval,timeout
		auto-merge
		elements = { 127.0.0.1, 192.168.1.1 }
	}
	set psw2_vps {
		type ipv4_addr
		flags interval,timeout
		auto-merge
		elements = { 192.0.2.10 }
	}
	set psw2_old {
		type ipv4_addr
		flags interval
	}
	chain dstnat {
		type nat hook prerouting priority dstnat - 1; policy accept;
		ip saddr @psw2_local jump PSW2_DNS
	}
	chain PSW2_DNS {
		meta l4proto udp udp dport 53 counter packets 9 bytes 300 redirect to :2001 comment "LAN {guest}"
	}
	chain PSW2_GONE {
		counter return
	}
}
]]

check("提交事务：补齐集合与链、刷新内容变化的集合、整链重填、删除旧链并报告旧集合", function()
	local script, summary = R.nft_commit(R.parse_nft(LISTING), R.parse_nft(CURRENT), {
		table = "inet passwall2", base = { dstnat = "type nat hook prerouting priority dstnat - 1; policy accept;" } })
	assert(script, summary)
	local lines = {}
	for line in script:gmatch("[^\n]+") do lines[#lines + 1] = line end
	eq(lines[1], "add table inet passwall2")
	eq(lines[2], "flush set inet passwall2 psw2_local")
	eq(lines[3], "add element inet passwall2 psw2_local { 127.0.0.1, 192.168.1.1, 198.51.100.0/24 timeout 365d }")
	eq(lines[4], "add chain inet passwall2 dstnat { type nat hook prerouting priority dstnat - 1; policy accept; }")
	eq(lines[5], "add chain inet passwall2 PSW2_DNS")
	eq(lines[6], "flush chain inet passwall2 dstnat")
	eq(lines[8], "flush chain inet passwall2 PSW2_GONE")
	eq(lines[9], "add rule inet passwall2 dstnat ip saddr @psw2_local jump PSW2_DNS")
	eq(lines[10], [[add rule inet passwall2 PSW2_DNS meta l4proto udp udp dport 53 counter redirect to :2005 comment "LAN {guest}"]])
	eq(lines[#lines], "delete chain inet passwall2 PSW2_GONE")
	eq(table.concat(summary.sets_obsolete, ","), "psw2_old")
	eq(table.concat(summary.sets_refreshed, ","), "psw2_local")
	eq(summary.changed, true)
	-- psw2_vps 只补充：目标为空时不清空运行中由 DNS 写入的地址。
	assert(not script:find("psw2_vps"), script)
end)

check("提交事务：配置相同判定为无变化，新表从零创建", function()
	local current = R.parse_nft(CURRENT:gsub("redirect to :2001", "redirect to :2005"):gsub("\t\tcounter return\n", ""))
	current.chains.PSW2_GONE = nil
	current.chain_order = { "dstnat", "PSW2_DNS" }
	local desired = R.parse_nft(CURRENT:gsub("redirect to :2001", "redirect to :2005"))
	desired.chains.PSW2_GONE = nil
	desired.chain_order = { "dstnat", "PSW2_DNS" }
	local _, summary = R.nft_commit(desired, current, { table = "inet passwall2" })
	eq(summary.changed, false)
	local script = R.nft_commit(R.parse_nft(LISTING), nil, { table = "inet passwall2", base = {} })
	assert(script:find("add set inet passwall2 psw2_vps { type ipv4_addr; flags interval,timeout; auto-merge }", 1, true), script)
	assert(script:find("add set inet passwall2 psw2_local", 1, true), script)
end)

check("集合分类：直连写集合与沿用集合不动，vps/wan 只补充，flush 指定的集合刷新", function()
	eq(R.set_class("psw2_myshunt_white"), "keep")
	eq(R.set_class("psw2_myshunt_white6"), "keep")
	eq(R.set_class("psw2_myshunt_China", { preserved = { psw2_myshunt_China = true } }), "keep")
	eq(R.set_class("psw2_vps6"), "union")
	eq(R.set_class("psw2_direct"), "refresh")
	eq(R.set_class("psw2_myshunt_white", { flush = { psw2_myshunt_white = true } }), "refresh")
	local _, err = R.nft_commit(R.parse_nft(LISTING), R.parse_nft((LISTING:gsub("\t\tauto%-merge\n\t}", "\t}", 1))), { table = "inet passwall2" })
	assert(type(err) == "string" and err:find("psw2_vps"), err)
end)

check("进程登记解析与匹配：按配置路径对应，命令或内容变化判为变更", function()
	local p = R.parse_command("/tmp/etc/passwall2/bin/sing-box run -c /tmp/etc/passwall2/acl/a.json >/tmp/etc/passwall2/acl/a.log")
	eq(p.name, "sing-box")
	eq(p.config, "/tmp/etc/passwall2/acl/a.json")
	eq(p.output, "/tmp/etc/passwall2/acl/a.log")
	local d = R.parse_command("/tmp/etc/passwall2/bin/dnsmasq_acl_default -C /tmp/etc/passwall2/acl/acl_default_dnsmasq.conf -x /tmp/etc/passwall2/acl/p.pid >/dev/null")
	eq(d.config, "/tmp/etc/passwall2/acl/acl_default_dnsmasq.conf")
	local h = R.parse_command("/tmp/etc/passwall2/bin/haproxy -f /tmp/etc/passwall2/haproxy/config.cfg >/dev/null")
	eq(h.key, "/tmp/etc/passwall2/haproxy/config.cfg")
	local plain = R.parse_command("/usr/bin/foo --bar")
	eq(plain.key, "/usr/bin/foo --bar")
	eq(plain.output, "/dev/null")
	local desired = { p, d, R.parse_command("/tmp/etc/passwall2/bin/sing-box run -c /tmp/etc/passwall2/acl/b.json >/dev/null") }
	local current = { R.parse_command("/tmp/etc/passwall2/bin/sing-box run -c /tmp/etc/passwall2/acl/a.json >/dev/null"), d,
		R.parse_command("/tmp/etc/passwall2/bin/sslocal -c /tmp/etc/passwall2/nodesocks_n_2010.json -v >/dev/null") }
	local plan = R.process_plan(desired, current, function(proc) return proc.command end)
	eq(#plan.start, 1)
	eq(plan.start[1].config, "/tmp/etc/passwall2/acl/b.json")
	eq(#plan.change, 1)
	eq(#plan.keep, 1)
	eq(#plan.stop, 1)
	eq(plan.stop[1].name, "sslocal")
end)

check("var 与稳定分配的解析和写回", function()
	local values, order = R.parse_var('A="1"\nB="x y"\nA="2"\nbad line\n')
	eq(values.A, "2")
	eq(values.B, "x y")
	eq(table.concat(order, ","), "A,B")
	values.C = "3"
	eq(R.format_var(values, order), 'A="2"\nB="x y"\nC="3"\n')
	local stable = R.parse_pairs("acl_default:redir 2002\nacl_default:secret abc\n")
	eq(stable["acl_default:redir"], "2002")
	local env = R.parse_pairs("USE_TABLES=nftables\nNODE=\n", "=")
	eq(env.USE_TABLES, "nftables")
	eq(env.NODE, "")
end)

local SAVE = [[
# Generated by iptables-save
*nat
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:prerouting_rule - [0:0]
:PSW2 - [0:0]
:PSW2_OLD - [0:0]
-A PREROUTING -j prerouting_rule
-A PREROUTING -m set ! --match-set psw2_direct dst -p tcp -j PSW2
-A PREROUTING -j zone_lan_prerouting
-A PSW2 -j RETURN
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A PREROUTING -j mwan3_hook
COMMIT
]]

local function log(lines)
	local out = {}
	for _, line in ipairs(lines) do
		if type(line) == "table" then out[#out + 1] = table.concat(line, "\031") else out[#out + 1] = line end
	end
	return table.concat(out, "\n") .. "\n"
end

check("iptables 模拟：去掉 passwall2 规则后重放配方，查询与 iptables -L 一样带序号", function()
	local tables = R.ipt_strip(R.ipt_parse_save(SAVE))
	assert(not tables.nat.chains.PSW2 and not tables.nat.chains.PSW2_OLD)
	eq(#tables.nat.chains.PREROUTING, 2)
	local base = { ["4 nat"] = tables.nat, ["4 mangle"] = tables.mangle }
	local entries = R.ipt_log(log({
		{ "C", "4", "nat", "-N", "PSW2" },
		{ "C", "4", "nat", "-A", "PSW2", "-m", "set", "--match-set", "psw2_vps", "dst", "-j", "RETURN" },
		{ "C", "4", "nat", "-I", "PREROUTING", "2", "-p", "tcp", "-j", "PSW2" },
		{ "C", "4", "mangle", "-N", "PSW2" },
		{ "C", "4", "mangle", "-I", "PREROUTING", "1", "-j", "PSW2" },
		{ "R", "4" }, "*nat", ":PSW2_SHUNT_NAT - [0:0]", "-A PSW2_SHUNT_NAT -m set --match-set psw2_x dst -j RETURN", "COMMIT", "\030",
		{ "S", "-!", "create", "psw2_x", "nethash", "maxelem", "1048576" },
		{ "S", "-!", "-R" }, "add psw2_x 9.9.9.0/24", "add psw2_x 9.9.8.1/32", "COMMIT", "\030",
	}))
	local models = R.ipt_replay(base, entries)
	eq(table.concat(models["4 nat"].chains.PREROUTING, " | "), "-j prerouting_rule | -p tcp -j PSW2 | -j zone_lan_prerouting")
	eq(#models["4 nat"].chains.PSW2_SHUNT_NAT, 1)
	local listing = R.ipt_list(models, "4", "nat", { "-n", "-L", "PREROUTING", "--line-numbers" })
	assert(listing:find("\n3    %-j zone_lan_prerouting\n"), listing)
	eq(R.ipt_list(models, "4", "nat", { "-n", "-L", "PSW2_MISSING" }), nil)
	local ipset = R.ipset_model(entries)
	assert(ipset.sets.psw2_x.elements["9.9.9.0/24"] and ipset.sets.psw2_x.elements["9.9.8.1"])
	eq(ipset.sets.psw2_x.spec, "nethash maxelem 1048576")
	-- 与当前配方比较：相同为一致，多一条跳转即不一致。
	assert(R.ipt_equal(models, R.ipt_replay(base, entries)))
	local more = R.ipt_log(log({ { "C", "4", "mangle", "-I", "OUTPUT", "1", "-j", "PSW2" } }))
	for _, entry in ipairs(more) do entries[#entries + 1] = entry end
	assert(not R.ipt_equal(models, R.ipt_replay(base, entries)))
end)

check("iptables 提交：删除旧跳转、按目标位置插入新跳转、重填链并删除旧链", function()
	local tables = R.ipt_strip(R.ipt_parse_save(SAVE))
	local base = { ["4 nat"] = tables.nat, ["4 mangle"] = tables.mangle }
	local models = R.ipt_replay(base, R.ipt_log(log({
		{ "C", "4", "nat", "-N", "PSW2" },
		{ "C", "4", "nat", "-A", "PSW2", "-j", "RETURN" },
		{ "C", "4", "nat", "-I", "PREROUTING", "2", "-p", "udp", "-j", "PSW2" },
	})))
	local script = R.ipt_restore_script(models, R.ipt_parse_save(SAVE), "4")
	local lines = {}
	for line in script:gmatch("[^\n]+") do lines[#lines + 1] = line end
	eq(lines[1], "*nat")
	eq(lines[2], ":PSW2 - [0:0]")
	eq(lines[3], ":PSW2_OLD - [0:0]")
	eq(lines[4], "-D PREROUTING -m set ! --match-set psw2_direct dst -p tcp -j PSW2")
	eq(lines[5], "-I PREROUTING 2 -p udp -j PSW2")
	eq(lines[6], "-A PSW2 -j RETURN")
	eq(lines[7], "-X PSW2_OLD")
	eq(lines[8], "COMMIT")
	-- mangle 表没有 passwall2 规则，不输出。
	assert(not script:find("*mangle", 1, true), script)
	local referenced = R.ipt_referenced_sets(R.ipt_replay(base, R.ipt_log(log({
		{ "C", "4", "nat", "-N", "PSW2" }, { "C", "4", "nat", "-A", "PSW2", "-m", "set", "--match-set", "psw2_y", "dst", "-j", "RETURN" } }))))
	assert(referenced.psw2_y)
end)

check("ipset 计划：新建、内容替换、只补充、保留与可删除的集合", function()
	local current = R.ipset_parse_list([[
Name: psw2_direct
Type: hash:net
Members:
10.0.0.0/8
192.168.1.0/24

Name: psw2_vps
Type: hash:ip
Members:
192.0.2.10 timeout 3600

Name: psw2_old_rule
Type: hash:net
Members:

Name: psw2_myshunt_white
Type: hash:ip
Members:
198.51.100.9
]])
	assert(current.psw2_vps.members["192.0.2.10"], "元素应去掉 timeout")
	local desired = { order = { "psw2_direct", "psw2_vps", "psw2_new", "psw2_myshunt_white" }, sets = {
		psw2_direct = { spec = "nethash", elements = { ["10.0.0.0/8"] = true } },
		psw2_vps = { spec = "iphash", elements = { ["192.0.2.11"] = true } },
		psw2_new = { spec = "nethash", elements = { ["9.9.9.0/24"] = true } },
		psw2_myshunt_white = { spec = "iphash timeout 259200", elements = {} },
	} }
	local plan = R.ipset_plan(desired, current, {})
	eq(plan.create[1].name, "psw2_new")
	eq(plan.swap[1].name, "psw2_direct")
	eq(plan.add[1].name, "psw2_vps")
	eq(plan.add[1].elements[1], "192.0.2.11")
	eq(#plan.swap, 1, "直连写集合不能被替换")
	eq(table.concat(plan.obsolete, ","), "psw2_old_rule")
	plan = R.ipset_plan(desired, current, { referenced = { psw2_old_rule = true } })
	eq(#plan.obsolete, 0)
	local tmp = R.ipset_temp_name("psw2_myshunt_China6")
	assert(#tmp <= 31 and tmp:match("^psw2_r%x+$") and tmp == R.ipset_temp_name("psw2_myshunt_China6"), tmp)
end)

print("差量热重载逻辑测试通过：" .. passed .. "；失败：0")
