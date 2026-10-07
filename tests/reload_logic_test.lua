local reload = dofile(arg[1] .. "/luci-app-passwall2/luasrc/passwall2/reload.lua")
local passed = 0
local function check(name, fn)
	local ok, err = pcall(fn)
	if not ok then error(name .. ": " .. tostring(err)) end
	passed = passed + 1
end
local function section(name, kind, options) return {name = name, type = kind, options = options} end
local function baseline()
	return {passwall2 = {
		section("global", "global", {enabled = "1", node = "a", remote_dns = "1.1.1.1", timestamp = "1"}),
		section("a", "nodes", {type = "Xray", protocol = "vless", address = "192.0.2.1", port = "443", uuid = "test-a"}),
		section("b", "nodes", {type = "Xray", protocol = "vless", address = "192.0.2.2", port = "443", uuid = "test-b"}),
		section("rule", "shunt_rules", {domain_list = "domain:example.test"}),
	}, external = {
		dnsmasq = {name = "cfg01411c", options = {server = {"119.29.29.29"}, noresolv = "1", dns_redirect = "0"}},
		firewall = {type = "include", path = "/var/etc/passwall2.include"},
		resolv = {"2408:8888::8", "202.98.0.68"},
		tables = "nftables"
	}}
end
local function add_shunt(a, options)
	local shunt = {type = "Xray", protocol = "_shunt", default_node = "a", rule = "a"}
	for k, v in pairs(options or {}) do shunt[k] = v end
	a.passwall2[#a.passwall2 + 1] = section("shunt", "nodes", shunt)
	return #a.passwall2
end
local function add_acl(a, node)
	a.passwall2[1].options.acl_enable = "1"
	a.passwall2[#a.passwall2 + 1] = section("lan", "acl_rule", {enabled = "1", node = node, sources = "192.168.1.10"})
end
local function same(a, b) return reload.equal(reload.fingerprint(a), reload.fingerprint(b)) end

check("深复制与结构比较", function()
	local a = baseline()
	local b = reload.clone(a)
	assert(reload.equal(a, b))
	b.passwall2[2].options.uuid = "changed"
	assert(not reload.equal(a, b))
	assert(a.passwall2[2].options.uuid == "test-a")
end)
check("保存时间戳不重启", function()
	local a = baseline(); local b = reload.clone(a)
	b.passwall2[1].options.timestamp = "99"
	assert(same(a, b))
end)
check("节点认证与原生协议允许核心重载", function()
	local a = baseline(); local b = reload.clone(a)
	b.passwall2[2].options.uuid = "new-value"
	b.passwall2[2].options.protocol = "trojan"
	assert(same(a, b))
end)
check("同核心普通节点切换允许核心重载", function()
	local a = baseline(); local b = reload.clone(a)
	b.passwall2[1].options.node = "b"
	assert(same(a, b))
end)
check("远程 DNS 与缓存允许核心重载", function()
	local a = baseline(); local b = reload.clone(a)
	b.passwall2[1].options.remote_dns = "8.8.8.8"
	b.passwall2[1].options.dns_cache = "0"
	assert(same(a, b))
end)
check("节点地址、端口与链式代理变化交给执行器热更新", function()
	local a = baseline(); local b = reload.clone(a)
	b.passwall2[2].options.address = "node.example.test"
	b.passwall2[3].options.port = "8443"
	b.passwall2[2].options.chain_proxy = "1"
	b.passwall2[2].options.preproxy_node = "b"
	assert(same(a, b))
	local before, after = reload.node_endpoints(a), reload.node_endpoints(b)
	assert(before.a == "192.0.2.1||443" and after.a == "node.example.test||443" and after.b == "192.0.2.2||8443")
	assert(not reload.equal(before, after))
	b.passwall2[#b.passwall2 + 1] = section("ss", "nodes", {type = "SS-Rust", address = "192.0.2.9"})
	assert(reload.node_endpoints(b).ss == nil, "外部程序运行的节点整节比较")
	assert(not same(a, b))
end)
check("监听端口、ACL 与前置 DNS 变化回退", function()
	for _, key in ipairs({"node_socks_port", "acl_enable", "direct_dns", "direct_dns_shunt", "dns_redirect"}) do
		local a = baseline(); local b = reload.clone(a)
		b.passwall2[1].options[key] = "changed"
		assert(not same(a, b))
	end
end)
check("nftables 下全局节点在普通与分流节点之间切换无需完整重启", function()
	local a = baseline(); add_shunt(a, {write_ipset_direct = "1", enable_geoview_ip = "1"})
	local b = reload.clone(a); b.passwall2[1].options.node = "shunt"
	assert(same(a, b))
	local c = reload.clone(b); c.passwall2[1].options.node = "b"
	assert(same(b, c))
end)
check("跨核心切换全局节点交给执行器替换核心，无效节点仍完整重启", function()
	local a = baseline(); a.passwall2[3].options.type = "sing-box"
	local b = reload.clone(a); b.passwall2[1].options.node = "b"
	assert(same(a, b))
	b.passwall2[1].options.node = "missing"
	assert(not same(a, b))
end)
check("iptables 下全局分流节点同样由分流子链热切换", function()
	local a = baseline(); a.external.tables = "iptables"
	local index = add_shunt(a, {enable_geoview_ip = "1"})
	local b = reload.clone(a); b.passwall2[1].options.node = "shunt"
	assert(same(a, b))
	local c = reload.clone(b); c.passwall2[index].options.rule = "_direct"
	assert(same(b, c))
end)
check("nftables 下全局分流节点改直连／代理分类由子链替换处理", function()
	local a = baseline(); local index = add_shunt(a, {write_ipset_direct = "1"})
	a.passwall2[1].options.node = "shunt"
	local b = reload.clone(a); b.passwall2[index].options.rule = "_direct"
	assert(same(a, b))
	b.passwall2[index].options.default_node = "_direct"
	assert(same(a, b))
end)
check("ACL 跟随全局或使用无关节点时可切换全局节点", function()
	for _, node in ipairs({"default", "", "shunt"}) do
		local a = baseline(); add_shunt(a); add_acl(a, node)
		local b = reload.clone(a); b.passwall2[1].options.node = "b"
		assert(same(a, b), node)
	end
end)
check("ACL 指定节点等于新旧全局节点时仍是独立实例，可热切换全局节点", function()
	for _, node in ipairs({"a", "b"}) do
		local a = baseline(); add_acl(a, node)
		local b = reload.clone(a); b.passwall2[1].options.node = "b"
		assert(same(a, b), node)
	end
end)
check("ACL 规则本身变化仍回退", function()
	local a = baseline(); add_acl(a, "b")
	local b = reload.clone(a); b.passwall2[#b.passwall2].options.sources = "192.168.1.11"
	assert(not same(a, b))
end)
check("独立 ACL 实例的分流分类变化回退", function()
	local a = baseline(); local index = add_shunt(a, {enable_geoview_ip = "1"}); add_acl(a, "shunt")
	local b = reload.clone(a); b.passwall2[index].options.rule = "b"
	assert(same(a, b))
	b.passwall2[index].options.rule = "_direct"
	assert(not same(a, b))
end)
check("未开启 GeoIP 预加载时分类不进入防火墙", function()
	local a = baseline(); local index = add_shunt(a); add_acl(a, "shunt")
	local b = reload.clone(a); b.passwall2[index].options.rule = "_direct"
	assert(same(a, b))
	b.passwall2[index].options.enable_geoview_ip = "1"
	assert(not same(a, b))
end)
check("只有同组且已指定目标的规则进入分流签名", function()
	local a = baseline(); local index = add_shunt(a, {enable_geoview_ip = "1"}); add_acl(a, "shunt")
	local b = reload.clone(a)
	b.passwall2[#b.passwall2 + 1] = section("newrule", "shunt_rules", {domain_list = "domain:new.test"})
	assert(same(a, b), "新增但未指定目标的规则")
	b.passwall2[#b.passwall2 + 1] = section("other", "shunt_rules", {group = "g2", ip_list = "192.0.2.0/24"})
	b.passwall2[index].options.other = "_direct"
	assert(same(a, b), "其它分组的规则")
	b.passwall2[index].options.newrule = "_direct"
	assert(not same(a, b), "指定目标后生成新的集合")
end)
check("分流分类、直连写集合与出站网卡辅助判断", function()
	local a = baseline(); local index = add_shunt(a, {write_ipset_direct = "1", default_node = "_direct", enable_geoview_ip = "1"})
	assert(reload.shunt_signature(a, "a") == nil)
	local signature = reload.shunt_signature(a, "shunt")
	assert(signature.white and signature.geoview and signature.rule_rule == "redirect")
	a.passwall2[index].options.rule = "_default"
	assert(reload.shunt_signature(a, "shunt").rule_rule == "direct")
	assert(reload.write_ipset_direct(a, "shunt") and not reload.write_ipset_direct(a, "a"))
	a.passwall2[2].options.write_ipset_direct = "1"
	assert(not reload.write_ipset_direct(a, "a"))
	a.passwall2[#a.passwall2 + 1] = section("eth", "nodes", {type = "Xray", protocol = "_iface", iface = "wan2"})
	a.passwall2[index].options.rule = "eth"
	a.passwall2[3].options.outbound_node = "_iface"
	a.passwall2[3].options.outbound_node_iface = "wg0"
	a.passwall2[index].options.default_node = "b"
	local ifaces = table.concat(reload.graph_ifaces(a, "shunt"), ",")
	assert(ifaces == "wg0,wan2" or ifaces == "wan2,wg0", ifaces)
	assert(#reload.graph_ifaces(a, "a") == 0)
end)
check("分流规则内容变化交给集合热刷新（nftables 与 iptables）", function()
	local a = baseline()
	add_shunt(a, {enable_geoview_ip = "1"})
	local b = reload.clone(a); b.passwall2[4].options.ip_list = "192.0.2.0/24"
	assert(same(a, b))
	local reason = reload.refresh_reason(a, b)
	assert(reason and reason.rules and not reason.flush)
	a.external.tables, b.external.tables = "iptables", "iptables"
	assert(same(a, b))
	local plain = baseline(); add_shunt(plain)
	local edited = reload.clone(plain); edited.passwall2[4].options.domain_list = "domain:new.test"
	assert(same(plain, edited) and reload.refresh_reason(plain, edited) == nil, "规则只影响核心路由时不刷新集合")
end)
check("flush_set 是动作标志，不改变配置指纹", function()
	local a = baseline(); local b = reload.clone(a)
	assert(reload.refresh_reason(a, b) == nil)
	b.passwall2[1].options.flush_set = "1"
	assert(same(a, b))
	local reason = reload.refresh_reason(a, b)
	assert(reason and reason.flush and not reason.rules)
end)
check("dnsmasq 上游、ISP DNS 与防火墙 include 变化回退", function()
	local a = baseline()
	local b = reload.clone(a); b.external.dnsmasq.options.server = {"223.5.5.5"}
	assert(not same(a, b))
	b = reload.clone(a); b.external.resolv = {"202.98.0.68", "202.98.5.68"}
	assert(not same(a, b))
	b = reload.clone(a); b.external.firewall.path = "/tmp/other.include"
	assert(not same(a, b))
	b = reload.clone(a); b.external.dnsmasq.name = "cfg02"
	assert(not same(a, b))
	b = reload.clone(a); b.external.tables = nil
	assert(not same(a, b))
end)
check("普通节点增删与改类型不改变指纹，派生结构仍回退", function()
	local a = baseline(); local b = reload.clone(a)
	b.passwall2[#b.passwall2 + 1] = section("new", "nodes", {type = "sing-box", protocol = "vless", address = "new.example.test", port = "443"})
	table.remove(b.passwall2, 3)
	assert(same(a, b), "订阅增删普通节点")
	local c = reload.clone(a); c.passwall2[3].options.type = "sing-box"
	assert(same(a, c), "未被引用的节点改类型")
	c = reload.clone(a); c.passwall2[3].options.outbound_iface = "wan2"
	assert(not same(a, c), "出站网卡需要启动时生成的放行规则")
	c = reload.clone(a); c.passwall2[3].options.protocol = "wireguard"
	assert(not same(a, c), "WireGuard 节点整节比较")
end)
check("订阅、测速与界面选项不影响运行，定时选项只重建计划任务", function()
	local a = baseline()
	a.passwall2[#a.passwall2 + 1] = section("sub1", "subscribe_list", {remark = "S", url = "https://example.test/a"})
	a.passwall2[#a.passwall2 + 1] = section("cfg_sub", "global_subscribe", {filter_keyword_mode = "1"})
	a.passwall2[#a.passwall2 + 1] = section("cfg_other", "global_other", {show_node_info = "0"})
	a.passwall2[#a.passwall2 + 1] = section("cfg_rules", "global_rules", {v2ray_location_asset = "/usr/share/v2ray/", geoip_url = "https://a.test/geoip.dat"})
	a.passwall2[#a.passwall2 + 1] = section("cfg_delay", "global_delay", {start_daemon = "1", start_delay = "60"})
	local n = #a.passwall2
	local b = reload.clone(a)
	b.passwall2[n - 4].options.url = "https://example.test/b"
	b.passwall2[n - 3].options.filter_keyword_mode = "2"
	b.passwall2[n - 2].options.show_node_info = "1"
	b.passwall2[n - 1].options.geoip_url = "https://b.test/geoip.dat"
	b.passwall2[n].options.start_delay = "30"
	b.passwall2[#b.passwall2 + 1] = section("sub2", "subscribe_list", {remark = "T", url = "https://example.test/c"})
	assert(same(a, b))
	assert(reload.equal(reload.schedule_signature(a), reload.schedule_signature(b)), "没有定时设置的订阅增删不重建计划任务")
	local c = reload.clone(a); c.passwall2[n].options.start_daemon = "0"
	assert(same(a, c) and not reload.equal(reload.schedule_signature(a), reload.schedule_signature(c)))
	c = reload.clone(a); c.passwall2[n - 4].options.update_week_mode = "7"
	assert(same(a, c) and not reload.equal(reload.schedule_signature(a), reload.schedule_signature(c)))
	c = reload.clone(a); c.passwall2[n - 1].options.v2ray_location_asset = "/tmp/v2ray/"
	assert(not same(a, c), "规则数据目录影响核心")
end)
check("外部输入未变时保留热重载", function()
	local a = baseline(); local b = reload.clone(a)
	b.passwall2[1].options.timestamp = "100"
	assert(same(a, b))
end)
check("辅助核心依赖不能按原生实例重载", function()
	local a = baseline()
	assert(reload.native_graph(a, "a", "xray"))
	a.passwall2[2].options.chain_proxy = "1"
	a.passwall2[2].options.preproxy_node = "b"
	assert(reload.native_graph(a, "a", "xray"))
	a.passwall2[3].options.type = "sing-box"
	assert(not reload.native_graph(a, "a", "xray"))
end)
print("配置分类测试通过：" .. passed .. "；失败：0")
