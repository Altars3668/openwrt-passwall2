-- Copyright (C) 2026 Openwrt-Passwall Organization

local M = {}

function M.clone(value)
	if type(value) ~= "table" then return value end
	local result = {}
	for k, v in pairs(value) do result[k] = M.clone(v) end
	return result
end

function M.equal(a, b)
	if type(a) ~= type(b) then return false end
	if type(a) ~= "table" then return a == b end
	for k, v in pairs(a) do if not M.equal(v, b[k]) then return false end end
	for k in pairs(b) do if a[k] == nil then return false end end
	return true
end

local function without(value, keys)
	local result = M.clone(value or {})
	for _, key in ipairs(keys) do result[key] = nil end
	return result
end

function M.sections(snapshot, kind)
	local result = {}
	for _, section in ipairs(snapshot.passwall2 or {}) do
		if section.type == kind then result[#result + 1] = section end
	end
	return result
end

function M.node(snapshot, id)
	for _, section in ipairs(snapshot.passwall2 or {}) do
		if section.name == id and section.type == "nodes" then return section.options end
	end
end

local global_runtime = {
	"node", "loglevel", "log_node", "dns_cache", "dns_hosts", "remote_dns_protocol",
	"remote_dns", "remote_dns_doh", "remote_dns_client_ip", "remote_dns_detour",
	"remote_fakedns", "remote_dns_query_strategy", "remote_rewrite_ttl", "timestamp", "auto_lang",
	-- 一次性动作标志（规则更新、保存分流规则、手动清空集合）：由执行器热刷新集合后删除，不代表配置变化。
	"flush_set"
}
-- 节点进入启动时派生结构（出站网卡放行、直连写集合 DNS、GeoIP 预加载）的选项；变化时改用差量热重载。
-- 地址、端口与链式代理由执行器热更新：前置 DNS 的节点域名转发、直连白名单与本机放行规则（见 M.node_endpoints）。
local node_infrastructure = {
	"type", "outbound_iface", "outbound_node_iface", "iface", "write_ipset_direct", "enable_geoview_ip"
}

-- 只影响 crontab、看门狗与循环更新进程的选项：变化时由执行器重建计划任务，不重启服务。
local schedule_options = {
	global_delay = { "start_daemon", "stop_week_mode", "stop_time_mode", "start_week_mode", "start_time_mode",
		"restart_week_mode", "restart_time_mode", "restart_interval_mode" },
	global_rules = { "update_week_mode", "update_time_mode", "update_interval_mode" },
	subscribe_list = { "update_week_mode", "update_time_mode", "update_interval_mode" }
}
-- 这些节对运行中的服务只有下面列出的选项有影响；其余只被订阅、规则更新脚本、测速或 LuCI 读取
-- （global_delay 的 start_delay 只在开机时使用）。不在表中的节类型仍整节比较。
local runtime_options = {
	global_subscribe = {}, global_other = {}, subscribe_list = {}, global_delay = {},
	global_rules = { "v2ray_location_asset" }
}

function M.schedule_signature(snapshot)
	local result = {}
	for _, section in ipairs(snapshot.passwall2 or {}) do
		local keys = schedule_options[section.type]
		-- 没有设置自动更新的订阅不产生计划任务，增删这类订阅无需重建。
		if keys and (section.type ~= "subscribe_list" or section.options.update_week_mode) then
			local values = {}
			for _, key in ipairs(keys) do values[key] = section.options[key] end
			result[#result + 1] = { name = section.name, type = section.type, options = values }
		end
	end
	return result
end

local function global_options(snapshot)
	return (M.sections(snapshot, "global")[1] or {}).options or {}
end

-- 分流节点进入防火墙的部分，决定该节点的 nft 分流列表（集合名及直连／代理动作）；普通节点返回 nil。
-- 与 gen_shunt_list 一致：只有开启 GeoIP 预加载时才按规则生成集合，且只取同一分组、已指定目标的规则；
-- 直连写集合只取决于 write_ipset_direct。集合的内容（规则的 IP 与 geoip 代码）由热刷新原地更新，不在其中。
function M.shunt_signature(snapshot, id)
	local node = M.node(snapshot, id)
	if not node or node.protocol ~= "_shunt" then return nil end
	local result = { geoview = node.enable_geoview_ip == "1", white = node.write_ipset_direct == "1" }
	if result.geoview then
		local default = (node.default_node or "_direct") == "_direct" and "direct" or "redirect"
		for _, rule in ipairs(M.sections(snapshot, "shunt_rules")) do
			local target = node[rule.name]
			if (rule.options.group or "") == (node.shunt_group or "") and target and target ~= "" then
				result["rule_" .. rule.name] = (target == "_direct" and "direct") or (target == "_default" and default) or "redirect"
			end
		end
	end
	return result
end

-- 与 app.sh 一致：只有分流节点的 write_ipset_direct 才会启动直连写集合 DNS。
function M.write_ipset_direct(snapshot, id)
	local node = M.node(snapshot, id)
	return node ~= nil and node.protocol == "_shunt" and node.write_ipset_direct == "1"
end

-- 原生核心节点的服务器端点：变化时执行器重写前置 DNS 的节点域名转发并补充直连白名单与本机放行规则。
-- 其它类型的节点由外部程序运行，整节比较（见 fingerprint）。
function M.node_endpoints(snapshot)
	local result = {}
	for _, section in ipairs(M.sections(snapshot, "nodes")) do
		local node = section.options
		if node.type == "Xray" or node.type == "sing-box" then
			result[section.name] = (node.address or "") .. "|" .. (node.download_address or "") .. "|" .. (node.port or "")
		end
	end
	return result
end

-- 分流规则内容会进入防火墙集合或直连写集合 DNS 的情形。
local function optimized_shunt(snapshot)
	for _, section in ipairs(M.sections(snapshot, "nodes")) do
		local node = section.options
		if node.protocol == "_shunt" and (node.write_ipset_direct == "1" or node.enable_geoview_ip == "1") then return true end
	end
	return false
end

-- 需要热刷新防火墙集合的原因：flush_set 动作（规则更新、保存分流规则、手动清空集合），
-- 或分流规则内容变化且有分流节点开启了 GeoIP 预加载／直连写集合。返回 nil 表示不需要。
function M.refresh_reason(previous, current)
	local flush = global_options(current).flush_set == "1"
	local rules = optimized_shunt(current) and not M.equal(M.sections(previous, "shunt_rules"), M.sections(current, "shunt_rules"))
	if flush or rules then return { flush = flush, rules = rules } end
end

-- 与 app_acl.lua 一致：启用且指定了节点、未整体绕过的访问控制规则使用独立实例，其分流规则是启动时生成的静态规则。
local function acl_static_nodes(snapshot)
	local global, result = global_options(snapshot), {}
	if global.acl_enable ~= "1" then return result end
	for _, section in ipairs(M.sections(snapshot, "acl_rule")) do
		local acl = section.options
		if acl.enabled == "1" and acl.node and acl.node ~= "" and acl.mode ~= "0" then result[acl.node] = true end
	end
	return result
end

-- 指纹相同（与防火墙、DNS 前置服务、辅助进程和监听资源无关的变化）走核心重载快速路径，其余由差量热重载处理。
-- snapshot.external 是启动时派生的外部输入（dnsmasq 主实例、防火墙 include、ISP DNS、防火墙后端），原样比较。
-- 使用默认实例的分流项位于可原子替换的子链（nftables 与 iptables 都是），切换全局节点不再要求完整重启；
-- 规则内容由集合热刷新重建。独立访问控制实例的分流规则是启动时生成的静态规则，其分流签名变化由差量热重载重建。
-- 访问控制规则本身（含“跟随全局”与显式节点）原样比较；显式节点总是独立实例，不随全局节点变化。
function M.fingerprint(snapshot)
	local result = without(snapshot, {"passwall2"})
	result.passwall2 = {}
	local global = global_options(snapshot)
	local selected = M.node(snapshot, global.node) or {}
	-- 全局节点改用另一种核心时由执行器替换核心进程（DNS 与防火墙不变），这里只记录节点是否有效。
	result.global_valid = selected.type ~= nil
	local static_shunt = acl_static_nodes(snapshot)
	for _, section in ipairs(snapshot.passwall2 or {}) do
		local options = M.clone(section.options)
		local keep = true
		if section.type == "global" then
			options = without(options, global_runtime)
		elseif section.type == "global_xray" or section.type == "global_singbox" or section.type == "xray_noise_packets" then
			keep = false
		elseif section.type == "shunt_rules" then
			keep = false
		elseif runtime_options[section.type] then
			local kept = {}
			for _, key in ipairs(runtime_options[section.type]) do kept[key] = options[key] end
			options, keep = kept, next(kept) ~= nil
		elseif section.type == "nodes" and (options.type == "Xray" or options.type == "sing-box") then
			local node = options
			options = {}
			for _, key in ipairs(node_infrastructure) do options[key] = node[key] end
			if (node.protocol or ""):sub(1, 1) == "_" then options.protocol = node.protocol end
			if node.protocol == "_shunt" and static_shunt[section.name] then
				options.shunt = M.shunt_signature(snapshot, section.name)
			elseif node.protocol == "_iface" or node.protocol == "wireguard" then
				options = node
			end
			-- 没有启动时派生结构的普通节点（订阅增删、改地址或类型）不影响运行结构：
			-- 被运行中的实例引用时，执行器按节点图检查核心类型与出站网卡，不满足时改用差量热重载。
			local function set(key) return node[key] ~= nil and node[key] ~= "" end
			keep = options.shunt ~= nil or node.protocol == "_iface" or node.protocol == "wireguard" or
				set("outbound_iface") or set("outbound_node_iface") or set("iface") or
				node.write_ipset_direct == "1" or node.enable_geoview_ip == "1"
		end
		if keep then result.passwall2[#result.passwall2 + 1] = { name = section.name, type = section.type, options = options } end
	end
	return result
end

-- 新节点图中需要的出站网卡；启动时这些网卡会写入 TMP_IFACE_PATH 并生成本机流量放行规则。
function M.graph_ifaces(snapshot, id, seen, result)
	seen, result = seen or {}, result or {}
	if not id or id == "" or id:sub(1, 1) == "_" or seen[id] then return result end
	seen[id] = true
	local node = M.node(snapshot, id)
	if not node then return result end
	if node.protocol == "_iface" and node.iface then result[#result + 1] = node.iface end
	if node.outbound_node == "_iface" and node.outbound_node_iface then result[#result + 1] = node.outbound_node_iface end
	-- 缺省值用空串占位，避免 nil 截断 ipairs 遍历。
	local refs = { node.preproxy_node or "", node.to_node or "", node.default_node or "", node.fallback_node or "" }
	for _, key in ipairs({"balancing_node", "urltest_node"}) do
		for _, ref in ipairs(type(node[key]) == "table" and node[key] or {}) do refs[#refs + 1] = ref end
	end
	if node.protocol == "_shunt" then
		for _, rule in ipairs(M.sections(snapshot, "shunt_rules")) do refs[#refs + 1] = node[rule.name] or "" end
	end
	for _, ref in ipairs(refs) do M.graph_ifaces(snapshot, ref, seen, result) end
	return result
end

-- 节点图中的全部节点（前置、落地、分流目标、负载均衡与自动选择成员）。
function M.graph_nodes(snapshot, id, result)
	result = result or {}
	if not id or id == "" or id:sub(1, 1) == "_" or result[id] then return result end
	local node = M.node(snapshot, id)
	if not node then return result end
	result[id] = true
	local refs = { node.preproxy_node or "", node.to_node or "", node.default_node or "", node.fallback_node or "" }
	for _, key in ipairs({"balancing_node", "urltest_node"}) do
		for _, ref in ipairs(type(node[key]) == "table" and node[key] or {}) do refs[#refs + 1] = ref end
	end
	if node.protocol == "_shunt" then
		for _, rule in ipairs(M.sections(snapshot, "shunt_rules")) do refs[#refs + 1] = node[rule.name] or "" end
	end
	for _, ref in ipairs(refs) do M.graph_nodes(snapshot, ref, result) end
	return result
end

function M.native_graph(snapshot, id, core, seen)
	if not id or id == "" or id:sub(1, 1) == "_" or id:sub(1, 6) == "Socks_" then return true end
	seen = seen or {}
	if seen[id] then return true end
	seen[id] = true
	local node = M.node(snapshot, id)
	if not node or (node.type or ""):lower() ~= core then return false end
	local refs = { node.preproxy_node or "", node.to_node or "", node.default_node or "", node.fallback_node or "" }
	for _, key in ipairs({"balancing_node", "urltest_node"}) do
		for _, ref in ipairs(type(node[key]) == "table" and node[key] or {}) do refs[#refs + 1] = ref end
	end
	if node.protocol == "_shunt" then
		for _, rule in ipairs(M.sections(snapshot, "shunt_rules")) do
			refs[#refs + 1] = node[rule.name] or ""
			refs[#refs + 1] = node[rule.name .. "_proxy_tag"] or ""
		end
	end
	if node.node_add_mode == "batch" then return false end
	for _, ref in ipairs(refs) do if not M.native_graph(snapshot, ref, core, seen) then return false end end
	return true
end

return M
