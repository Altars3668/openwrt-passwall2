-- 旧版服务端配置迁移：用内存中的假 uci 游标验证，不读写真实配置。
-- 用法：lua tests/server_migrate_test.lua <仓库根目录>
local root = arg[1] or "."
local saved, random = {}, 0
package.loaded["luci.passwall2.api"] = {
	base64Decode = function(s)
		assert(s == "c2VjcmV0", "测试只用到一个 base64 值")
		return "secret"
	end,
	gen_random_char = function()
		random = random + 1
		return string.format("u%07d", random)
	end,
	uci_save = function(_, config, commit, apply)
		saved[#saved + 1] = config .. ":" .. tostring(commit) .. ":" .. tostring(apply)
	end
}
package.preload["luci.passwall2.server_migrate"] = assert(loadfile(root .. "/luci-app-passwall2/luasrc/passwall2/server_migrate.lua"))
local migrate = require "luci.passwall2.server_migrate"

local function copy(t)
	local r = {}
	for k, v in pairs(t) do r[k] = type(v) == "table" and copy(v) or v end
	return r
end

-- 与 luci.model.uci 的语义一致：foreach/get_all 返回副本，section 追加到末尾。
local function cursor(configs)
	local c = { data = configs }
	function c:foreach(config, stype, fn)
		for _, s in ipairs(copy(self.data[config] or {})) do
			if stype == nil or s[".type"] == stype then
				if fn(s) == false then break end
			end
		end
	end
	function c:get_all(config, name)
		for _, s in ipairs(self.data[config] or {}) do
			if s[".name"] == name then return copy(s) end
		end
	end
	function c:delete(config, name)
		for i, s in ipairs(self.data[config] or {}) do
			if s[".name"] == name then table.remove(self.data[config], i) return true end
		end
	end
	function c:section(config, stype, name, values)
		assert(not self:get_all(config, name), "节名冲突：" .. name)
		local s = copy(values or {})
		s[".name"], s[".type"] = name, stype
		self.data[config] = self.data[config] or {}
		table.insert(self.data[config], s)
		return name
	end
	return c
end

local function find(c, name) return c:get_all("passwall2_server", name) end
local function users_of(c)
	local r = {}
	c:foreach("passwall2_server", "user", function(s) r[#r + 1] = s end)
	return r
end

local passed = 0
local function check(name, fn)
	local ok, err = pcall(fn)
	if not ok then error(name .. ": " .. tostring(err), 0) end
	passed = passed + 1
end

local function legacy()
	return cursor({
		passwall2_server = {
			{ [".name"] = "global", [".type"] = "global", enable = "1" },
			{ [".name"] = "existing", [".type"] = "user", username = "vless_1", password = "p0", uuid = "aaaa" },
			{ [".name"] = "socks", [".type"] = "user", enable = "1", remarks = "S", type = "sing-box", protocol = "socks",
				port = "31004", auth = "1", username = "alice", password = "pw", accept_lan = "1", outbound_node = "n1" },
			{ [".name"] = "vless", [".type"] = "user", enable = "1", type = "Xray", protocol = "vless", port = "31003",
				uuid = { "bbbb", "cccc" }, flow = "xtls-rprx-vision", tls = "1", reality = "1" },
			{ [".name"] = "vless2", [".type"] = "user", enable = "0", type = "Xray", protocol = "vless", port = "31005",
				uuid = { "cccc" }, bind_local = "1" },
			{ [".name"] = "trojan", [".type"] = "user", type = "sing-box", protocol = "trojan", port = "443", uuid = "tp" },
			{ [".name"] = "tuic", [".type"] = "user", type = "sing-box", protocol = "tuic", port = "8443", uuid = { "dddd" }, password = "tpw" },
			{ [".name"] = "hy", [".type"] = "user", type = "sing-box", protocol = "hysteria", port = "9443",
				hysteria_auth_type = "base64", hysteria_auth_password = "c2VjcmV0" },
			{ [".name"] = "ss", [".type"] = "user", type = "Xray", protocol = "shadowsocks", port = "8388", method = "aes-128-gcm", password = "sspw" },
			{ [".name"] = "rust", [".type"] = "user", type = "SS-Rust", port = "8389", method = "aes-256-gcm", password = "rpw" },
			{ [".name"] = "door", [".type"] = "user", type = "Xray", protocol = "dokodemo-door", port = "5353", d_address = "1.1.1.1" },
			{ [".name"] = "noauth", [".type"] = "user", type = "Xray", protocol = "socks", port = "1080", auth = "0", username = "x", password = "y" },
			{ [".name"] = "custom", [".type"] = "user", type = "Xray", custom = "1", config_str = "e30=" },
			{ [".name"] = "hy2core", [".type"] = "user", type = "Hysteria2", port = "4443", auth_password = "h" },
		},
		firewall = {
			{ [".name"] = "passwall2_server", [".type"] = "include", type = "script", path = "/var/etc/passwall2_server.include" },
			{ [".name"] = "keep", [".type"] = "rule", name = "keep" },
		}
	})
end

local logs = {}
local c = legacy()
local count = migrate.run(c, "passwall2_server", function(msg) logs[#logs + 1] = msg end)

check("识别全部旧服务端并保留节名与顺序", function()
	assert(count == 12, count)
	local order = {}
	c:foreach("passwall2_server", "server", function(s) order[#order + 1] = s[".name"] end)
	assert(table.concat(order, ",") == "socks,vless,vless2,trojan,tuic,hy,ss,rust,door,noauth,custom,hy2core", table.concat(order, ","))
end)
check("socks 认证转为同名用户", function()
	local s = find(c, "socks")
	assert(s[".type"] == "server" and s.auth == nil and s.username == nil and s.password == nil)
	assert(s.accept_lan == "1" and s.outbound_node == "n1" and #s.users == 1)
	local u = find(c, s.users[1])
	assert(u[".type"] == "user" and u.username == "alice" and u.password == "pw" and u.uuid == nil)
end)
check("UUID 列表逐个建用户、生成不冲突用户名并在服务端间复用", function()
	local s, s2 = find(c, "vless"), find(c, "vless2")
	assert(s.uuid == nil and s.flow == "xtls-rprx-vision" and #s.users == 2)
	local a, b = find(c, s.users[1]), find(c, s.users[2])
	assert(a.uuid == "bbbb" and a.username == "vless_2", a.username)
	assert(b.uuid == "cccc" and b.username == "vless_3", b.username)
	assert(#s2.users == 1 and s2.users[1] == s.users[2], "相同 UUID 应复用同一用户")
	assert(find(c, "existing").username == "vless_1", "已有新格式用户不能改动")
end)
check("trojan 与 tuic 凭据", function()
	local t = find(c, find(c, "trojan").users[1])
	assert(t.password == "tp" and t.uuid == nil and t.username == "trojan_1")
	local q = find(c, "tuic")
	assert(q.password == nil)
	local u = find(c, q.users[1])
	assert(u.uuid == "dddd" and u.password == "tpw")
end)
check("hysteria base64 认证解码为字符串", function()
	local h = find(c, "hy")
	assert(h.hysteria_auth_type == nil and h.hysteria_auth_password == nil)
	assert(find(c, h.users[1]).password == "secret")
end)
check("Xray shadowsocks 改用 ss_ 字段", function()
	local s = find(c, "ss")
	assert(s.ss_method == "aes-128-gcm" and s.ss_password == "sspw" and s.method == nil and s.password == nil and s.users == nil)
end)
check("SS-Rust 密码转为单个 user 引用", function()
	local s = find(c, "rust")
	assert(s.method == "aes-256-gcm" and s.password == nil and s.users == nil)
	local u = find(c, s.user)
	assert(u.password == "rpw" and u.username == "ssrust_1")
end)
check("dokodemo-door 改名 tunnel", function()
	assert(find(c, "door").protocol == "tunnel" and find(c, "door").d_address == "1.1.1.1")
end)
check("未启用认证的 socks 不建用户并清除残留字段", function()
	local s = find(c, "noauth")
	assert(s.users == nil and s.username == nil and s.password == nil and s.auth == nil)
end)
check("防火墙放行与旧版一致", function()
	for _, name in ipairs({ "socks", "vless", "trojan", "rust", "noauth" }) do
		local s = find(c, name)
		assert(s.firewall_allow == "1" and s.firewall_allow_src == "*", name)
	end
	local s2 = find(c, "vless2")
	assert(s2.firewall_allow == "0" and s2.firewall_allow_src == nil and s2.bind_local == nil, "仅本机时不放行")
	assert(find(c, "custom").firewall_allow == "0", "没有端口的自定义配置不放行")
	assert(find(c, "custom").config_str == "e30=")
end)
check("Hysteria2 核心类型保留并提示", function()
	local s = find(c, "hy2core")
	assert(s.type == "Hysteria2" and s.auth_password == "h")
	local found = false
	for _, msg in ipairs(logs) do if msg:find("Hysteria2") then found = true end end
	assert(found)
end)
check("清除旧防火墙包含并提交", function()
	assert(c:get_all("firewall", "passwall2_server") == nil and c:get_all("firewall", "keep"))
	assert(table.concat(saved, ",") == "passwall2_server:true:nil,firewall:true:true", table.concat(saved, ","))
end)
check("重复执行不再改动", function()
	local before = copy(c.data)
	saved = {}
	assert(migrate.run(c, "passwall2_server") == 0)
	assert(#saved == 0)
	local function dump(t)
		local keys = {}
		for k in pairs(t) do keys[#keys + 1] = tostring(k) end
		table.sort(keys)
		local out = {}
		for _, k in ipairs(keys) do
			local v = t[k] == nil and t[tonumber(k)] or t[k]
			out[#out + 1] = k .. "=" .. (type(v) == "table" and dump(v) or tostring(v))
		end
		return "{" .. table.concat(out, ";") .. "}"
	end
	assert(dump(before) == dump(c.data))
end)
check("新格式配置不受影响", function()
	local fresh = cursor({ passwall2_server = {
		{ [".name"] = "global", [".type"] = "global", enable = "1" },
		{ [".name"] = "u", [".type"] = "user", username = "bob", password = "x", uuid = "eeee" },
		{ [".name"] = "s", [".type"] = "server", type = "Xray", protocol = "vless", users = { "u" } },
	} })
	saved = {}
	assert(migrate.run(fresh, "passwall2_server") == 0 and #saved == 0)
	assert(#users_of(fresh) == 1 and find(fresh, "s").users[1] == "u")
end)

print(string.format("server_migrate_test: %d passed", passed))
