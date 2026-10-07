-- 迁移 2026-08 上游重构之前的服务端配置。
-- 旧格式把每个服务端保存为 user 节并内联凭据（uuid 列表、auth/username/password 等）；
-- 新格式使用 server 节，凭据放在独立的 user 节，经 users（列表）或 user（SS-Rust/SSR）引用。
-- 旧 user 节必有 type 选项（服务端类型），新 user 节没有，据此识别；迁移后不再匹配，可重复调用。
module("luci.passwall2.server_migrate", package.seeall)
local api = require "luci.passwall2.api"

-- 已转为 user 节或不再使用的旧选项。
local CREDENTIAL_OPTIONS = {
	"auth", "username", "password", "uuid", "bind_local",
	"hysteria_auth_type", "hysteria_auth_password", "hysteria2_auth_password"
}

local function list(value)
	if type(value) == "table" then return value end
	if value and value ~= "" then return { value } end
	return {}
end

local function filled(value)
	return value ~= nil and value ~= ""
end

-- 返回凭据列表与引用方式："user"（单个，SS-Rust/SSR）或 "users"（列表）。
local function credentials(s)
	local t, p, c = s.type, s.protocol or "", {}
	if t == "SS-Rust" or t == "SSR" then
		if filled(s.password) then c[1] = { password = s.password } end
		return c, "user"
	end
	if p == "mixed" or p == "socks" or p == "http" then
		if s.auth == "1" and filled(s.username) and filled(s.password) then
			c[1] = { username = s.username, password = s.password }
		end
	elseif p == "naive" or p == "anytls" then
		if filled(s.password) then c[1] = { username = s.username, password = s.password } end
	elseif p == "vmess" or p == "vless" then
		for _, id in ipairs(list(s.uuid)) do c[#c + 1] = { uuid = id } end
	elseif p == "trojan" then
		for _, password in ipairs(list(s.uuid)) do c[#c + 1] = { password = password } end
	elseif p == "tuic" then
		for _, id in ipairs(list(s.uuid)) do c[#c + 1] = { uuid = id, password = s.password } end
	elseif p == "hysteria" then
		local auth = s.hysteria_auth_type
		if (auth == "string" or auth == "base64") and filled(s.hysteria_auth_password) then
			-- 新版只生成 auth_str；base64 认证解码为原始字符串后等价。
			local password = s.hysteria_auth_password
			if auth == "base64" then password = api.base64Decode(password) end
			c[1] = { password = password }
		end
	elseif p == "hysteria2" then
		if filled(s.hysteria2_auth_password) then c[1] = { password = s.hysteria2_auth_password } end
	end
	return c, "users"
end

local function same(a, b)
	return (a or "") == (b or "")
end

function run(uci, config, log)
	log = log or function() end
	local legacy, users, names = {}, {}, {}
	uci:foreach(config, nil, function(s)
		names[s[".name"]] = true
	end)
	uci:foreach(config, "user", function(s)
		if s.type then
			legacy[#legacy + 1] = s
		else
			users[#users + 1] = s
		end
	end)

	-- 协议用到的凭据字段都相同时复用同一 user 节；没有用户名的凭据（UUID/密码类）按协议生成不重复的用户名。
	local function add_user(cred, prefix)
		for _, u in ipairs(users) do
			local match = true
			for _, k in ipairs({ "username", "password", "uuid" }) do
				if cred[k] ~= nil and not same(u[k], cred[k]) then match = false end
			end
			if match then return u[".name"] end
		end
		local username = cred.username
		if not filled(username) then
			local taken = {}
			for _, u in ipairs(users) do
				if u.username then taken[u.username] = true end
			end
			local i = 1
			while taken[prefix .. "_" .. i] do i = i + 1 end
			username = prefix .. "_" .. i
		end
		local sid
		repeat sid = api.gen_random_char() until not names[sid]
		names[sid] = true
		local values = { username = username, password = cred.password, uuid = cred.uuid }
		uci:section(config, "user", sid, values)
		values[".name"] = sid
		users[#users + 1] = values
		return sid
	end

	for _, s in ipairs(legacy) do
		local id = s[".name"]
		local values = {}
		for k, v in pairs(s) do
			if k:sub(1, 1) ~= "." then values[k] = v end
		end
		if s.type == "Hysteria2" then
			log(string.format("服务端 %s 使用的 Hysteria2 核心已被上游移除，请改用 sing-box 或 Xray 的 Hysteria2 重新配置", s.remarks or id))
		else
			local creds, ref = credentials(s)
			if (s.type == "Xray" or s.type == "sing-box") and s.protocol == "shadowsocks" then
				values.ss_method = s.method
				values.ss_password = s.password
				values.method = nil
			end
			for _, k in ipairs(CREDENTIAL_OPTIONS) do values[k] = nil end
			local prefix = (s.type == "SS-Rust" and "ssrust") or (s.type == "SSR" and "ssr") or (s.protocol or "user")
			prefix = prefix:gsub("[^%w_]", "_")
			local sids = {}
			for _, cred in ipairs(creds) do sids[#sids + 1] = add_user(cred, prefix) end
			if ref == "user" then
				values.user = sids[1]
			elseif #sids > 0 then
				values.users = sids
			end
			if s.type == "Xray" and s.protocol == "dokodemo-door" then
				values.protocol = "tunnel"
			end
		end
		-- 旧版未勾选“仅本机”时在 fw4/iptables INPUT 对所有来源放行端口；新版改为 UCI 防火墙规则。
		if values.firewall_allow == nil then
			if s.bind_local ~= "1" and filled(s.port) then
				values.firewall_allow = "1"
				values.firewall_allow_src = "*"
			else
				values.firewall_allow = "0"
			end
		end
		values.bind_local = nil
		uci:delete(config, id)
		uci:section(config, "server", id, values)
		log(string.format("已迁移旧版服务端配置：%s（%s %s）", s.remarks or id, s.type, s.protocol or ""))
	end
	if #legacy > 0 then
		api.uci_save(uci, config, true)
	end

	-- 旧版的防火墙脚本包含与运行时链：新版不再生成包含文件，残留的包含与放行链需要清除。
	local include = uci:get_all("firewall", config)
	if include and include[".type"] == "include" then
		uci:delete("firewall", config)
		api.uci_save(uci, "firewall", true, true)
		log("已删除旧版服务端防火墙包含")
	end
	if api.sys then
		api.sys.call("nft list chain inet fw4 PSW2-SERVER >/dev/null 2>&1 && { " ..
			"for h in $(nft -a list chain inet fw4 input | grep PSW2-SERVER | awk -F '# handle ' '{print $2}'); do " ..
			"nft delete rule inet fw4 input handle $h; done; nft delete chain inet fw4 PSW2-SERVER; } >/dev/null 2>&1")
		for _, ipt in ipairs({ "iptables", "ip6tables" }) do
			api.sys.call(string.format("command -v %s >/dev/null 2>&1 && %s -w -nL PSW2-SERVER >/dev/null 2>&1 && " ..
				"{ %s -w -D INPUT -j PSW2-SERVER; %s -w -F PSW2-SERVER; %s -w -X PSW2-SERVER; } >/dev/null 2>&1",
				ipt, ipt, ipt, ipt, ipt))
		end
		os.remove("/tmp/etc/" .. config .. ".include")
	end
	return #legacy
end
