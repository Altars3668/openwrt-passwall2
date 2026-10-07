local api = require "luci.passwall2.api"
local c_config = api.c_config
local sys = api.sys
local jsonc = api.jsonc
local fs = api.fs
local datatypes = api.datatypes
local TMP = {}

local function tinsert(table_name, val)
	if table_name and type(table_name) == "table" then
		if not TMP[table_name] then
			TMP[table_name] = {}
		end
		if TMP[table_name][val] then
			return false
		end
		table.insert(table_name, val)
		TMP[table_name][val] = true
		return true
	end
	return false
end

local function backup_servers()
	local DNSMASQ_DNS = api.uci_get("dhcp", "@dnsmasq[0]", "server")
	if DNSMASQ_DNS and #DNSMASQ_DNS > 0 then
		api.uci_set_c("@global[0]", "dnsmasq_servers", DNSMASQ_DNS)
		api.uci_save_c(true)
	end
end

local function restore_servers()
	local dns_table = {}
	local DNSMASQ_DNS = api.uci_get("dhcp", "@dnsmasq[0]", "server")
	if DNSMASQ_DNS and #DNSMASQ_DNS > 0 then
		for k, v in ipairs(DNSMASQ_DNS) do
			tinsert(dns_table, v)
		end
	end
	local OLD_SERVER = api.uci_get_c("@global[0]", "dnsmasq_servers")
	if OLD_SERVER and #OLD_SERVER > 0 then
		for k, v in ipairs(OLD_SERVER) do
			tinsert(dns_table, v)
		end
		api.uci_del_c("@global[0]", "dnsmasq_servers")
		api.uci_save_c(true)
	end
	if dns_table and #dns_table > 0 then
		api.uci_set("dhcp", "@dnsmasq[0]", "server", dns_table)
		api.uci_save(nil, "dhcp", true)
	end
end

function stretch()
	local dnsmasq_server = api.uci_get("dhcp", "@dnsmasq[0]", "server")
	local dnsmasq_noresolv = api.uci_get("dhcp", "@dnsmasq[0]", "noresolv")
	local _flag
	if dnsmasq_server and #dnsmasq_server > 0 then
		for k, v in ipairs(dnsmasq_server) do
			if not v:find("/") then
				_flag = true
			end
		end
	end
	if not _flag and dnsmasq_noresolv == "1" then
		api.uci_del("dhcp", "@dnsmasq[0]", "noresolv")
		local RESOLVFILE = "/tmp/resolv.conf.d/resolv.conf.auto"
		local file = io.open(RESOLVFILE, "r")
		if not file then
			RESOLVFILE = "/tmp/resolv.conf.auto"
		else
			local size = file:seek("end")
			file:close()
			if size == 0 then
				RESOLVFILE = "/tmp/resolv.conf.auto"
			end
		end
		api.uci_set("dhcp", "@dnsmasq[0]", "resolvfile", RESOLVFILE)
		api.uci_save(nil, "dhcp", true)
	end
end

function restart(var)
	local LOG = var["LOG"]
	sys.call("/etc/init.d/dnsmasq restart >/dev/null 2>&1")
	if LOG == "1" then
		api.log(0, api.i18n.translate("Restart dnsmasq service."))
	end
end

function logic_restart(var)
	local LOG = var["LOG"]
	local DEFAULT_DNS = api.get_cache_var("DEFAULT_DNS")
	if DEFAULT_DNS then
		backup_servers()
		--sys.call("sed -i '/list server/d' /etc/config/dhcp >/dev/null 2>&1")
		local dns_table = {}
		local dnsmasq_server = api.uci_get("dhcp", "@dnsmasq[0]", "server")
		if dnsmasq_server and #dnsmasq_server > 0 then
			for k, v in ipairs(dnsmasq_server) do
				if v:find("/") then
					tinsert(dns_table, v)
				end
			end
			api.uci_set("dhcp", "@dnsmasq[0]", "server", dns_table)
			api.uci_save(nil, "dhcp", true)
		end
		sys.call("/etc/init.d/dnsmasq restart >/dev/null 2>&1")
		restore_servers()
	else
		sys.call("/etc/init.d/dnsmasq restart >/dev/null 2>&1")
	end
	if LOG == "1" then
		api.log(0, api.i18n.translate("Restart dnsmasq service."))
	end
end

function copy_instance(var)
	local LISTEN_PORT = var["LISTEN_PORT"]
	local TMP_DNSMASQ_PATH = var["TMP_DNSMASQ_PATH"]
	local conf_lines = {}
	local DEFAULT_DNSMASQ_CFGID = sys.exec("echo -n $(uci -q show dhcp.@dnsmasq[0] | awk 'NR==1 {split($0, conf, /[.=]/); print conf[2]}')")
	
	local conf_file = "/var/etc/dnsmasq.conf." .. DEFAULT_DNSMASQ_CFGID
	
	local retry = 5
	while not fs.access(conf_file) and retry > 0 do
		api.nixio.nanosleep(1, 0)
		retry = retry - 1
	end

	if fs.access(conf_file) then
		for line in io.lines(conf_file) do
			local filter
			if line:find("passwall2") then filter = true end
			if line:find("ubus") then filter = true end
			if line:find("dhcp") then filter = true end
			if line:find("server=") == 1 then filter = true end
			if line:find("port=") == 1 then filter = true end
			if line:find("conf%-dir=") == 1 then
				filter = true
				if TMP_DNSMASQ_PATH then
					local tmp_path = line:sub(1 + #"conf-dir=")
					sys.call(string.format("cp -r %s/* %s/ 2>/dev/null", tmp_path, TMP_DNSMASQ_PATH))
				end
			end
			if line:find("address=") == 1 or (line:find("server=") == 1 and line:find("/")) then filter = nil end
			if not filter then
				tinsert(conf_lines, line)
			end
		end
	else
		sys.call("logger -t passwall2 'ERROR: dnsmasq config " .. conf_file .. " not found after 5s wait! DNS hijacking will fail.'")
	end

	tinsert(conf_lines, "port=" .. LISTEN_PORT)
	--dhcp.leases to hostsMore actions
	local hosts = api.CACHE_PATH .. "/dhcp-hosts"
	sys.call("touch " .. hosts)
	tinsert(conf_lines, "addn-hosts=" .. hosts)
	if TMP_DNSMASQ_PATH then
		sys.call("rm -rf " .. TMP_DNSMASQ_PATH .. "/*passwall2*")
	end
	if var["return"] == "1" then
		return conf_lines
	end
	if #conf_lines > 0 then
		local DNSMASQ_CONF = var["DNSMASQ_CONF"]
		local conf_out = io.open(DNSMASQ_CONF, "a")
		conf_out:write(table.concat(conf_lines, "\n"))
		conf_out:write("\n")
		conf_out:close()
	end
end

-- 所有节点域名（地址与下载地址），用于让节点域名始终经国内 DNS 解析。
local function node_domains()
	local result = {}
	api.uci_foreach_c("nodes", function(t)
		for _, address in ipairs({ t.address or "", t.download_address or "" }) do
			address = address:lower()
			if address ~= "engage.cloudflareclient.com" and datatypes.hostname(address) then result[#result + 1] = address end
		end
	end)
	return result
end

-- 节点域名的转发规则写入 servers-file（不在 conf-dir 内）：dnsmasq 收到 SIGHUP 时重读该文件，
-- 节点地址变化无需重启 DNS 实例。文件先写临时文件再改名，读者看不到半个文件。
local function write_servers(path, local_dns)
	local seen, lines = {}, {}
	for _, domain in ipairs(node_domains()) do
		for dns in string.gmatch(local_dns or "", '[^,]+') do
			local line = string.format("server=/.%s/%s", domain, dns)
			if not seen[line] then seen[line] = true; lines[#lines + 1] = line end
		end
	end
	local out = io.open(path .. ".tmp", "w")
	if not out then return false end
	out:write(table.concat(lines, "\n") .. (#lines > 0 and "\n" or ""))
	out:close()
	return fs.rename(path .. ".tmp", path)
end

-- 热重载：按当前节点重写指定实例的节点域名转发规则；调用者随后向该 dnsmasq 发送 SIGHUP。
function update_servers(var)
	local base = api.CACHE_PATH .. "/dnsmasq_" .. (var["FLAG"] or "")
	local local_dns = fs.readfile(base .. ".local_dns")
	if not local_dns or not fs.access(base .. ".servers") or not write_servers(base .. ".servers", local_dns) then
		os.exit(1)
	end
end

function add_rule(var)
	local FLAG = var["FLAG"]
	local TMP_DNSMASQ_PATH = var["TMP_DNSMASQ_PATH"]
	local DNSMASQ_CONF_FILE = var["DNSMASQ_CONF_FILE"]
	local CACHE_CONF_FILE = var["CACHE_CONF_FILE"] or DNSMASQ_CONF_FILE
	local DEFAULT_DNS = var["DEFAULT_DNS"]
	local LOCAL_DNS = var["LOCAL_DNS"]
	local TUN_DNS = var["TUN_DNS"]
	local NFTFLAG = var["NFTFLAG"]
	-- 影子启动把实例缓存写到暂存目录，不改动运行中实例读取的缓存（servers-file 会在 SIGHUP 时重读）。
	local CACHE_PATH = os.getenv("PW2_DNSMASQ_CACHE") or api.CACHE_PATH
	local CACHE_FLAG = "dnsmasq_" .. FLAG
	local CACHE_DNS_PATH = CACHE_PATH .. "/" .. CACHE_FLAG
	local CACHE_TEXT_FILE = CACHE_DNS_PATH .. ".txt"

	local list1 = {}

	local function check_dns(domain, dns)
		if domain == "" or domain:find("#") then
			return false
		end
		if not dns then
			return
		end
		for k,v in ipairs(list1[domain].dns) do
			if dns == v then
				return true
			end
		end
		return false
	end

	local function check_ipset(domain, ipset)
		if domain == "" or domain:find("#") then
			return false
		end
		if not ipset then
			return
		end
		for k,v in ipairs(list1[domain].ipsets) do
			if ipset == v then
				return true
			end
		end
		return false
	end

	local function set_domain_dns(domain, dns)
		if domain == "" or domain:find("#") then
			return
		end
		if not dns then
			return
		end
		if not list1[domain] then
			list1[domain] = {
				dns = {},
				ipsets = {}
			}
		end
		for line in string.gmatch(dns, '[^' .. "," .. ']+') do
			if not check_dns(domain, line) then
				table.insert(list1[domain].dns, line)
			end
		end
	end

	local function set_domain_ipset(domain, ipset)
		if domain == "" or domain:find("#") then
			return
		end
		if not ipset then
			return
		end
		if not list1[domain] then
			list1[domain] = {
				dns = {},
				ipsets = {}
			}
		end
		for line in string.gmatch(ipset, '[^' .. "," .. ']+') do
			if not check_ipset(domain, line) then
				table.insert(list1[domain].ipsets, line)
			end
		end
	end

	local cache_text = ""
	local nodes_address_md5 = sys.exec("echo -n $(uci show %s | grep '\\.address') | md5sum" % c_config)
	-- 末尾的布局标记让旧版本留下的缓存（节点域名转发写在 conf-dir 中）在升级后重建一次。
	local new_text = TMP_DNSMASQ_PATH .. CACHE_CONF_FILE .. DEFAULT_DNS .. LOCAL_DNS .. TUN_DNS .. nodes_address_md5 .. NFTFLAG .. "|servers-file"
	if fs.access(CACHE_TEXT_FILE) then
		for line in io.lines(CACHE_TEXT_FILE) do
			cache_text = line
		end
	end

	if cache_text ~= new_text then
		api.remove(CACHE_DNS_PATH .. "*")
	end

	local dnsmasq_default_dns = TUN_DNS

	local setflag_4= (NFTFLAG == "1") and "4#inet#passwall2#" or ""
	local setflag_6= (NFTFLAG == "1") and "6#inet#passwall2#" or ""

	if not fs.access(CACHE_DNS_PATH) then
		fs.mkdir(CACHE_DNS_PATH)

		local fwd_dns

		-- Always use domestic DNS to resolve node domain names
		if true then
			fwd_dns = LOCAL_DNS
			api.uci_foreach_c("nodes", function(t)
				local function process_address(address)
					address = (address or ""):lower()
					if address == "engage.cloudflareclient.com" then return end
					if datatypes.hostname(address) then
						set_domain_dns(address, fwd_dns)
						set_domain_ipset(address, setflag_4 .. "psw2_vps," .. setflag_6 .. "psw2_vps6")
					end
				end
				process_address(t.address)
				process_address(t.download_address)
			end)
		end

		-- 节点域名转发改用 servers-file（见 write_servers）；即使暂时没有节点域名也建立空文件，便于以后热更新。
		fs.writefile(CACHE_DNS_PATH .. ".local_dns", fwd_dns or "")
		write_servers(CACHE_DNS_PATH .. ".servers", fwd_dns)
		fs.writefile(CACHE_DNS_PATH .. "/000-servers-file.conf", "servers-file=" .. CACHE_DNS_PATH .. ".servers\n")

		if list1 and next(list1) then
			local ipset_out = io.open(CACHE_DNS_PATH .. "/ipset.conf", "a")
			local set_name = "ipset"
			if NFTFLAG == "1" then
				set_name = "nftset"
			end
			for key, value in pairs(list1) do
				if value.ipsets and #value.ipsets > 0 then
					local ipsets_str = ""
					for i, ipset in ipairs(value.ipsets) do
						ipsets_str = ipsets_str .. ipset .. ","
					end
					ipsets_str = ipsets_str:sub(1, #ipsets_str - 1)
					ipset_out:write(string.format("%s=/.%s/%s", set_name, key, ipsets_str) .. "\n")
				end
			end
			ipset_out:close()
		end

		local f_out = io.open(CACHE_TEXT_FILE, "a")
		f_out:write(new_text)
		f_out:close()
	end

	api.remove(TMP_DNSMASQ_PATH)
	fs.symlink(CACHE_DNS_PATH, TMP_DNSMASQ_PATH)

	if DNSMASQ_CONF_FILE ~= "nil" then
		local conf_lines = {}
		tinsert(conf_lines, string.format("conf-dir=%s", TMP_DNSMASQ_PATH))
		if dnsmasq_default_dns then
			for s in string.gmatch(dnsmasq_default_dns, '[^' .. "," .. ']+') do
				tinsert(conf_lines, string.format("server=%s", s))
			end
			tinsert(conf_lines, "all-servers")
			tinsert(conf_lines, "no-poll")
			tinsert(conf_lines, "no-resolv")

			if FLAG == "acl_default" then
				api.set_cache_var("DEFAULT_DNS", DEFAULT_DNS)
			end
		end
		if #conf_lines > 0 then
			local conf_out = io.open(DNSMASQ_CONF_FILE, "a")
			conf_out:write(table.concat(conf_lines, "\n"))
			conf_out:write("\n")
			conf_out:close()
		end
	end
end

_G.stretch = stretch
_G.restart = restart
_G.logic_restart = logic_restart
_G.copy_instance = copy_instance
_G.add_rule = add_rule
_G.update_servers = update_servers

if arg[1] then
	local func =_G[arg[1]]
	if func then
		local var = nil
		if arg[2] then
			var = jsonc.parse(arg[2])
		end
		func(var or {})
	end
end
