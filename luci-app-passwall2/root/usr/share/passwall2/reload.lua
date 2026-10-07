-- Copyright (C) 2026 Openwrt-Passwall Organization

local api = require "luci.passwall2.api"
local logic = require "luci.passwall2.reload"
local fs, sys, json, nixio = api.fs, api.sys, api.jsonc, api.nixio
local root = api.TMP_PATH .. "/reload"
local quote = api.util.shellquote

local function read_json(path)
	local content = fs.readfile(path)
	return content and json.parse(content)
end

local function write_json(path, value)
	local content = json.stringify(value, 1)
	if not content or not fs.writefile(path .. ".tmp", content) then error("无法写入重载状态") end
	fs.chmod(path .. ".tmp", "600")
	if not fs.rename(path .. ".tmp", path) then error("无法提交重载状态") end
end

local function section_options(section)
	local options = {}
	for k, v in pairs(section or {}) do if k:sub(1, 1) ~= "." then options[k] = v end end
	return options
end

local function nameservers()
	local content = fs.readfile("/tmp/resolv.conf.d/resolv.conf.auto")
	if not content or content == "" then content = fs.readfile("/tmp/resolv.conf.auto") or "" end
	local result = {}
	for server in content:gmatch("nameserver%s+([^%s]+)") do result[#result + 1] = server end
	table.sort(result)
	return result
end

-- 只记录启动时实际派生的外部输入：dnsmasq 主实例、防火墙 include 与 ISP DNS。
-- 其它脚本改写的域名记录、防火墙规则或接口定义不会触发完整重启。
local function snapshot()
	local result = {passwall2 = {}}
	api.uci:foreach("passwall2", nil, function(section)
		result.passwall2[#result.passwall2 + 1] = { name = section[".name"], type = section[".type"], options = section_options(section) }
	end)
	local dnsmasq
	api.uci:foreach("dhcp", "dnsmasq", function(section)
		if not dnsmasq then dnsmasq = { name = section[".name"], options = section_options(section) } end
	end)
	result.external = {
		dnsmasq = dnsmasq or {},
		firewall = section_options(api.uci:get_all("firewall", "passwall2")),
		resolv = nameservers(),
		tables = api.get_cache_var("USE_TABLES")
	}
	return result
end

-- 节点测速（test.sh 的 url_test_*）与 Socks 自动切换的探测（test_node_*）是临时实例，由各自的脚本启动和结束：
-- 不登记、不参与热重载与差量比较（运行目录中的对应文件同样不受管理，见 managed）。
local function temporary_flag(flag)
	return flag:match("^url_test_") ~= nil or flag:match("^test_node_") ~= nil
end

local function instance_file(name)
	local flag = name:match("^instance_([%w_%-]+)%.json$")
	return flag ~= nil and not temporary_flag(flag)
end

local function instances(include_inactive)
	local result = {}
	for name in fs.dir(root) or function() end do
		if instance_file(name) then
			local state = read_json(root .. "/" .. name)
			if not state or state.version ~= 1 then error("重载实例状态损坏") end
			state.state_file = root .. "/" .. name
			if include_inactive or state.active ~= false then result[#result + 1] = state end
		end
	end
	table.sort(result, function(a, b) return a.config_file < b.config_file end)
	return result
end

local function proc_args(pid)
	local args = {}
	for value in (fs.readfile("/proc/" .. pid .. "/cmdline") or ""):gmatch("([^%z]+)%z") do args[#args + 1] = value end
	return args
end

local function pid_for(path)
	local found
	for name in fs.dir("/proc") or function() end do
		if name:match("^%d+$") then
			local args = proc_args(name)
			if args[2] == "run" then
				for i = 3, #args - 1 do
					if args[i] == "-c" and args[i + 1] == path then
						if found then return nil end
						found = tonumber(name)
					end
				end
			end
		end
	end
	return found
end

local function pause()
	nixio.nanosleep(0, 100000000)
end

local function command(binary, args, output)
	return sys.call(quote(binary) .. " " .. args .. " >" .. quote(output or root .. "/api.log") .. " 2>&1")
end

-- 失败输出另存一份，避免随后成功的校验覆盖诊断信息。
local function validate(core, binary, config, path)
	write_json(path, config)
	local log = root .. "/check.log"
	if command(binary, (core == "xray" and "run -test -c " or "check -c ") .. quote(path), log) == 0 then return true end
	fs.writefile(root .. "/check.failed.log", fs.readfile(log) or "")
	fs.chmod(root .. "/check.failed.log", "600")
	return false
end

-- 进程自己持有的监听端口（TCP 监听与已绑定的 UDP）：按进程的 socket inode 对照 /proc/net，
-- 端口被其它程序占用时不会误判为就绪。
local function owned_ports(pid)
	local inodes, ports = {}, {}
	for fd in fs.dir("/proc/" .. pid .. "/fd") or function() end do
		local inode = (fs.readlink("/proc/" .. pid .. "/fd/" .. fd) or ""):match("^socket:%[(%d+)%]$")
		if inode then inodes[inode] = true end
	end
	for _, name in ipairs({ "tcp", "tcp6", "udp", "udp6" }) do
		for line in (fs.readfile("/proc/net/" .. name) or ""):gmatch("[^\n]+") do
			local address, st, inode = line:match("^%s*%d+:%s+(%S+)%s+%S+%s+(%x%x)%s+%S+%s+%S+%s+%S+%s+%S+%s+%S+%s+(%d+)")
			if address and inodes[inode] and (name:sub(1, 3) == "udp" or st == "0A") then
				ports[tonumber(address:match(":(%x+)$"), 16)] = true
			end
		end
	end
	return ports
end

local function ready(state)
	local pid = pid_for(state.config_file)
	if not pid then return false end
	local owned = owned_ports(pid)
	for _, inbound in ipairs((read_json(state.config_file) or {}).inbounds or {}) do
		local port = tonumber(inbound.listen_port or inbound.port)
		if port and not owned[port] then return false end
	end
	return true
end

local function stop_core(state)
	local pid = pid_for(state.config_file)
	if not pid then return end
	nixio.kill(pid, 15)
	for _ = 1, 30 do if not nixio.kill(pid, 0) then return end; pause() end
	if pid_for(state.config_file) == pid then nixio.kill(pid, 9) end
	for _ = 1, 20 do if not pid_for(state.config_file) then return end; pause() end
	if pid_for(state.config_file) then error("核心进程未能停止") end
end

-- 与 ln_run 一致，经 TMP_BIN_PATH 下以核心命名的链接启动，stop 与看门狗按同样的命令行识别进程。
local function launch_path(core, binary)
	local link = api.TMP_PATH .. "/bin/" .. core
	if not fs.access(link) then fs.symlink(binary, link) end
	return fs.access(link) and link or binary
end

local function replace_core(state, config, log_file, core, binary)
	stop_core(state)
	write_json(state.config_file, config)
	state.launch = launch_path(core or state.core, binary or state.binary)
	sys.call("nohup " .. quote(state.launch) .. " run -c " .. quote(state.config_file) .. " >" .. quote(log_file or state.log_file) .. " 2>&1 &")
	-- Xray 载入大型 geosite 数据可能需要数秒，等待时间留足，避免误判失败而回滚；进程已退出则不再等待。
	for i = 1, 150 do
		if ready(state) then pause(); return ready(state) end
		if i > 10 and not pid_for(state.config_file) then return false end
		pause()
	end
	return false
end

local function nonempty(value)
	if value ~= nil and value ~= "" then return value end
end

-- 默认实例（全局节点）的生成参数：与 app_acl.lua 读取全局选项、run_singbox/run_xray 组装 JSON 的方式一致。
-- 其它实例（访问控制、Socks）的选项变化会改变配置指纹，由差量热重载处理，这里沿用记录的参数。
local function current_args(state, current, core)
	local args = logic.clone(state.args)
	local global = (logic.sections(current, "global")[1] or {}).options or {}
	state.next_log_file = state.log_file
	if args.flag == "acl_default" then
		args.node = global.node
		args.loglevel = global.loglevel or "warn"
		state.next_log_file = (global.log_node or "0") == "0" and "/dev/null" or api.TMP_ACL_PATH .. "/acl_default.log"
		local keys = {}
		for name in pairs(args) do
			if name:match("^remote_dns_") or name == "remote_rewrite_ttl" then keys[#keys + 1] = name end
		end
		for _, name in ipairs(keys) do args[name] = nil end
		local protocol = global.remote_dns_protocol or "tcp"
		local server, port = api.parseDNS(global.remote_dns or "1.1.1.1:53")
		port = tostring(port)
		local singbox = core == "sing-box"
		if protocol == "udp" or (singbox and protocol == "quic") then
			args.remote_dns_udp_server, args.remote_dns_udp_port = server, port
			args.remote_dns_quic = protocol == "quic" and "1" or nil
		elseif protocol == "tcp" or (singbox and protocol == "tls") then
			args.remote_dns_tcp_server, args.remote_dns_tcp_port = server, port
			args.remote_dns_tls = protocol == "tls" and "1" or nil
		elseif protocol == "doh" or (singbox and protocol == "http3") then
			local value = global.remote_dns_doh or "https://1.1.1.1/dns-query"
			local url = value:match("^[^,]*")
			local host_port = api.get_domain_from_url(url) or ""
			local host = host_port:match("^[^:]*")
			local bootstrap = nonempty(value:match("^[^,]*,(.*)$"))
			if api.is_ip(host) then bootstrap = host end
			args.remote_dns_doh_ip = bootstrap
			args.remote_dns_doh_port = host_port:match("^[^:]*:([^:]*)") or "443"
			args.remote_dns_doh_url = url
			args.remote_dns_doh_host = host
			args.remote_dns_http3 = protocol == "http3" and "1" or nil
		end
		if (global.remote_fakedns or "0") == "1" then
			args.remote_dns_fake = "1"
			if not singbox then args.remote_dns_fake_strategy = global.remote_dns_query_strategy or "UseIPv4" end
		end
		args.remote_dns_detour = global.remote_dns_detour or "remote"
		args.remote_dns_query_strategy = global.remote_dns_query_strategy or "UseIPv4"
		args.remote_dns_client_ip = nonempty(global.remote_dns_client_ip)
		args.remote_rewrite_ttl = singbox and nonempty(global.remote_rewrite_ttl) or nil
		if singbox then
			args.log = state.next_log_file == "/dev/null" and "0" or "1"
			args.logfile = state.next_log_file ~= "/dev/null" and state.next_log_file or nil
		else
			args.log, args.logfile = nil, nil
		end
	end
	args.no_run, args.reload = "1", "1"
	return args
end

local function singbox_api(state, path)
	local control = ((state.old.experimental or {}).clash_api or {})
	if not control.external_controller or not control.external_controller:match("^127%.0%.0%.1:%d+$") then return 2 end
	local secret = control.secret or ""
	if secret:find('["\\\r\n]') then return 1 end
	local options = root .. "/curl.conf"
	if not fs.writefile(options, 'header = "Authorization: Bearer ' .. secret .. '"\n') then return 1 end
	fs.chmod(options, "600")
	local url = "http://" .. control.external_controller .. "/configs/hot-reload"
	local body, status_file = root .. "/api.json", root .. "/http.status"
	local args = "curl --noproxy '*' --connect-timeout 2 --max-time 15 -sS -K " .. quote(options) .. " -H 'Content-Type: application/json'"
	if path then args = args .. " -X PUT --data-binary " .. quote("@" .. path) end
	local result = sys.call(args .. " -o " .. quote(body) .. " -w '%{http_code}' " .. quote(url) .. " >" .. quote(status_file) .. " 2>" .. quote(root .. "/api.log"))
	if result ~= 0 then return 1 end
	local status = tonumber(fs.readfile(status_file))
	if status == 404 or status == 501 or status == 409 then return 2 end
	local response = read_json(body)
	if status ~= 200 or not response or response.hot_reload_version ~= 1 or (path and response.applied ~= true) then return 1 end
	return 0
end

-- geodata：Xray 先重新读取 geoip/geosite 数据并原地重建匹配器（没有配置文件时只做这一步）；
-- sing-box 的规则集由核心监视文件自行重载，不需要额外调用。
local function native_api(state, path, geodata)
	if state.args.reload_native ~= "1" then return 2 end
	if state.core == "sing-box" then return singbox_api(state, path) end
	if geodata and state.args.reload_geodata ~= "1" then return 2 end
	local target = path and quote(path) or (geodata and "" or "--check")
	return command(state.binary, "api reloadconfig --server=127.0.0.1:" .. state.args.reload_api_port ..
		(geodata and " --timeout=60 --geodata " or " --timeout=15 ") .. target)
end

-- 暂存配置必须以 .json 结尾：Xray 按扩展名判断配置格式，"*.json.next" 会被拒绝。
local function side_file(state, kind)
	return (state.state_file:gsub("%.json$", "." .. kind .. ".json"))
end

local function restore(state)
	if state.mode == "none" then return true end
	if state.mode ~= "core" then
		write_json(side_file(state, "restore"), state.old)
		if native_api(state, side_file(state, "restore")) == 0 then
			write_json(state.config_file, state.old)
			return true
		end
	end
	return replace_core(state, state.old)
end

local function clean_transaction()
	for name in fs.dir(root) or function() end do
		-- 同时清理旧版本留下的 *.next／*.restore（完整配置，不应长期保留）。
		if name == "transaction.json" or name == "curl.conf" or name:match("%.next%.json$") or name:match("%.restore%.json$")
			or name:match("%.next$") or name:match("%.restore$") then fs.unlink(root .. "/" .. name) end
	end
end

local function metadata(state, args, log_file)
	return {version = 1, core = state.core, binary = state.binary, config_file = state.config_file, log_file = log_file or state.log_file, args = args or state.args, active = state.active}
end

local function update_monitor(state)
	local path = api.TMP_PATH .. "/script_func"
	for name in fs.dir(path) or function() end do
		local file = path .. "/" .. name
		local content = fs.readfile(file)
		if content and content:find("-c " .. state.config_file .. " >", 1, true) then
			-- 跨核心切换后看门狗必须按新核心的启动命令拉起；看门狗用 pgrep -f 匹配原文，不能加引号。
			local launch = state.switched_core and (state.launch .. " run -c " .. state.config_file .. " ") or content:match("^(.-)>")
			fs.writefile(file, launch .. ">" .. state.next_log_file .. "\n")
		end
	end
end

local app_path = "/usr/share/" .. api.appname
local direct_dns_dir = api.TMP_ACL_PATH

local function config_pids(path)
	local result = {}
	for name in fs.dir("/proc") or function() end do
		if name:match("^%d+$") then
			local args = proc_args(name)
			for i = 1, #args - 1 do
				if args[i] == "-C" and args[i + 1] == path then result[#result + 1] = tonumber(name); break end
			end
		end
	end
	return result
end

local function udp_listening(port)
	return sys.call("netstat -uln 2>/dev/null | grep -q " .. quote(":" .. port .. " ")) == 0
end

-- 已运行的全局直连写集合 DNS：按配置中的集合名对应节点，监听端口取自同一配置。
-- 切换离开的节点保留其服务直到下次完整重启（其它实例或前置 DNS 可能仍指向它），切回时直接复用。
local function direct_dns_server(node)
	for name in fs.dir(direct_dns_dir) or function() end do
		if name:match("^dns_acl_default_direct.*%.conf$") then
			local path = direct_dns_dir .. "/" .. name
			local content = "\n" .. (fs.readfile(path) or "")
			local port = content:match("\nbind%-port%s+(%d+)") or content:match("\nport=(%d+)")
			if port and content:find("psw2_" .. node .. "_white", 1, true) and #config_pids(path) > 0 and udp_listening(port) then
				return { port = port, conf = path }
			end
		end
	end
end

local function stop_direct_dns(server)
	for _, pid in ipairs(config_pids(server.conf)) do nixio.kill(pid, 15) end
	local path = api.TMP_PATH .. "/script_func"
	for name in fs.dir(path) or function() end do
		local content = fs.readfile(path .. "/" .. name)
		if content and content:find("-C " .. server.conf .. " ", 1, true) then fs.unlink(path .. "/" .. name) end
	end
	fs.unlink(server.conf)
end

local function start_direct_dns(node)
	local output = root .. "/direct_dns.log"
	local status = sys.call(app_path .. "/app.sh reload_direct_dns acl_default " .. quote(node) .. " </dev/null >" .. quote(output) .. " 2>&1")
	local port = (fs.readfile(output) or ""):match("PORT=(%d+)")
	local server = { port = port, conf = direct_dns_dir .. "/dns_acl_default_direct_" .. node .. ".conf", started = true }
	if status == 0 and port then
		for _ = 1, 30 do
			if udp_listening(port) then return server end
			pause()
		end
	end
	stop_direct_dns(server)
end

-- 当前防火墙后端的脚本（nftables.sh／iptables.sh）；两者提供相同的热重载入口。
local function firewall_script()
	local tables = api.get_cache_var("USE_TABLES")
	if tables == "nftables" or tables == "iptables" then return app_path .. "/" .. tables .. ".sh" end
end

-- 上游 gen_nftset 在标准输入不是终端时会读取输入作为集合元素，必须显式给出空输入。
local function firewall(args, log)
	local script = firewall_script()
	return script ~= nil and sys.call(script .. " " .. args .. " </dev/null >" .. quote(log or root .. "/firewall.log") .. " 2>&1") == 0
end

local function shunt_switch(node, redir_port)
	return firewall("shunt_switch " .. quote(node) .. " " .. quote(redir_port))
end

-- 规则数据或分流规则内容更新：重建由规则派生的集合（nftables 为一个事务，iptables 为逐个 ipset swap）并重填默认实例的分流子链。
local function refresh_sets(node, redir_port, flush)
	return firewall("refresh_sets " .. quote(node or "") .. " " .. quote(redir_port or "") .. " " .. (flush and "1" or "0"))
end

-- sing-box 规则集原地重写：运行中的核心监视到同名文件被替换后自动重载，与配置事务无关。
local function refresh_rule_sets()
	local generator = package.loaded["luci.passwall2.util_sing-box"]
	if generator and generator.refresh_geofile and not generator.refresh_geofile() then
		api.log(0, "部分 sing-box 规则集转换失败，沿用原文件。")
	end
end

-- passwall2 运行的 dnsmasq 实例（前置 DNS）：标志取自配置文件名 <TMP_ACL_PATH>/<标志>_dnsmasq.conf。
local function dnsmasq_instances()
	local result = {}
	for name in fs.dir("/proc") or function() end do
		if name:match("^%d+$") then
			local args = proc_args(name)
			if (args[1] or ""):match("/dnsmasq_[%w_%-]+$") then
				for i = 2, #args - 1 do
					local flag = args[i] == "-C" and args[i + 1]:match("/([%w_%-]+)_dnsmasq%.conf$")
					if flag then result[#result + 1] = { pid = tonumber(name), flag = flag } end
				end
			end
		end
	end
	return result
end

-- 节点域名的转发规则在 servers-file 中，SIGHUP 即可重读；旧版本启动的实例或接入系统 dnsmasq 时改用差量热重载。
local function node_dns_ready()
	local main = api.get_cache_var("DEFAULT_DNSMASQ_CONF")
	if main and fs.access(main) then return false end
	for _, instance in ipairs(dnsmasq_instances()) do
		local base = api.CACHE_PATH .. "/dnsmasq_" .. instance.flag
		if not fs.access(base .. ".local_dns") or not fs.access(base .. "/000-servers-file.conf") then return false end
	end
	return true
end

-- 节点地址变化：重写各前置 DNS 的节点域名转发并发送 SIGHUP（保留监听与已缓存外的状态），
-- 再把新地址加入直连白名单：字面 IP 与启动时一样全部加入，域名只解析运行中节点图里变化的节点。
local function sync_node_endpoints(previous, current, states)
	for _, instance in ipairs(dnsmasq_instances()) do
		if sys.call("lua " .. app_path .. "/helper_dnsmasq.lua update_servers " .. quote(json.stringify({ FLAG = instance.flag })) .. " >/dev/null 2>&1") ~= 0 then
			return false
		end
		nixio.kill(instance.pid, 1)
	end
	pause()
	firewall("filter_vpsip", "/dev/null")
	local used = {}
	for _, state in ipairs(states) do logic.graph_nodes(current, state.next_args.node, used) end
	local before, after, hosts = logic.node_endpoints(previous), logic.node_endpoints(current), {}
	for id in pairs(used) do
		local node = logic.node(current, id) or {}
		if after[id] and before[id] ~= after[id] then
			for _, host in ipairs({ node.address or "", node.download_address or "" }) do
				if host ~= "" and not api.is_ip(host) then hosts[#hosts + 1] = quote(host) end
			end
		end
	end
	if #hosts > 0 then firewall("filter_vps_addr " .. table.concat(hosts, " "), "/dev/null") end
	return true
end

-- 生成器在热重载时把直连拨号的节点追加到 direct_node_list：去重后为新的“地址:端口”补充本机放行规则（已有的跳过）。
local function sync_direct_nodes()
	if not firewall_script() then return end
	local path = api.TMP_PATH .. "/direct_node_list"
	local seen, lines = {}, {}
	for line in (fs.readfile(path) or ""):gmatch("[^\n]+") do
		if not seen[line] then seen[line] = true; lines[#lines + 1] = line end
	end
	if #lines == 0 then return end
	fs.writefile(path, table.concat(lines, "\n") .. "\n")
	firewall("filter_direct_node_list", "/dev/null")
end

local function node_label(snapshot_data, id)
	local node = logic.node(snapshot_data, id) or {}
	return (node.remarks and node.remarks ~= "") and node.remarks or id
end

-- 全局节点改用另一种核心时的目标核心；非 Xray/sing-box 节点保持原核心，交由节点图检查回退。
local function target_core(state, current)
	if state.args.flag ~= "acl_default" then return state.core end
	local global = (logic.sections(current, "global")[1] or {}).options or {}
	local node = logic.node(current, global.node) or {}
	local core = (node.type or ""):lower()
	return (core == "sing-box" or core == "xray") and core or state.core
end

-- 稳定分配记录（见 utils.sh stable_get/stable_set）：控制端口与 secret 按实例沿用，差量热重载生成的配置才与运行中的一致。
local function stable_value(key)
	for line in (fs.readfile(api.TMP_PATH .. "/stable") or ""):gmatch("[^\n]+") do
		local k, v = line:match("^(%S+)%s+(%S+)")
		if k == key then return v end
	end
end

local function stable_store(key, value)
	sys.call(". " .. app_path .. "/utils.sh; stable_set " .. quote(key) .. " " .. quote(value))
end

-- 与 app.sh 的 run_singbox/run_xray 与 prepare_reload_api 一致，按目标核心补齐或去掉专有参数。
local function switch_core_args(args, core, binary)
	args.tags, args.reload_api_secret, args.reload_native, args.reload_geodata = nil, nil, nil, nil
	if core == "sing-box" then
		args.tags = sys.exec(quote(binary) .. " version 2>/dev/null"):match("Tags:%s*(%S+)")
		if not (args.tags or ""):find("with_clash_api", 1, true) then
			args.reload_api_port = nil
			return
		end
		args.reload_api_port = args.reload_api_port or tostring(api.get_new_port(nil, args.flag .. ":api"))
		local secret = stable_value(args.flag .. ":secret")
		if not secret then
			secret = (fs.readfile("/proc/sys/kernel/random/uuid") or ""):gsub("%s", "")
			stable_store(args.flag .. ":secret", secret)
		end
		args.reload_api_secret = secret
		if sys.call(quote(binary) .. " hot-reload-capabilities >/dev/null 2>&1") == 0 then args.reload_native = "1" end
	else
		args.reload_api_port = args.reload_api_port or tostring(api.get_new_port(nil, args.flag .. ":api"))
		local capability = sys.exec(quote(binary) .. " api reloadconfig --local 2>/dev/null") or ""
		if capability:find('"hot_reload_version"', 1, true) then args.reload_native = "1" end
		if capability:find('"geodata":true', 1, true) then args.reload_geodata = "1" end
	end
end

local function set_direct_dns(args, proto, server, port)
	for _, name in ipairs({"direct_dns_udp_server", "direct_dns_udp_port", "direct_dns_tcp_server", "direct_dns_tcp_port"}) do args[name] = nil end
	args["direct_dns_" .. proto .. "_server"], args["direct_dns_" .. proto .. "_port"] = server, port
end

-- 全局节点切换或其分流分类变化：准备防火墙子链替换与直连写集合 DNS。
-- 返回 2 表示快速路径无法处理（改用差量热重载）；context.plan 记录需要提交或回滚的内容。
local function plan_global(state, previous, current, context)
	local old_id, new_id = state.args.node, state.next_args.node
	local old_signature, new_signature = logic.shunt_signature(previous, old_id), logic.shunt_signature(current, new_id)
	if old_id == new_id and logic.equal(old_signature, new_signature) then return end
	local plan = { old = old_id, new = new_id, redir_port = state.args.redir_port }
	if not plan.redir_port or not firewall("shunt_ready", "/dev/null") then return 2 end
	context.plan = plan
	if old_id == new_id then return end
	local args = state.next_args
	if logic.write_ipset_direct(current, new_id) then
		local server = direct_dns_server(new_id)
		if not server then
			if not args.dns_listen_port then return 2 end
			server = start_direct_dns(new_id)
			if not server then api.log(0, "无法为新的全局节点启动直连写集合 DNS，保留当前服务。"); return 1 end
			plan.server = server
		end
		-- 与 run_singbox/run_xray 一致：写集合 DNS 以 UDP 监听，替换原直连 DNS 参数。
		set_direct_dns(args, "udp", "127.0.0.1", server.port)
		local set4, set6 = "psw2_" .. new_id .. "_white", "psw2_" .. new_id .. "_white6"
		if api.get_cache_var("USE_TABLES") == "nftables" then
			args.direct_nftset, args.direct_ipset = "4#inet#passwall2#" .. set4 .. ",6#inet#passwall2#" .. set6, nil
			api.set_cache_var("node_" .. new_id .. "_direct_nftset4", set4)
			api.set_cache_var("node_" .. new_id .. "_direct_nftset6", set6)
		else
			args.direct_ipset, args.direct_nftset = set4 .. "," .. set6, nil
			api.set_cache_var("node_" .. new_id .. "_direct_ipset4", set4)
			api.set_cache_var("node_" .. new_id .. "_direct_ipset6", set6)
		end
	elseif logic.write_ipset_direct(previous, old_id) then
		-- 旧版本启动时没有记录原始直连 DNS，无法安全恢复。
		if not args.direct_dns_base_proto or not args.direct_dns_base_server or not args.direct_dns_base_port then return 2 end
		set_direct_dns(args, args.direct_dns_base_proto, args.direct_dns_base_server, args.direct_dns_base_port)
		args.direct_nftset, args.direct_ipset = nil, nil
	end
end

-- 恢复防火墙子链并停止本次新启动的直连 DNS；子链替换本身是原子的，重复执行无副作用。
local function restore_global(plan)
	local ok = shunt_switch(plan.old, plan.redir_port)
	if plan.server then stop_direct_dns(plan.server) end
	return ok
end

local function update_global_cache(node, redir_port, remarks)
	api.set_cache_var("ACL_acl_default_node", node)
	api.set_cache_var("node_" .. node .. "_redir_port", redir_port)
	-- 使用默认实例的访问控制条目（含全局条目本身）共用分流子链，同步各自 var 文件中的节点记录，
	-- 以后重新生成防火墙规则时与运行状态一致。
	local label = (remarks or node):gsub('[%%"\n\\]', "")
	for sid in fs.dir(api.TMP_ACL_PATH) or function() end do
		local file = api.TMP_ACL_PATH .. "/" .. sid .. "/var"
		local text = "\n" .. (fs.readfile(file) or "")
		if text:find('\nuse="acl_default"\n', 1, true) then
			text = text:gsub('\nnode="[^"\n]*"', '\nnode="' .. node .. '"')
			text = text:gsub('\nnode_remarks="[^"\n]*"', '\nnode_remarks="' .. label .. '"')
			fs.writefile(file, text:sub(2))
		end
	end
end

local function prepare(states, previous, current, context)
	for _, state in ipairs(states) do
		if not pid_for(state.config_file) then return 2 end
		state.next_core, state.next_binary = target_core(state, current), state.binary
		state.next_args = current_args(state, current, state.next_core)
		if state.next_core ~= state.core then
			-- 跨核心切换只能替换核心进程：进程内的连接与 FakeIP 映射无法迁移，但 DNS、防火墙与其它实例保持不变。
			state.next_binary = api.get_app_path(state.next_core)
			if not state.next_binary or not fs.access(state.next_binary) then return 2 end
			switch_core_args(state.next_args, state.next_core, state.next_binary)
		end
		if not logic.native_graph(current, state.next_args.node, state.next_core) then return 2 end
		-- 新出现的出站网卡需要启动时生成的本机放行规则。
		for _, iface in ipairs(logic.graph_ifaces(current, state.next_args.node)) do
			if not fs.access(api.TMP_IFACE_PATH .. "/" .. iface) then return 2 end
		end
		if state.args.flag == "acl_default" then
			local status = plan_global(state, previous, current, context)
			if status then return status end
		end
		state.old = read_json(state.config_file)
		if not state.old then error("运行配置缺失") end
		local generator = require("luci.passwall2.util_" .. (state.next_core == "xray" and "xray" or "sing-box"))
		state.next = json.parse(generator.gen_config(state.next_args))
		if not state.next then error("无法生成新配置") end
		-- 启动路径在生成后把用到的 geosite/geoip 转成规则集文件；进程内生成需要同样补齐，否则校验会缺文件。
		if generator.convert_pending_geofile then generator.convert_pending_geofile() end
		state.mode = logic.equal(state.old, state.next) and state.log_file == state.next_log_file and "none" or "hot"
		-- 规则数据文件已更新：Xray 的匹配器按“文件:代码”缓存，必须显式重载 geodata 才会读取新文件。
		state.geodata = context.refresh and context.refresh.flush and state.next_core == "xray" or nil
		if not validate(state.next_core, state.next_binary, state.next, side_file(state, "next")) then
			api.log(0, "新配置校验失败，保留当前服务。详见 " .. root .. "/check.failed.log")
			return 1
		end
		if state.next_core ~= state.core then
			state.mode = "core"
		elseif state.mode ~= "none" or state.geodata then
			local result = state.mode ~= "none" and native_api(state) or 0
			-- 不支持 geodata 重载的核心改为重启核心，以读取新的规则数据文件。
			if state.geodata and state.args.reload_geodata ~= "1" then result = 2 end
			if result == 2 or state.log_file ~= state.next_log_file then state.mode = "core"
			elseif result ~= 0 then api.log(0, "核心热重载接口不可用，保留当前服务。"); return 1 end
		end
	end
	return 0
end

-- ===== 差量热重载 =====
-- 访问控制、监听端口、本机／客户端代理、DNS、外部输入等改变服务拓扑的配置：按当前配置做一次影子启动
-- （app.sh stage，生成的文件写入暂存目录、进程只登记不启动、防火墙规则写入不挂钩子的影子表），
-- 得到目标状态后与运行状态逐组件比较并提交：未变化的进程不动；核心原生热更新；前置 DNS 与直连写集合 DNS
-- 蓝绿替换（新端口的实例就绪后再切换）；新增实例先启动；防火墙规则在一个 nft 事务中替换；最后停止不再需要的进程。
-- 提交点（防火墙事务）之前的任何失败都会恢复原状态。

local R = require "luci.passwall2.reconcile"
local stage_root = root .. "/stage"
local journal_file = root .. "/reconcile.json"
local real_tmp = api.TMP_PATH
local cache_root = api.CACHE_PATH
local stage_rewrite = R.rewriter({ [stage_root .. "/dnsmasq_cache"] = cache_root, [stage_root] = real_tmp })

local function shell_env(values)
	local parts = {}
	for k, v in pairs(values) do parts[#parts + 1] = k .. "=" .. quote(v) end
	table.sort(parts)
	return table.concat(parts, " ")
end

local function walk(base, rel, callback)
	local dir = rel ~= "" and base .. "/" .. rel or base
	for name in fs.dir(dir) or function() end do
		local child = rel ~= "" and rel .. "/" .. name or name
		local st = fs.lstat(base .. "/" .. child)
		if st and st.type == "lnk" then callback(child, "link", fs.readlink(base .. "/" .. child))
		elseif st and st.type == "dir" then walk(base, child, callback)
		elseif st and st.type == "reg" then callback(child, "file") end
	end
end

-- 影子启动的私有文件（不安装到正式目录）。
local stage_private = {
	log = true, stdout = true, ["stage.env"] = true, ["stage.errors"] = true, preserved_sets = true, flush_sets = true,
	autoswitch = true, ["routes.add"] = true, nft_base_chains = true, var = true, stable = true, ["test.log"] = true,
	["dnsmasq-main.conf"] = true, ["ipt.log"] = true, ipt_snapshot_4 = true, ipt_snapshot_6 = true
}

local function stage_skip(rel)
	local top = rel:match("^[^/]+")
	return stage_private[rel] or top == "process_list" or top == "reload" or top == "dnsmasq_cache" or top == "gen_cache" or
		top == "bin" or top == "script_func" or rel:match("%.log$") or rel:match("%.pid$")
end

-- 运行目录中由启动流程生成、需要与目标状态比较的文件（日志、pid、运行时生成的测试配置等除外）。
local function managed(rel)
	local top = rel:match("^[^/]+")
	if top == "reload" or top == "script_func" or top == "bin" or top == "process_list" or top == "sub_crontabs" then return false end
	if rel == "var" or rel == "stable" or rel == "test.log" or rel:match("%.log$") or rel:match("%.pid$") or rel:match("%.sock$") then return false end
	if rel:match("^ipt_snapshot_") then return false end
	if rel == "PSW2_RULE.nft" or rel:match("^refresh_sets") or rel:match("test_node_") or rel:match("url_test_") then return false end
	return true
end

-- 目标状态中不再存在时可以删除的文件：启动流程生成的配置与列表。
local function deletable(rel)
	return managed(rel) and (rel:match("^acl/") or rel:match("^[^/]+%.json$") or rel:match("^haproxy/") or rel:match("^iface/") or
		rel:match("^route/") or rel:match("_plugin%.sh$") or rel == "direct_node_list") and true or false
end

local function run_stage(fresh, refresh)
	sys.call("rm -rf " .. quote(stage_root) .. "; nft delete table inet passwall2_stage >/dev/null 2>&1")
	fs.mkdirr(stage_root .. "/gen_cache")
	fs.mkdirr(stage_root .. "/dnsmasq_cache")
	fs.chmod(stage_root, "700")
	-- 分流规则的上次记录：影子启动据此判断是否要清空直连写集合（提交时写回正式缓存）。
	for name in fs.dir(cache_root) or function() end do
		if name:match("^cache_[%w_%-]+%.txt$") then fs.writefile(stage_root .. "/gen_cache/" .. name, fs.readfile(cache_root .. "/" .. name) or "") end
	end
	local env = {
		PW2_STAGE = "1", PW2_TMP_PATH = stage_root, PW2_LOG_FILE = stage_root .. "/log",
		PW2_STABLE_HINT = real_tmp .. "/stable", PW2_STABLE_FRESH = table.concat(fresh or {}, " "),
		PW2_DNSMASQ_CACHE = stage_root .. "/dnsmasq_cache", PW2_GEN_CACHE = stage_root .. "/gen_cache"
	}
	if refresh then env.PW2_STAGE_REFRESH = "1" end
	-- iptables 后端的影子启动查询内置链时需要其它程序的规则：保存当前规则快照（与 iptables.sh 选用同一套命令）。
	sys.call("ipt=$(command -v iptables-legacy || command -v iptables); ip6t=$(command -v ip6tables-legacy || command -v ip6tables); " ..
		"[ -n \"$ipt\" ] && ${ipt}-save > " .. quote(stage_root .. "/ipt_snapshot_4") .. " 2>/dev/null; " ..
		"[ -n \"$ip6t\" ] && ${ip6t}-save > " .. quote(stage_root .. "/ipt_snapshot_6") .. " 2>/dev/null")
	local status = sys.call(shell_env(env) .. " " .. app_path .. "/app.sh stage </dev/null >" .. quote(stage_root .. "/stdout") .. " 2>&1")
	local errors = (fs.readfile(stage_root .. "/stage.errors") or ""):gsub("%s+$", "")
	if status ~= 0 or errors ~= "" then
		sys.call("nft delete table inet passwall2_stage >/dev/null 2>&1")
		if errors ~= "" then return false, "实例 [" .. errors:gsub("%s+", ", ") .. "] 的新配置校验失败" end
		return false, "影子启动失败，详见 " .. stage_root .. "/stdout"
	end
	return true
end

local function sorted_entries(dir)
	local names = {}
	for name in fs.dir(dir) or function() end do names[#names + 1] = name end
	table.sort(names, function(a, b)
		local na, nb = tonumber(a:match("%d+$")) or 0, tonumber(b:match("%d+$")) or 0
		if na ~= nb then return na < nb end
		return a < b
	end)
	return names
end

-- 读取一侧的状态：生成的文件与链接、二进制链接、登记的进程、核心实例记录、var 与稳定分配。
local function read_model(kind)
	local base = kind == "stage" and stage_root or real_tmp
	local rewrite = kind == "stage" and stage_rewrite or function(text) return text end
	local model = { kind = kind, files = {}, links = {}, bins = {}, procs = {}, instances = {}, cache = {} }
	walk(base, "", function(rel, t, target)
		if rel:match("^bin/[^/]+$") and t == "link" then model.bins[rel:sub(5)] = target; return end
		if kind == "stage" and stage_skip(rel) or kind ~= "stage" and not managed(rel) then return end
		if t == "link" then model.links[rel] = rewrite(target) else model.files[rel] = rewrite(fs.readfile(base .. "/" .. rel) or "") end
	end)
	local registry = base .. (kind == "stage" and "/process_list" or "/script_func")
	for _, name in ipairs(sorted_entries(registry)) do
		local proc = R.parse_command(rewrite(fs.readfile(registry .. "/" .. name) or ""))
		if proc then model.procs[#model.procs + 1] = proc end
	end
	for name in fs.dir(base .. "/reload") or function() end do
		if instance_file(name) then
			local record = read_json(base .. "/reload/" .. name)
			if record and record.version == 1 and record.args and record.args.flag then
				model.instances[record.args.flag] = R.rewrite_value(record, rewrite)
			end
		end
	end
	model.var, model.var_order = R.parse_var(rewrite(fs.readfile(base .. "/var") or ""))
	model.stable = R.parse_pairs(fs.readfile(base .. "/stable") or "")
	if kind == "stage" then
		model.env = R.parse_pairs(fs.readfile(base .. "/stage.env") or "", "=")
		model.preserved, model.flush, model.autoswitch, model.routes = {}, {}, {}, {}
		for name in (fs.readfile(base .. "/preserved_sets") or ""):gmatch("%S+") do model.preserved[name] = true end
		for name in (fs.readfile(base .. "/flush_sets") or ""):gmatch("%S+") do model.flush[name] = true end
		for id in (fs.readfile(base .. "/autoswitch") or ""):gmatch("%S+") do model.autoswitch[#model.autoswitch + 1] = id end
		for line in (fs.readfile(base .. "/routes.add") or ""):gmatch("[^\n]+") do model.routes[#model.routes + 1] = line end
		model.main_dnsmasq = fs.readfile(base .. "/dnsmasq-main.conf")
		if model.main_dnsmasq then model.main_dnsmasq = rewrite(model.main_dnsmasq) end
		model.base_chains = {}
		for line in (fs.readfile(base .. "/nft_base_chains") or ""):gmatch("[^\n]+") do
			local name, spec = line:match("^([^|]+)|(.*)$")
			if name then model.base_chains[name] = spec end
		end
	end
	return model
end

local function rel_path(path)
	if path and path:sub(1, #real_tmp + 1) == real_tmp .. "/" then return path:sub(#real_tmp + 2) end
end

-- 缓存目录中的前置 DNS 文件：目标状态取暂存缓存，运行状态取正式缓存。
local function cache_read(model, name)
	if model.kind == "stage" then
		local content = fs.readfile(stage_root .. "/dnsmasq_cache/" .. name)
		return content and stage_rewrite(content)
	end
	return fs.readfile(cache_root .. "/" .. name)
end

local function cache_dir_files(model, name)
	local result, names = {}, {}
	local base = (model.kind == "stage" and stage_root .. "/dnsmasq_cache/" or cache_root .. "/") .. name
	for file in fs.dir(base) or function() end do names[#names + 1] = file end
	table.sort(names)
	for _, file in ipairs(names) do result[#result + 1] = { name = file, content = cache_read(model, name .. "/" .. file) or "" } end
	return result
end

-- 进程内容摘要：命令、二进制、配置文件，以及前置 DNS 的 conf-dir 中除节点域名集合外的配置
-- （节点域名的转发与集合由节点地址热更新处理，不需要重启前置 DNS）。
local function signature(model)
	return function(proc)
		local parts = { proc.command, proc.output, model.bins[proc.name] or "" }
		for _, word in ipairs(proc.argv) do
			local rel = rel_path(word)
			local content = rel and not rel:match("%.pid$") and model.files[rel]
			if content then
				parts[#parts + 1] = content
				for dir in ("\n" .. content):gmatch("\nconf%-dir=([^\n]+)") do
					local target = model.links[rel_path(dir) or ""] or dir
					local name = target:sub(1, #cache_root + 1) == cache_root .. "/" and target:sub(#cache_root + 2)
					for _, file in ipairs(name and cache_dir_files(model, name) or {}) do
						if file.name ~= "ipset.conf" then parts[#parts + 1] = file.name .. "\0" .. file.content end
					end
				end
			end
		end
		return table.concat(parts, "\0")
	end
end

local function instance_by_config(model, config)
	for _, record in pairs(model.instances) do
		if record.config_file == config then return record end
	end
end

local function proc_kind(proc, model)
	if (proc.name == "sing-box" or proc.name == "xray") and instance_by_config(model, proc.config) then return "core" end
	if proc.name:match("^dnsmasq_") then return "dnsmasq" end
	if proc.config and proc.config:match("/dns_[%w_%-]+_direct_[%w_%-]+%.conf$") then return "direct_dns" end
	if proc.name == "haproxy" then return "haproxy" end
	return "other"
end

local function listen_port(content)
	content = "\n" .. (content or "")
	return content:match("\nport=(%d+)") or content:match("\nbind%-port%s+(%d+)")
end

local function pids_of(argv)
	local result = {}
	for name in fs.dir("/proc") or function() end do
		if name:match("^%d+$") then
			local args = proc_args(name)
			local same = #args == #argv
			for i = 1, #argv do if not same or args[i] ~= argv[i] then same = false; break end end
			if same then result[#result + 1] = tonumber(name) end
		end
	end
	return result
end

local function alive(pid)
	return nixio.kill(pid, 0) and true or false
end

local function stop_pids(pids)
	for _, pid in ipairs(pids) do nixio.kill(pid, 15) end
	for _ = 1, 30 do
		local remaining = false
		for _, pid in ipairs(pids) do if alive(pid) then remaining = true end end
		if not remaining then return end
		pause()
	end
	for _, pid in ipairs(pids) do if alive(pid) then nixio.kill(pid, 9) end end
end

local function launch(proc)
	sys.call("nohup " .. proc.command .. " >" .. quote(proc.output) .. " 2>&1 &")
end

local function port_listening(port)
	return sys.call("netstat -tuln 2>/dev/null | grep -q " .. quote(":" .. port .. " ")) == 0
end

-- 新进程就绪：配置中有监听端口的等端口出现，否则确认进程在一秒后仍在运行。
local function wait_ready(proc, before, content)
	local port = listen_port(content)
	for i = 1, port and 50 or 10 do
		local found
		for _, pid in ipairs(pids_of(proc.argv)) do
			local old = false
			for _, p in ipairs(before or {}) do if p == pid then old = true end end
			if not old then found = pid end
		end
		if found and (not port and i >= 10 or port and port_listening(port)) then return found end
		pause()
	end
end

-- 文件写入：先写临时文件再改名；backups 记录原内容，提交点之前失败时恢复。
local function path_state(path)
	local st = fs.lstat(path)
	if not st then return { path = path, type = "none" } end
	if st.type == "lnk" then return { path = path, type = "link", target = fs.readlink(path) } end
	return { path = path, type = "file", content = fs.readfile(path) or "", mode = st.modedec and tostring(st.modedec) or "644" }
end

-- 权限：核心配置与稳定分配记录含认证参数／secret，仅所有者可读；其余（前置 DNS 降权后还要重读的
-- servers-file 等）保持启动时的 644。
local function file_mode(path)
	if path:match("%.json$") or path:match("/stable$") then return "600" end
	return "644"
end

local function put_file(path, content, backups)
	if backups then backups[#backups + 1] = path_state(path) end
	fs.mkdirr(path:match("^(.*)/[^/]+$"))
	local st = fs.lstat(path)
	if st and st.type == "lnk" then fs.unlink(path) end
	if not fs.writefile(path .. ".pw2tmp", content) then error("无法写入 " .. path) end
	fs.chmod(path .. ".pw2tmp", file_mode(path))
	if not fs.rename(path .. ".pw2tmp", path) then error("无法写入 " .. path) end
end

local function put_link(path, target, backups)
	if backups then backups[#backups + 1] = path_state(path) end
	fs.mkdirr(path:match("^(.*)/[^/]+$"))
	local st = fs.lstat(path)
	if st and st.type == "dir" then sys.call("rm -rf " .. quote(path)) elseif st then fs.unlink(path) end
	if not fs.symlink(target, path) then error("无法创建链接 " .. path) end
end

local function restore_paths(backups)
	for i = #backups, 1, -1 do
		local item = backups[i]
		local st = fs.lstat(item.path)
		if st and st.type == "dir" then sys.call("rm -rf " .. quote(item.path)) elseif st then fs.unlink(item.path) end
		if item.type == "file" then fs.writefile(item.path, item.content); fs.chmod(item.path, item.mode or "644")
		elseif item.type == "link" then fs.symlink(item.target, item.path) end
	end
end

-- 前置 DNS 的实例缓存目录（conf-dir 指向的目录与 servers-file 等）按暂存缓存整体安装。
local function install_cache(flag, backups)
	local name = "dnsmasq_" .. flag
	for _, suffix in ipairs({ ".servers", ".local_dns", ".txt" }) do
		local content = cache_read({ kind = "stage" }, name .. suffix)
		if content then put_file(cache_root .. "/" .. name .. suffix, content, backups) end
	end
	local dir = cache_root .. "/" .. name
	for file in fs.dir(dir) or function() end do
		if backups then backups[#backups + 1] = path_state(dir .. "/" .. file) end
		fs.unlink(dir .. "/" .. file)
	end
	for _, file in ipairs(cache_dir_files({ kind = "stage" }, name)) do put_file(dir .. "/" .. file.name, file.content, backups) end
end

-- 进程启动前需要的文件：命令行与配置内容中引用的生成文件与链接。
local function referenced(desired, proc)
	local result, seen = {}, {}
	local function add(path)
		local rel = rel_path(path)
		if not rel or seen[rel] or rel:match("%.pid$") or rel:match("%.log$") then return end
		seen[rel] = true
		if desired.files[rel] or desired.links[rel] then
			result[#result + 1] = rel
			for inner in (desired.files[rel] or ""):gmatch("(" .. real_tmp:gsub("%p", "%%%0") .. "/[^%s\"',;]+)") do add(inner) end
		end
	end
	for _, word in ipairs(proc.argv) do add(word) end
	return result
end

local function install_rel(desired, rel, backups)
	if desired.links[rel] then put_link(real_tmp .. "/" .. rel, desired.links[rel], backups)
	elseif desired.files[rel] then put_file(real_tmp .. "/" .. rel, desired.files[rel], backups) end
end

local function core_state(record)
	return { version = 1, core = record.core, binary = record.binary, config_file = record.config_file, log_file = record.log_file,
		args = record.args, active = true, state_file = root .. "/instance_" .. record.args.flag .. ".json" }
end

local function nft_capture(args)
	local output = root .. "/nft.out"
	if sys.call("nft " .. args .. " >" .. quote(output) .. " 2>&1") ~= 0 then return nil, fs.readfile(output) end
	return fs.readfile(output) or ""
end

local function ip_rule_present(family)
	return sys.call("ip " .. (family == 6 and "-6 " or "") .. "rule show 2>/dev/null | grep -q 'fwmark 0x50535732 lookup 999'") == 0
end

local function set_ip_rules(family, wanted)
	local ip = "ip " .. (family == 6 and "-6 " or "")
	local default = family == 6 and "::/0" or "0.0.0.0/0"
	if wanted and not ip_rule_present(family) then
		sys.call(ip .. "rule add fwmark 0x50535732 table 999 priority 999 >/dev/null 2>&1; " .. ip .. "route add local " .. default .. " dev lo table 999 >/dev/null 2>&1")
	elseif not wanted and ip_rule_present(family) then
		sys.call(ip .. "rule del fwmark 0x50535732 >/dev/null 2>&1; " .. ip .. "route del local " .. default .. " dev lo table 999 >/dev/null 2>&1")
	end
end

-- 只存在于运行中记录的 var：启动时备份的系统设置（bak_*），以及端口分配游标（影子启动沿用记录时不会推进）。
local function runtime_var(key)
	return key:match("^bak_") or key == "last_get_new_port_auto"
end

-- 端口分配标记（get_port_<端口>，避免同一端口重复分配）：节点测速等临时实例也会写入，并行测速靠它错开端口。
-- 不代表配置变化，比较时忽略；提交时只写回目标状态中的标记（临时实例留下的随之清除）。
local function allocation_marker(key)
	return key:match("^get_port_") ~= nil
end

local function label_list(items)
	return #items > 0 and table.concat(items, "、") or nil
end

-- dry：只做影子启动与比较，把计划写到标准输出，不改动运行状态（app.sh 之外的诊断入口 reload.lua plan）。
local function reconcile(previous, current, dry)
	if not fs.access(real_tmp .. "/stable") then return 2 end
	if fs.access(journal_file) then
		-- 上次差量提交被中断：状态无法确定，交给完整重启。
		if not dry then fs.unlink(journal_file) end
		return 2
	end
	local refresh = logic.refresh_reason(previous, current)
	local ok, err = run_stage(nil, refresh ~= nil)
	if not ok then api.log(0, "差量热重载未执行：" .. err .. "；保留当前服务。"); return 1 end
	local desired, actual = read_model("stage"), read_model("current")
	-- 启动流程只在加载了透明代理规则时记录 USE_TABLES。
	local desired_tables, actual_tables = desired.var.USE_TABLES or "", actual.var.USE_TABLES or ""

	-- process_plan 的摘要函数按进程所属一侧计算。
	local desired_sig, actual_sig = signature(desired), signature(actual)
	local desired_set = {}
	for _, proc in ipairs(desired.procs) do desired_set[proc] = true end
	local plan = R.process_plan(desired.procs, actual.procs, function(proc) return desired_set[proc] and desired_sig(proc) or actual_sig(proc) end)

	-- 内容变化的前置 DNS 与直连写集合 DNS 需要换用新端口（新实例就绪后才切换）：换键重新做一次影子启动。
	local fresh, inverse = {}, {}
	for key, value in pairs(desired.stable) do inverse[value] = key end
	for _, change in ipairs(plan.change) do
		local kind = proc_kind(change.new, desired)
		if kind == "dnsmasq" or kind == "direct_dns" then
			local key = inverse[listen_port(desired.files[rel_path(change.new.config) or ""]) or ""]
			if key then fresh[#fresh + 1] = key end
		end
	end
	local blue_green = {}
	if #fresh > 0 then
		ok, err = run_stage(fresh, refresh ~= nil)
		if not ok then api.log(0, "差量热重载未执行：" .. err .. "；保留当前服务。"); return 1 end
		desired = read_model("stage")
		desired_sig, desired_set = signature(desired), {}
		for _, proc in ipairs(desired.procs) do desired_set[proc] = true end
		plan = R.process_plan(desired.procs, actual.procs, function(proc) return desired_set[proc] and desired_sig(proc) or actual_sig(proc) end)
		for _, change in ipairs(plan.change) do
			local kind = proc_kind(change.new, desired)
			if kind == "dnsmasq" or kind == "direct_dns" then blue_green[change.new.key] = true end
		end
	end

	-- 防火墙：目标规则集（影子表）与运行中的规则集。
	local fw_script, fw_summary, obsolete_sets = nil, nil, {}
	if desired_tables == "nftables" then
		local stage_text, stage_err = nft_capture("list table inet passwall2_stage")
		if not stage_text then
			api.log(0, "差量热重载未执行：无法读取影子规则（" .. (stage_err or ""):gsub("%s+$", "") .. "）。")
			return 1
		end
		local current_text = nft_capture("list table inet passwall2")
		local flush = {}
		for name in pairs(desired.flush) do flush[name] = true end
		if refresh and refresh.flush then
			for name in stage_text:gmatch("set%s+(psw2_[%w_]+_white6?)%s*{") do flush[name] = true end
		end
		fw_script, fw_summary = R.nft_commit(R.parse_nft(stage_text), current_text and R.parse_nft(current_text) or nil,
			{ table = "inet passwall2", base = desired.base_chains, preserved = desired.preserved, flush = flush })
		if not fw_script then
			sys.call("nft delete table inet passwall2_stage >/dev/null 2>&1")
			api.log(0, "差量热重载未执行：" .. fw_summary .. "，改为完整重启。")
			return 2
		end
		obsolete_sets = fw_summary.sets_obsolete
		fs.writefile(root .. "/reconcile.nft", fw_script)
		fs.chmod(root .. "/reconcile.nft", "600")
		local _, check_err = nft_capture("-c -f " .. quote(root .. "/reconcile.nft"))
		if check_err then
			sys.call("nft delete table inet passwall2_stage >/dev/null 2>&1")
			api.log(0, "差量热重载未执行：新防火墙规则未通过 nft 校验，详见 " .. root .. "/nft.out")
			return 1
		end
	end
	sys.call("nft delete table inet passwall2_stage >/dev/null 2>&1")

	-- iptables：重放规则配方得到目标规则，与运行中的配方比较；集合按目标与系统中的实际内容比较。
	local ipt_desired, ipt_plan, ipt_changed
	if desired_tables == "iptables" then
		local base = {}
		for _, family in ipairs({ "4", "6" }) do
			for name, model in pairs(R.ipt_strip(R.ipt_parse_save(fs.readfile(stage_root .. "/ipt_snapshot_" .. family) or ""))) do
				base[family .. " " .. name] = model
			end
		end
		local entries = R.ipt_log(fs.readfile(stage_root .. "/ipt.log") or "")
		ipt_desired = R.ipt_replay(base, entries)
		local running = actual_tables == "iptables" and fs.readfile(real_tmp .. "/ipt.log")
		ipt_changed = not running or not R.ipt_equal(ipt_desired, R.ipt_replay(base, R.ipt_log(running)))
		local flush = {}
		for name in pairs(desired.flush) do flush[name] = true end
		local wanted = R.ipset_model(entries)
		if refresh and refresh.flush then
			for name in pairs(wanted.sets) do if name:match("_white6?$") then flush[name] = true end end
		end
		ipt_plan = R.ipset_plan(wanted, R.ipset_parse_list(sys.exec("ipset list 2>/dev/null") or ""),
			{ preserved = desired.preserved, flush = flush, referenced = R.ipt_referenced_sets(ipt_desired) })
		obsolete_sets = ipt_plan.obsolete
	end

	-- 核心实例：目标与运行中按标志对应。运行中的核心按配置差异原生热更新（必要时重启核心）；
	-- 未运行的实例只有在登记的命令或配置变化时才尝试启动（与看门狗的职责不重叠）。
	local cores, core_starts, removed_cores = {}, {}, {}
	local desired_by_config, touched = {}, {}
	for _, proc in ipairs(desired.procs) do if proc.config then desired_by_config[proc.config] = proc end end
	for _, proc in ipairs(plan.start) do if proc.config then touched[proc.config] = true end end
	for _, change in ipairs(plan.change) do if change.new.config then touched[change.new.config] = true end end
	for flag, record in pairs(desired.instances) do
		local old = actual.instances[flag]
		local running = old and old.config_file == record.config_file and pid_for(old.config_file)
		if running then
			local state = core_state(old)
			state.record = record
			state.old = read_json(state.config_file)
			state.next = json.parse(desired.files[rel_path(record.config_file) or ""] or "")
			if not state.old or not state.next then api.log(0, "差量热重载未执行：实例 [" .. flag .. "] 的配置无法读取。"); return 1 end
			state.next_args, state.next_log_file, state.next_core, state.next_binary = record.args, record.log_file, record.core, record.binary
			if logic.equal(state.old, state.next) and state.log_file == record.log_file and state.core == record.core and state.binary == record.binary then
				state.mode = "none"
			elseif state.core ~= record.core or state.binary ~= record.binary or state.log_file ~= record.log_file then
				state.mode = "core"
			else
				state.mode = "hot"
				local status = native_api(state)
				if status == 2 then state.mode = "core"
				elseif status ~= 0 then api.log(0, "差量热重载未执行：实例 [" .. flag .. "] 的热重载接口不可用。"); return 1 end
			end
			state.geodata = refresh and refresh.flush and state.core == "xray" and state.mode ~= "core" or nil
			cores[#cores + 1] = state
		elseif touched[record.config_file] and desired_by_config[record.config_file] then
			core_starts[#core_starts + 1] = desired_by_config[record.config_file]
		end
	end
	for flag, old in pairs(actual.instances) do
		local record = desired.instances[flag]
		if not record or record.config_file ~= old.config_file then removed_cores[#removed_cores + 1] = core_state(old) end
	end

	-- 分类核心之外的进程操作（核心的启停由上面的实例记录处理）。
	local starts, swaps, restarts, reloads, stops = {}, {}, {}, {}, {}
	for _, proc in ipairs(plan.start) do
		if proc_kind(proc, desired) ~= "core" then starts[#starts + 1] = proc end
	end
	for _, change in ipairs(plan.change) do
		local kind = proc_kind(change.new, desired)
		if kind == "core" or proc_kind(change.old, actual) == "core" then
		elseif blue_green[change.new.key] then swaps[#swaps + 1] = change
		elseif kind == "haproxy" then reloads[#reloads + 1] = change
		else restarts[#restarts + 1] = change end
	end
	for _, proc in ipairs(plan.stop) do
		if proc_kind(proc, actual) ~= "core" then stops[#stops + 1] = proc end
	end
	for _, proc in ipairs(core_starts) do starts[#starts + 1] = proc end

	-- 前置 DNS 的节点域名转发（servers-file）与国内 DNS 记录只需原地重读：内容变化时安装新文件并发送 SIGHUP，
	-- 不重启实例（与节点地址热更新相同）；节点域名的集合规则（ipset.conf）一并更新，下次启动生效。
	local soft = {}
	local function soft_files(flag)
		local name, result, hup = "dnsmasq_" .. flag, {}, false
		for _, suffix in ipairs({ ".servers", ".local_dns", ".txt", "/ipset.conf" }) do
			local want = cache_read(desired, name .. suffix)
			if want and want ~= cache_read(actual, name .. suffix) then
				result[#result + 1] = { path = cache_root .. "/" .. name .. suffix, content = want }
				if suffix == ".servers" or suffix == ".local_dns" then hup = true end
			end
		end
		return result, hup
	end
	for _, item in ipairs(plan.keep) do
		if proc_kind(item.new, desired) == "dnsmasq" then
			local files, hup = soft_files(item.new.name:sub(#"dnsmasq_" + 1))
			if #files > 0 then soft[#soft + 1] = { proc = item.new, files = files, hup = hup } end
		end
	end
	if desired.main_dnsmasq and desired.main_dnsmasq == (fs.readfile(desired.var.DEFAULT_DNSMASQ_CONF or "") or "") then
		local files, hup = soft_files("acl_default")
		if #files > 0 then soft[#soft + 1] = { main = true, files = files, hup = hup } end
	end
	local soft_changed = false
	for _, item in ipairs(soft) do if item.hup then soft_changed = true end end

	-- firewall.passwall2 include 变化（例如路径）：防火墙规则不变，但要按新路径重写防火墙重载时的恢复脚本。
	local include_changed = desired_tables ~= "" and not logic.equal((previous.external or {}).firewall, (current.external or {}).firewall)
	local fw_changed = fw_script ~= nil and fw_summary.changed or
		ipt_plan ~= nil and (ipt_changed or #ipt_plan.create > 0 or #ipt_plan.swap > 0 or #ipt_plan.add > 0)
	-- 不再需要透明代理规则，或换了防火墙后端：提交后清除旧后端的规则。
	local fw_clear = actual_tables ~= "" and desired_tables ~= actual_tables
	local core_changed = false
	for _, state in ipairs(cores) do if state.mode ~= "none" or state.geodata then core_changed = true end end
	-- 核心配置由不同的生成路径写出（脚本与进程内热重载），比较 JSON 内容而不是排版。
	local function same_file(rel)
		local a, b = desired.files[rel], actual.files[rel]
		if a == b then return true end
		if a and b and rel == "direct_node_list" then
			-- 直连节点列表在运行时去重重写，按行集合比较。
			local sa, sb = {}, {}
			for line in a:gmatch("[^\n]+") do sa[line] = true end
			for line in b:gmatch("[^\n]+") do sb[line] = true end
			return logic.equal(sa, sb)
		end
		if not a or not b or not rel:match("%.json$") then return false end
		local ja, jb = json.parse(a), json.parse(b)
		return ja ~= nil and jb ~= nil and logic.equal(ja, jb)
	end
	local files_changed = false
	for rel in pairs(desired.files) do if not same_file(rel) then files_changed = true; break end end
	for rel in pairs(actual.files) do if deletable(rel) and desired.files[rel] == nil then files_changed = true; break end end
	for rel, target in pairs(desired.links) do if actual.links[rel] ~= target then files_changed = true end end
	local main_changed = (desired.main_dnsmasq or "") ~= (fs.readfile(desired.var.DEFAULT_DNSMASQ_CONF or "") or "")
	local var_changed = false
	for key, value in pairs(desired.var) do if actual.var[key] ~= value and not allocation_marker(key) then var_changed = true end end
	for key in pairs(actual.var) do
		if desired.var[key] == nil and not runtime_var(key) and not allocation_marker(key) then var_changed = true end
	end
	if not logic.equal(desired.stable, actual.stable) then var_changed = true end
	if not fw_changed and not fw_clear and #obsolete_sets == 0 and not core_changed and #starts == 0 and #swaps == 0 and
		#restarts == 0 and #reloads == 0 and #stops == 0 and #removed_cores == 0 and not files_changed and not main_changed and
		not var_changed and not refresh and #soft == 0 and not include_changed and desired.env.DHCP_DNS_REDIRECT ~= "1" then
		if dry then print("plan: none") return 0, "none" end
		api.log(1, "配置重载：差量比较无运行时变化")
		return 0, "none"
	end
	if dry then
		local function names(list, field)
			local result = {}
			for _, item in ipairs(list) do
				local proc = item.new or item
				result[#result + 1] = field and item[field] or proc.name .. ":" .. (proc.config or proc.command)
			end
			return table.concat(result, " ")
		end
		local modes = {}
		for _, state in ipairs(cores) do modes[#modes + 1] = state.args.flag .. "=" .. state.mode .. (state.geodata and "+geodata" or "") end
		local changed_files, changed_vars = {}, {}
		for rel in pairs(desired.files) do if not same_file(rel) then changed_files[#changed_files + 1] = rel end end
		for rel in pairs(actual.files) do if deletable(rel) and desired.files[rel] == nil then changed_files[#changed_files + 1] = "-" .. rel end end
		for key, value in pairs(desired.var) do
			if actual.var[key] ~= value and not allocation_marker(key) then changed_vars[#changed_vars + 1] = key end
		end
		table.sort(changed_files)
		table.sort(changed_vars)
		print("plan: changes")
		print("firewall: " .. (fw_clear and "clear-" .. actual_tables .. " " or "") .. (fw_changed and "replace-" .. desired_tables or "same") ..
			(fw_summary and (" added_sets=" .. table.concat(fw_summary.sets_added, ",") .. " refreshed=" .. table.concat(fw_summary.sets_refreshed, ",") ..
			" obsolete=" .. table.concat(obsolete_sets, ",") .. " chains+=" .. table.concat(fw_summary.chains_added, ",") ..
			" chains-=" .. table.concat(fw_summary.chains_removed, ",")) or ""))
		print("cores: " .. table.concat(modes, " "))
		print("start: " .. names(starts))
		print("swap: " .. names(swaps))
		print("restart: " .. names(restarts))
		print("reload: " .. names(reloads))
		print("stop: " .. names(stops))
		local removed = {}
		for _, state in ipairs(removed_cores) do removed[#removed + 1] = state.args.flag end
		print("removed_cores: " .. table.concat(removed, " "))
		print("files: " .. table.concat(changed_files, " "))
		print("var: " .. table.concat(changed_vars, " "))
		print("main_dnsmasq: " .. tostring(main_changed))
		local soft_names = {}
		for _, item in ipairs(soft) do soft_names[#soft_names + 1] = (item.main and "main" or item.proc.name) .. (item.hup and "+hup" or "") end
		print("soft_dns: " .. table.concat(soft_names, " "))
		return 0, "plan"
	end

	-- dnsmasq 主实例（DNS 劫持只拦截发往本机的查询时接入主实例）：安装或删除 passwall2 的配置并重启主实例。
	local main_file = desired.var.DEFAULT_DNSMASQ_CONF
	local main_before = main_file and fs.readfile(main_file) or nil
	main_changed = (desired.main_dnsmasq or "") ~= (main_before or "")
	local main_mount = desired.var.DEFAULT_DNSMASQ_CONF_PATH or (real_tmp .. "/acl/acl_default_dnsmasq.d")
	local function main_dnsmasq_apply(revert)
		local content = revert and main_before or desired.main_dnsmasq
		if content then
			sys.call("lua " .. app_path .. "/helper_dnsmasq.lua stretch >/dev/null 2>&1")
			if not revert then install_cache("acl_default") end
			put_file(main_file, content)
			fs.chmod(main_file, "644")
			sys.call("uci -q del_list dhcp.@dnsmasq[0].addnmount=" .. quote(main_mount) ..
				"; uci -q add_list dhcp.@dnsmasq[0].addnmount=" .. quote(main_mount) .. "; uci -q commit dhcp")
			sys.call("lua " .. app_path .. "/helper_dnsmasq.lua logic_restart >/dev/null 2>&1")
		else
			fs.unlink(main_file)
			sys.call("uci -q del_list dhcp.@dnsmasq[0].addnmount=" .. quote(main_mount) .. "; uci -q commit dhcp; /etc/init.d/dnsmasq restart >/dev/null 2>&1")
		end
	end
	-- 新接入主实例时先让主实例带上新配置，再切换防火墙；离开或内容变化在提交点之后处理。
	local main_entered = false

	-- ===== 提交点之前：拉起新进程、蓝绿替换的新实例、原生热更新核心、替换防火墙；失败则全部恢复。 =====
	write_json(journal_file, { started = os.time() })
	local backups, launched, applied = {}, {}, {}
	-- iptables 提交：集合先于规则（规则按名称引用集合）。内容替换的集合经临时集合交换，旧内容留在临时集合中，
	-- 规则提交失败时换回；规则按地址族各一个 iptables-restore 事务，完整启动时会失败的单条命令按出错行剔除后重试。
	local swapped, ipt_saved = {}, {}
	local function ipset_call(args)
		if sys.call("ipset " .. args .. " >" .. quote(root .. "/ipset.out") .. " 2>&1") ~= 0 then
			error("ipset " .. args:match("^%S+%s*%S*") .. " 失败：" .. (fs.readfile(root .. "/ipset.out") or ""):gsub("%s+$", ""))
		end
	end
	local function ipset_fill(name, elements)
		if #elements == 0 then return end
		local lines = {}
		for _, element in ipairs(elements) do lines[#lines + 1] = "add " .. name .. " " .. element end
		fs.writefile(root .. "/ipset.restore", table.concat(lines, "\n") .. "\nCOMMIT\n")
		ipset_call("-! restore -f " .. quote(root .. "/ipset.restore"))
	end
	local function apply_iptables()
		for _, item in ipairs(ipt_plan.create) do
			ipset_call("-! create " .. item.name .. " " .. item.spec)
			ipset_fill(item.name, item.elements)
		end
		for _, item in ipairs(ipt_plan.add) do ipset_fill(item.name, item.elements) end
		for _, item in ipairs(ipt_plan.swap) do
			local tmp = R.ipset_temp_name(item.name)
			sys.call("ipset -q destroy " .. tmp)
			ipset_call("create " .. tmp .. " " .. item.spec)
			ipset_fill(tmp, item.elements)
			ipset_call("swap " .. tmp .. " " .. item.name)
			swapped[#swapped + 1] = { name = item.name, tmp = tmp }
		end
		if not ipt_changed then return end
		for _, family in ipairs({ "4", "6" }) do
			local bin = sys.exec("command -v " .. (family == "6" and "ip6tables-legacy || command -v ip6tables" or "iptables-legacy || command -v iptables")):gsub("%s+$", "")
			if bin ~= "" then
				-- 提交前保存 nat/mangle 两张表，后续步骤失败时整表恢复。
				ipt_saved[#ipt_saved + 1] = { bin = bin, family = family, rules = sys.exec(bin .. "-save -t nat 2>/dev/null; " .. bin .. "-save -t mangle 2>/dev/null") }
				local script = R.ipt_restore_script(ipt_desired, R.ipt_parse_save(sys.exec(bin .. "-save 2>/dev/null") or ""), family)
				local lines = {}
				for line in (script or ""):gmatch("[^\n]+") do lines[#lines + 1] = line end
				local applied_ok = #lines == 0
				for _ = 1, 50 do
					if applied_ok then break end
					fs.writefile(root .. "/ipt" .. family .. ".restore", table.concat(lines, "\n") .. "\n")
					fs.chmod(root .. "/ipt" .. family .. ".restore", "600")
					if sys.call(bin .. "-restore --noflush < " .. quote(root .. "/ipt" .. family .. ".restore") .. " >" .. quote(root .. "/ipt.out") .. " 2>&1") == 0 then
						applied_ok = true
					else
						local bad = tonumber(((fs.readfile(root .. "/ipt.out") or ""):match("Error occurred at line: (%d+)")))
						if not bad or not lines[bad] or not lines[bad]:match("^%-[AI] PSW2") and not lines[bad]:match("^%-I ") then
							error("iptables 规则提交失败：" .. (fs.readfile(root .. "/ipt.out") or ""):gsub("%s+$", ""))
						end
						table.remove(lines, bad)
					end
				end
				if not applied_ok then error("iptables 规则提交失败：无效规则过多") end
			end
		end
	end
	local function restore_sets()
		for i = #ipt_saved, 1, -1 do
			local path = root .. "/ipt" .. ipt_saved[i].family .. ".saved"
			fs.writefile(path, ipt_saved[i].rules)
			fs.chmod(path, "600")
			sys.call(ipt_saved[i].bin .. "-restore < " .. quote(path) .. " >/dev/null 2>&1")
			fs.unlink(path)
		end
		for i = #swapped, 1, -1 do
			sys.call("ipset swap " .. swapped[i].tmp .. " " .. swapped[i].name .. " >/dev/null 2>&1; ipset -q destroy " .. swapped[i].tmp)
		end
	end

	local function rollback(message)
		pcall(restore_sets)
		if main_entered then pcall(main_dnsmasq_apply, true) end
		for i = #applied, 1, -1 do pcall(restore, applied[i]) end
		for i = #launched, 1, -1 do pcall(stop_pids, { launched[i] }) end
		pcall(restore_paths, backups)
		fs.unlink(journal_file)
		clean_transaction()
		api.log(0, message .. "，已恢复原状态。")
		return 1
	end
	local done, failure = pcall(function()
		-- 二进制链接（新名称，或二进制路径变化）。
		for name, target in pairs(desired.bins) do
			if actual.bins[name] ~= target then put_link(real_tmp .. "/bin/" .. name, target, backups) end
		end
		local function start_proc(proc, before, tolerant)
			for _, rel in ipairs(referenced(desired, proc)) do install_rel(desired, rel, backups) end
			local kind = proc_kind(proc, desired)
			if kind == "dnsmasq" then install_cache(proc.name:sub(#"dnsmasq_" + 1), backups) end
			local record = kind == "core" and instance_by_config(desired, proc.config)
			if record then
				local state = core_state(record)
				state.launch = launch_path(record.core, record.binary)
				sys.call("nohup " .. quote(state.launch) .. " run -c " .. quote(record.config_file) .. " >" .. quote(record.log_file or "/dev/null") .. " 2>&1 &")
				-- 监听端口可能被其它程序占用：就绪后再确认进程仍在运行；进程已退出则不再等待。
				for i = 1, 150 do
					if ready(state) then
						for _ = 1, 5 do pause() end
						local pid = pid_for(record.config_file)
						if pid and ready(state) then launched[#launched + 1] = pid; return true end
						break
					end
					if i > 10 and not pid_for(record.config_file) then break end
					pause()
				end
			else
				launch(proc)
				local pid = wait_ready(proc, before, desired.files[rel_path(proc.config) or ""])
				if pid then launched[#launched + 1] = pid; return true end
			end
			for _, pid in ipairs(pids_of(proc.argv)) do
				local old = false
				for _, p in ipairs(before or {}) do if p == pid then old = true end end
				if not old then stop_pids({ pid }) end
			end
			if tolerant then api.log(1, "进程未能启动（与完整启动时一样跳过）：" .. proc.command); return false end
			error("进程未能启动：" .. proc.command)
		end
		for _, proc in ipairs(starts) do
			local kind = proc_kind(proc, desired)
			-- Socks、负载均衡与桥接进程启动失败时与完整启动一样跳过；透明代理的核心与 DNS 失败则放弃本次重载。
			local record = kind == "core" and instance_by_config(desired, proc.config)
			local tolerant = kind == "other" or kind == "haproxy" or (record and not desired.files["acl/" .. record.args.flag .. "/var"])
			proc.started = start_proc(proc, {}, tolerant)
		end
		for _, change in ipairs(swaps) do
			change.before = pids_of(change.old.argv)
			start_proc(change.new, change.before, false)
		end
		for _, state in ipairs(cores) do
			if state.mode ~= "none" or state.geodata then
				applied[#applied + 1] = state
				if state.mode == "hot" or state.geodata then
					local path = state.mode == "hot" and side_file(state, "next") or nil
					if path then write_json(path, state.next) end
					local result = native_api(state, path, state.geodata)
					-- Socks 与桥接实例热重载失败（如新监听端口被占用）时改为重启核心，起不来则与完整启动一样跳过。
					local tolerant = not desired.files["acl/" .. state.args.flag .. "/var"]
					if result == 2 or result ~= 0 and tolerant then state.mode = "core"
					elseif result ~= 0 then error("实例 [" .. state.args.flag .. "] 热重载失败") end
				end
				if state.mode == "core" then
					if not replace_core(state, state.next, state.next_log_file, state.next_core, state.next_binary) then
						-- Socks 与桥接实例与完整启动时一样跳过（例如端口被其它程序占用）；透明代理实例则放弃本次重载。
						if desired.files["acl/" .. state.args.flag .. "/var"] then error("实例 [" .. state.args.flag .. "] 核心重启失败") end
						api.log(1, "实例 [" .. state.args.flag .. "] 未能按新配置启动（与完整启动时一样跳过），详见其日志。")
						state.failed = true
					end
				elseif state.mode == "hot" then
					write_json(state.config_file, state.next)
				end
			end
		end
		if main_changed and desired.main_dnsmasq and not main_before then
			-- 主实例重启前写好 var，logic_restart 按其中的 DEFAULT_DNS 备份上游。
			put_file(real_tmp .. "/var", R.format_var(desired.var, desired.var_order), backups)
			main_entered = true
			main_dnsmasq_apply()
		end
		if fw_changed and fw_script then
			local _, apply_err = nft_capture("-f " .. quote(root .. "/reconcile.nft"))
			if apply_err then error("防火墙规则替换失败：" .. apply_err:gsub("%s+$", "")) end
		elseif fw_changed and ipt_plan then
			apply_iptables()
		end
	end)
	if not done then return rollback("差量热重载失败（" .. tostring(failure) .. "）") end

	-- ===== 提交点之后：停止旧进程、安装状态、系统设置与辅助进程；失败只记录。 =====
	local notes = {}
	local function step(name, fn)
		local good, problem = pcall(fn)
		if not good then api.log(0, "差量热重载的后续步骤失败（" .. name .. "）：" .. tostring(problem)) end
	end
	step("清除防火墙规则", function()
		if fw_clear and actual_tables ~= "" then
			sys.call(app_path .. "/" .. actual_tables .. ".sh clear </dev/null >" .. quote(root .. "/firewall.log") .. " 2>&1")
		end
	end)
	step("停止旧进程", function()
		for _, change in ipairs(swaps) do
			stop_pids(change.before)
			-- dnsmasq 退出时删除自己的 pid 文件，新实例的 pid 文件随之消失：按新实例重写。
			for i, word in ipairs(change.new.argv) do
				if word == "-x" and change.new.argv[i + 1] then
					local pids = pids_of(change.new.argv)
					if pids[1] then fs.writefile(change.new.argv[i + 1], pids[1] .. "\n") end
				end
			end
		end
		for _, proc in ipairs(stops) do
			stop_pids(pids_of(proc.argv))
			local base = proc.config and proc.config:match("^(.*)%.json$")
			if base then
				local plugin = fs.readfile(base .. "_plugin.pid")
				if plugin and tonumber(plugin:match("%d+")) then nixio.kill(tonumber(plugin:match("%d+")), 9) end
			end
		end
		for _, state in ipairs(removed_cores) do stop_core(state) end
	end)
	step("删除不再使用的集合", function()
		for _, item in ipairs(swapped) do sys.call("ipset -q destroy " .. item.tmp) end
		if ipt_plan then
			for _, name in ipairs(obsolete_sets) do sys.call("ipset -q destroy " .. quote(name)) end
			return
		end
		local lines = {}
		for _, name in ipairs(obsolete_sets) do lines[#lines + 1] = "delete set inet passwall2 " .. name end
		if #lines > 0 then
			fs.writefile(root .. "/reconcile-sets.nft", table.concat(lines, "\n") .. "\n")
			nft_capture("-f " .. quote(root .. "/reconcile-sets.nft"))
		end
	end)
	step("重启变化的进程", function()
		for _, change in ipairs(restarts) do
			stop_pids(pids_of(change.old.argv))
			for _, rel in ipairs(referenced(desired, change.new)) do install_rel(desired, rel) end
			if proc_kind(change.new, desired) == "dnsmasq" then install_cache(change.new.name:sub(#"dnsmasq_" + 1)) end
			launch(change.new)
		end
		for _, change in ipairs(reloads) do
			for _, rel in ipairs(referenced(desired, change.new)) do install_rel(desired, rel) end
			local old = pids_of(change.old.argv)
			local pids = {}
			for _, pid in ipairs(old) do pids[#pids + 1] = tostring(pid) end
			-- haproxy 软重载：新进程接管监听，旧进程处理完已有连接后退出。
			sys.call("nohup " .. change.new.command .. (#pids > 0 and " -sf " .. table.concat(pids, " ") or "") .. " >" .. quote(change.new.output) .. " 2>&1 &")
		end
	end)
	step("安装状态文件", function()
		for rel in pairs(desired.links) do if actual.links[rel] ~= desired.links[rel] then install_rel(desired, rel) end end
		for rel in pairs(desired.files) do if not same_file(rel) then install_rel(desired, rel) end end
		for rel in pairs(actual.files) do
			if desired.files[rel] == nil and deletable(rel) then fs.unlink(real_tmp .. "/" .. rel) end
		end
		for rel in pairs(actual.links) do
			if desired.links[rel] == nil and deletable(rel) then fs.unlink(real_tmp .. "/" .. rel) end
		end
		for name in fs.dir(real_tmp .. "/acl") or function() end do
			local st = fs.lstat(real_tmp .. "/acl/" .. name)
			if st and st.type == "dir" and not desired.files["acl/" .. name .. "/var"] then sys.call("rm -rf " .. quote(real_tmp .. "/acl/" .. name)) end
		end
		-- 前置 DNS 缓存：新实例与蓝绿替换已安装；分流规则缓存记录写回正式缓存。
		for name in fs.dir(stage_root .. "/gen_cache") or function() end do
			fs.writefile(cache_root .. "/" .. name, fs.readfile(stage_root .. "/gen_cache/" .. name) or "")
		end
		-- var：运行中才有的记录沿用（系统设置备份只在透明代理保持运行时沿用）。
		local values, order = desired.var, desired.var_order
		for key, value in pairs(actual.var) do
			if runtime_var(key) and values[key] == nil and (desired_tables ~= "" or not key:match("^bak_")) then
				values[key] = value
				order[#order + 1] = key
			end
		end
		put_file(real_tmp .. "/var", R.format_var(values, order))
		-- iptables 的规则配方随规则一起更新（运行时改动会继续追加）。
		if desired_tables == "iptables" then put_file(real_tmp .. "/ipt.log", fs.readfile(stage_root .. "/ipt.log") or "") end
		local stable = {}
		for key, value in pairs(desired.stable) do stable[#stable + 1] = key .. " " .. value end
		table.sort(stable)
		put_file(real_tmp .. "/stable", table.concat(stable, "\n") .. (#stable > 0 and "\n" or ""))
		local registry = real_tmp .. "/script_func"
		for name in fs.dir(registry) or function() end do fs.unlink(registry .. "/" .. name) end
		fs.mkdirr(registry)
		for i, proc in ipairs(desired.procs) do fs.writefile(registry .. "/queued_" .. i, proc.line .. "\n") end
		for name in fs.dir(root) or function() end do
			if instance_file(name) then fs.unlink(root .. "/" .. name) end
		end
		for flag, record in pairs(desired.instances) do
			local state = core_state(record)
			state.active = pid_for(record.config_file) ~= nil
			write_json(state.state_file, metadata(state))
			fs.chmod(record.config_file, "600")
		end
	end)
	step("前置 DNS 原地更新", function()
		for _, item in ipairs(soft) do
			for _, file in ipairs(item.files) do put_file(file.path, file.content) end
			if item.hup and item.proc then
				for _, pid in ipairs(pids_of(item.proc.argv)) do nixio.kill(pid, 1) end
			elseif item.hup then
				sys.call("for p in $(busybox pgrep -f '/var/etc/dnsmasq[.]conf'); do kill -HUP $p; done")
			end
		end
		if soft_changed then notes[#notes + 1] = "前置 DNS 的节点域名转发已原地重读（SIGHUP）" end
	end)
	step("dnsmasq 主实例", function()
		if desired.env.DHCP_DNS_REDIRECT == "1" then
			sys.call("uci -q set " .. api.appname .. ".@global[0].dnsmasq_dns_redirect='1'; uci -q commit " .. api.appname ..
				"; uci -q set dhcp.@dnsmasq[0].dns_redirect='0'; uci -q commit dhcp")
		end
		if main_changed and not main_entered then
			main_dnsmasq_apply()
			notes[#notes + 1] = "dnsmasq 主实例已按新配置重启"
		elseif desired.env.DHCP_DNS_REDIRECT == "1" then
			sys.call("/etc/init.d/dnsmasq restart >/dev/null 2>&1")
		end
	end)
	step("系统设置", function()
		-- 与 start/stop 一致：透明代理运行期间关闭网桥的 netfilter 调用，停止时按备份恢复。
		local active, was_active = desired_tables ~= "", actual_tables ~= ""
		set_ip_rules(4, active)
		set_ip_rules(6, active and desired.env.PROXY_IPV6 == "1")
		if active then
			local var = R.parse_var(fs.readfile(real_tmp .. "/var") or "")
			local function disable(name, key)
				if not var[key] then
					sys.call(". " .. app_path .. "/utils.sh; set_cache_var " .. key .. " \"$(sysctl -e -n net.bridge." .. name .. ")\"")
				end
				sys.call("sysctl -w net.bridge." .. name .. "=0 >/dev/null 2>&1")
			end
			disable("bridge-nf-call-iptables", "bak_bridge_nf_ipt")
			if desired.env.PROXY_IPV6 == "1" then disable("bridge-nf-call-ip6tables", "bak_bridge_nf_ip6t") end
		elseif was_active then
			if actual.var.bak_bridge_nf_ipt then sys.call("sysctl -w net.bridge.bridge-nf-call-iptables=" .. quote(actual.var.bak_bridge_nf_ipt) .. " >/dev/null 2>&1") end
			if actual.var.bak_bridge_nf_ip6t then sys.call("sysctl -w net.bridge.bridge-nf-call-ip6tables=" .. quote(actual.var.bak_bridge_nf_ip6t) .. " >/dev/null 2>&1") end
		end
		-- 负载均衡节点的出口路由：按目标状态增删。
		local old_routes, new_routes = {}, {}
		for rel, content in pairs(actual.files) do
			if rel:match("^route/") then for ip in content:gmatch("%S+") do old_routes[rel:sub(7) .. " " .. ip] = true end end
		end
		for rel, content in pairs(desired.files) do
			if rel:match("^route/") then for ip in content:gmatch("%S+") do new_routes[rel:sub(7) .. " " .. ip] = true end end
		end
		for item in pairs(old_routes) do
			if not new_routes[item] then
				local dev, ip = item:match("^(%S+) (%S+)$")
				sys.call("route del -host " .. quote(ip) .. " dev " .. quote(dev) .. " >/dev/null 2>&1")
			end
		end
		-- 新增路由沿用 add_ip2route 的解析；路由记录已随状态文件安装，这里的记录写到临时目录后丢弃。
		local scratch = root .. "/routes.tmp"
		for _, line in ipairs(desired.routes) do
			local host, iface = line:match("^(%S+)%s+(%S+)$")
			if host then
				fs.mkdirr(scratch)
				sys.call(". " .. app_path .. "/utils.sh; TMP_ROUTE_PATH=" .. quote(scratch) .. "; LOG_FILE=/dev/null; add_ip2route " .. quote(host) .. " " .. quote(iface) .. " >/dev/null 2>&1")
			end
		end
		sys.call("rm -rf " .. quote(scratch))
		if active and desired_tables ~= "" then
			sys.call(app_path .. "/" .. desired_tables .. ".sh post_reconcile </dev/null >" .. quote(root .. "/firewall.log") .. " 2>&1")
			-- 与启动时一样在后台补充节点地址到 psw2_vps（只增不减）。
			sys.call("(" .. app_path .. "/" .. desired_tables .. ".sh filter_vpsip; " .. app_path .. "/" .. desired_tables .. ".sh filter_vps_addr " ..
				quote(desired.env.NODE and (logic.node(current, desired.env.NODE) or {}).address or "") .. ") </dev/null >/dev/null 2>&1 &")
		end
	end)
	step("辅助进程", function()
		-- Socks 自动切换：每轮重新读取配置，只需按目标状态增减进程。
		local wanted, running = {}, {}
		for _, id in ipairs(desired.autoswitch) do wanted[id] = true end
		for name in fs.dir("/proc") or function() end do
			if name:match("^%d+$") then
				local args = proc_args(name)
				if args[2] == app_path .. "/socks_auto_switch.sh" and args[3] then
					if wanted[args[3]] then running[args[3]] = true else nixio.kill(tonumber(name), 15) end
				end
			end
		end
		for id in pairs(wanted) do
			if not running[id] then sys.call(app_path .. "/socks_auto_switch.sh " .. quote(id) .. " >/dev/null 2>&1 &") end
		end
		local has_copy = false
		for _, proc in ipairs(desired.procs) do if proc_kind(proc, desired) == "dnsmasq" then has_copy = true end end
		if has_copy then sys.call(app_path .. "/lease2hosts.sh >/dev/null 2>&1 &") end
		-- 节点地址变化：保留的前置 DNS 重读节点域名转发，新地址加入直连白名单（与核心热重载一致）。
		if not logic.equal(logic.node_endpoints(previous), logic.node_endpoints(current)) then
			local states = {}
			for _, record in pairs(desired.instances) do states[#states + 1] = { next_args = record.args } end
			sync_node_endpoints(previous, current, states)
		end
		sync_direct_nodes()
		if refresh and refresh.flush then refresh_rule_sets() end
	end)
	local function enabled(snapshot_data) return ((logic.sections(snapshot_data, "global")[1] or {}).options or {}).enabled or "0" end
	if not logic.equal(logic.schedule_signature(previous), logic.schedule_signature(current)) or
		(desired_tables ~= "") ~= (actual_tables ~= "") or enabled(previous) ~= enabled(current) then
		step("计划任务", function() sys.call(app_path .. "/app.sh reload_crontab </dev/null >/dev/null 2>&1") end)
	end
	if refresh and refresh.flush then
		sys.call("uci -q delete " .. api.appname .. ".@global[0].flush_set; uci -q commit " .. api.appname)
	end
	fs.unlink(journal_file)
	clean_transaction()

	local started, swapped, stopped, reloaded = {}, {}, {}, {}
	for _, proc in ipairs(starts) do
		local record = instance_by_config(desired, proc.config)
		if proc.started then started[#started + 1] = record and record.args.flag or proc.name end
	end
	for _, change in ipairs(swaps) do swapped[#swapped + 1] = change.new.name end
	for _, proc in ipairs(stops) do stopped[#stopped + 1] = proc.name end
	for _, state in ipairs(removed_cores) do stopped[#stopped + 1] = state.args.flag end
	for _, state in ipairs(cores) do
		if state.mode == "hot" then reloaded[#reloaded + 1] = state.args.flag .. "（原生热更新）"
		elseif state.mode == "core" then reloaded[#reloaded + 1] = state.args.flag .. (state.failed and "（未能启动，已跳过）" or "（重启核心）") end
	end
	local parts = {}
	if fw_changed then
		parts[#parts + 1] = ipt_plan and "iptables 规则已按表原子替换" or "防火墙规则已在一个 nft 事务中替换"
	end
	if fw_clear then parts[#parts + 1] = desired_tables ~= "" and ("已从 " .. actual_tables .. " 切换到 " .. desired_tables) or "透明代理规则已清除" end
	if include_changed then parts[#parts + 1] = "防火墙 include 已按新设置重写" end
	if label_list(reloaded) then parts[#parts + 1] = "核心：" .. label_list(reloaded) end
	if label_list(started) then parts[#parts + 1] = "新启动：" .. label_list(started) end
	if label_list(swapped) then parts[#parts + 1] = "蓝绿替换：" .. label_list(swapped) end
	if label_list(stopped) then parts[#parts + 1] = "已停止：" .. label_list(stopped) end
	if main_entered then parts[#parts + 1] = "dnsmasq 主实例已接入并按新配置重启" end
	for _, note in ipairs(notes) do parts[#parts + 1] = note end
	if #parts == 0 then parts[1] = "状态文件已更新" end
	api.log(1, "差量热重载完成，未完整重启：" .. table.concat(parts, "；"))
	return 0, "reconciled"
end

local function run_reload()
	local previous = read_json(root .. "/snapshot.json")
	if not previous then return 2 end
	local interrupted = read_json(root .. "/transaction.json")
	if interrupted then
		for _, backup in ipairs(interrupted.instances or interrupted) do
			if not restore(backup) then error("无法恢复中断的重载事务") end
			write_json(backup.state_file, metadata(backup))
		end
		if interrupted.global and not restore_global(interrupted.global) then error("无法恢复中断的防火墙切换") end
		clean_transaction()
	end
	local states, current = instances(), snapshot()
	-- 影响服务拓扑的变化、或核心快速路径无法处理的情形，改用差量热重载。
	local function fallback()
		local status, result = reconcile(previous, current)
		if status == 0 then
			-- 提交本身会改变外部输入（防火墙后端记录、接入 dnsmasq 主实例时的 addnmount 等），按提交后的值记录，
			-- 否则下一次重载会因此误判为拓扑变化。passwall2 配置仍用提交前读取的版本，其后的修改由排队的重载处理。
			if result ~= "none" then current.external = snapshot().external end
			if result ~= "none" or not logic.equal(previous, current) then write_json(root .. "/snapshot.json", current) end
		end
		return status
	end
	if not logic.equal(logic.fingerprint(previous), logic.fingerprint(current)) or #states == 0 then return fallback() end
	local context = {
		refresh = logic.refresh_reason(previous, current),
		endpoints = not logic.equal(logic.node_endpoints(previous), logic.node_endpoints(current))
	}
	-- 集合热刷新需要启动时建立的分流子链（旧版本加载的规则没有）；节点地址热更新需要 servers-file 布局。
	-- 不满足时改用差量热重载（其防火墙事务与前置 DNS 替换不依赖这些结构）。
	if context.refresh and not firewall("shunt_ready", "/dev/null") then return fallback() end
	if context.endpoints and (not firewall_script() or not node_dns_ready()) then return fallback() end
	local ok, status = pcall(prepare, states, previous, current, context)
	if not ok or status ~= 0 then
		-- 准备阶段尚未改动核心与防火墙，只需停止本次新启动的直连 DNS。
		if context.plan and context.plan.server then stop_direct_dns(context.plan.server) end
		clean_transaction()
		if not ok then error(status, 0) end
		if status == 2 then return fallback() end
		return status
	end
	local plan = context.plan
	if context.refresh and context.refresh.flush then refresh_rule_sets() end
	-- 节点域名转发与直连白名单只会增加直连条目，先于核心更新，使核心解析新节点域名时得到真实地址。
	if context.endpoints and not sync_node_endpoints(previous, current, states) then
		api.log(0, "无法更新前置 DNS 的节点域名转发，保留当前服务。")
		clean_transaction()
		return 1
	end
	local backups = {}
	for _, state in ipairs(states) do
		if state.mode ~= "none" then
			local backup = metadata(state)
			backup.state_file, backup.old, backup.mode = state.state_file, state.old, state.mode
			backups[#backups + 1] = backup
		end
	end
	write_json(root .. "/transaction.json", { instances = backups, global = plan })
	local applied = {}
	local function rollback(message)
		local restored = true
		for i = #applied, 1, -1 do
			local done, result = pcall(restore, applied[i])
			if not done or not result then restored = false end
		end
		if plan then
			local done, result = pcall(restore_global, plan)
			if not done or not result then restored = false end
		end
		if restored then clean_transaction() end
		api.log(0, restored and message or "重载及回滚失败，保留事务以供下次恢复。")
		return 1
	end
	for _, state in ipairs(states) do
		if state.mode ~= "none" or state.geodata then
			applied[#applied + 1] = state
			local done, success = pcall(function()
				if state.mode == "hot" or state.geodata then
					local path = state.mode == "hot" and side_file(state, "next") or nil
					local result = state.mode == "core" and 2 or native_api(state, path, state.geodata)
					if result == 2 then state.mode = "core" elseif result ~= 0 then return false end
				end
				if state.mode == "core" then return replace_core(state, state.next, state.next_log_file, state.next_core, state.next_binary) end
				if state.mode == "hot" then write_json(state.config_file, state.next) end
				return true
			end)
			if not done or not success then return rollback("配置重载失败，已恢复原配置。") end
		end
	end
	-- 核心已切到新配置后再原子替换防火墙分流子链；两者之间只有毫秒级窗口，且只影响新连接。
	-- 集合热刷新同时按新的全局节点重填子链，覆盖全局节点切换的子链替换。
	if context.refresh then
		local default
		for _, state in ipairs(states) do if state.args.flag == "acl_default" then default = state end end
		if not refresh_sets(default and default.next_args.node, default and default.args.redir_port, context.refresh.flush) then
			return rollback("防火墙集合热刷新失败，已恢复原配置。详见 " .. root .. "/firewall.log")
		end
	elseif plan and not shunt_switch(plan.new, plan.redir_port) then
		return rollback("防火墙分流子链替换失败，已恢复原配置。详见 " .. root .. "/firewall.log")
	end
	sync_direct_nodes()
	for _, state in ipairs(states) do
		state.next_args.no_run, state.next_args.reload = nil, nil
		local previous_core = state.core
		state.switched_core = state.next_core ~= state.core
		state.core, state.binary = state.next_core, state.next_binary
		write_json(state.state_file, metadata(state, state.next_args, state.next_log_file))
		update_monitor(state)
		if state.args.flag == "acl_default" then
			update_global_cache(state.next_args.node, state.next_args.redir_port, (logic.node(current, state.next_args.node) or {}).remarks)
			if state.args.node ~= state.next_args.node then
				api.log(1, "全局节点热切换：[" .. node_label(previous, state.args.node) .. "] → [" .. node_label(current, state.next_args.node) .. "]" ..
					(plan and "，防火墙分流子链已原子替换" or ""))
			elseif plan then
				api.log(1, "全局分流节点的直连／代理分类已更新，防火墙分流子链已原子替换")
			end
		end
		if state.switched_core then
			api.log(1, "配置重载 [" .. state.args.flag .. "]：跨核心切换（" .. previous_core .. " → " .. state.core .. "），兼容重启核心，保留 DNS 和防火墙；经该核心的已有连接会断开")
		elseif state.geodata and state.mode ~= "core" then
			api.log(1, "配置重载 [" .. state.args.flag .. "]：" .. (state.mode == "hot" and "原生热更新并" or "") .. "原地重载 geodata，保留已有连接")
		else
			api.log(1, "配置重载 [" .. state.args.flag .. "]：" .. ({none = "无运行时变化", hot = "原生热更新，保留已有连接", core = "兼容重启核心，保留 DNS 和防火墙"})[state.mode])
		end
	end
	if context.endpoints then
		api.log(1, "节点地址变化：前置 DNS 的节点域名转发已原地重读（SIGHUP），新地址已加入直连白名单与本机放行规则")
	end
	if context.refresh then
		local notes = context.refresh.flush and { "直连写集合已清空、由 DNS 重新写入" } or {}
		if context.refresh.flush and package.loaded["luci.passwall2.util_sing-box"] then notes[#notes + 1] = "sing-box 规则集已原地更新" end
		api.log(1, "防火墙集合热刷新：由规则派生的集合与分流子链已在一个 nft 事务中原子重建" ..
			(#notes > 0 and "；" .. table.concat(notes, "，") or ""))
	end
	-- 定时选项（启停／重启／规则与订阅更新时间、看门狗开关）只需重建计划任务与相关后台进程。
	if not logic.equal(logic.schedule_signature(previous), logic.schedule_signature(current)) then
		if sys.call(app_path .. "/app.sh reload_crontab </dev/null >/dev/null 2>&1") == 0 then
			api.log(1, "计划任务、看门狗与循环更新已按新设置重建，未重启服务")
		else
			api.log(0, "计划任务重建失败，将在下次启动时生效。")
		end
	end
	if context.refresh and context.refresh.flush then
		-- 与 nftables.sh stop 一样消费一次性标志；命令行提交不会触发 procd 的配置触发器。
		sys.call("uci -q delete " .. api.appname .. ".@global[0].flush_set; uci -q commit " .. api.appname)
		for _, section in ipairs(current.passwall2) do
			if section.type == "global" then section.options.flush_set = nil end
		end
	end
	write_json(root .. "/snapshot.json", current)
	clean_transaction()
	return 0
end

local function main()
	if arg[1] == "record" then
		local args = json.parse(arg[6])
		if not args or not args.flag or not args.flag:match("^[%w_%-]+$") then return 1 end
		if temporary_flag(args.flag) then return 0 end
		fs.mkdir(root)
		fs.chmod(root, "700")
		fs.chmod(arg[4], "600")
		write_json(root .. "/instance_" .. args.flag .. ".json", {version = 1, core = arg[2], binary = arg[3], config_file = arg[4], log_file = arg[5], args = args})
		return 0
	elseif arg[1] == "snapshot" then
		fs.mkdir(root)
		fs.chmod(root, "700")
		for _, state in ipairs(instances(true)) do
			for _ = 1, 20 do if pid_for(state.config_file) then break end; pause() end
			for _ = 1, 5 do pause() end
			state.active = pid_for(state.config_file) ~= nil
			write_json(state.state_file, metadata(state))
			if not state.active then api.log(0, "实例 [" .. state.args.flag .. "] 未启动，不把端口冲突或启动失败的实例当作热重载目标。") end
		end
		write_json(root .. "/snapshot.json", snapshot())
		return 0
	elseif arg[1] == "apply" then return run_reload()
	elseif arg[1] == "plan" then
		-- 诊断：按当前配置做差量比较并打印计划，不提交。
		local previous = read_json(root .. "/snapshot.json")
		if not previous then print("plan: no snapshot") return 2 end
		local status = reconcile(previous, snapshot(), true)
		return status
	end
	return 1
end

local ok, status = pcall(main)
if not ok then api.log(0, "配置重载失败，未执行完整重启；请检查运行日志和重载事务。"); status = 1 end
os.exit(status)
