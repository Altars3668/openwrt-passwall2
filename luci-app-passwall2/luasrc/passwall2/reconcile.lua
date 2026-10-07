-- Copyright (C) 2026 Openwrt-Passwall Organization

-- 差量热重载（影子启动 + 按组件提交）的纯逻辑部分：不依赖 OpenWrt 运行库，便于在本机测试。
-- 执行器（/usr/share/passwall2/reload.lua）负责读写文件、进程与防火墙。

local M = {}

local function escape_pattern(text)
	return (text:gsub("[%^%$%(%)%%%.%[%]%*%+%-%?]", "%%%0"))
end

-- 路径改写：影子启动的暂存路径换成正式路径；前缀按长度从长到短替换，避免短前缀先命中。
-- 生成器输出的 JSON 把 "/" 转义为 "\/"，转义写法同样改写。
function M.rewriter(rules)
	local ordered = {}
	for from, to in pairs(rules) do
		ordered[#ordered + 1] = { from = from, to = to }
		ordered[#ordered + 1] = { from = (from:gsub("/", "\\/")), to = (to:gsub("/", "\\/")) }
	end
	table.sort(ordered, function(a, b) return #a.from > #b.from end)
	return function(text)
		if type(text) ~= "string" then return text end
		for _, rule in ipairs(ordered) do
			text = text:gsub(escape_pattern(rule.from), (rule.to:gsub("%%", "%%%%")))
		end
		return text
	end
end

-- 递归改写表中的全部字符串（实例记录、参数）。
function M.rewrite_value(value, rewrite)
	if type(value) == "string" then return rewrite(value) end
	if type(value) ~= "table" then return value end
	local result = {}
	for k, v in pairs(value) do result[rewrite(k)] = M.rewrite_value(v, rewrite) end
	return result
end

-- 统计一行中引号外的花括号，判断规则或元素列表是否在本行结束。
local function brace_delta(line)
	local delta, quoted = 0, false
	for i = 1, #line do
		local c = line:sub(i, i)
		if c == '"' then quoted = not quoted
		elseif not quoted then
			if c == "{" then delta = delta + 1 elseif c == "}" then delta = delta - 1 end
		end
	end
	return delta
end

local function trim(text)
	return (text:gsub("^%s+", ""):gsub("%s+$", ""))
end

-- 按引号与花括号之外的逗号拆分元素列表。
local function split_elements(text)
	local result, depth, quoted, current = {}, 0, false, {}
	for i = 1, #text do
		local c = text:sub(i, i)
		if c == '"' then quoted = not quoted end
		if not quoted and c == "{" then depth = depth + 1 end
		if not quoted and c == "}" then depth = depth - 1 end
		if c == "," and depth == 0 and not quoted then
			result[#result + 1] = trim(table.concat(current))
			current = {}
		else
			current[#current + 1] = c
		end
	end
	local last = trim(table.concat(current))
	if last ~= "" then result[#result + 1] = last end
	return result
end

-- 元素比较与复制时去掉剩余寿命（expires），它随时间变化且不能写回。
function M.element_key(element)
	return (element:gsub("%s+expires%s+%S+", ""))
end

-- 规则文本去掉计数器的数值，比较与重新提交时都用规范形式。
function M.rule_key(rule)
	return (rule:gsub("counter packets %d+ bytes %d+", "counter"))
end

-- 解析 `nft list table` 的输出：集合（定义行与元素）、链（钩子定义与规则），保持出现顺序。
function M.parse_nft(text)
	local model = { sets = {}, set_order = {}, chains = {}, chain_order = {} }
	local state, current, pending, pending_depth
	for raw in (text or ""):gmatch("[^\n]+") do
		local line = trim(raw)
		if pending then
			pending[#pending + 1] = line
			pending_depth = pending_depth + brace_delta(line)
			if pending_depth <= 0 then
				local joined = table.concat(pending, " ")
				pending = nil
				if state == "set" then
					local body = joined:match("^elements%s*=%s*{(.*)}$") or ""
					for _, element in ipairs(split_elements(body)) do current.elements[#current.elements + 1] = element end
				else
					current.rules[#current.rules + 1] = joined
				end
			end
		elseif line == "" then
		elseif not state then
			if line:match("^table%s+%S+%s+%S+%s*{$") then state = "table" end
		elseif state == "table" then
			local kind, name = line:match("^(%a+)%s+(%S+)%s*{$")
			if kind == "set" or kind == "map" then
				current = { name = name, kind = kind, lines = {}, elements = {} }
				model.sets[name] = current
				model.set_order[#model.set_order + 1] = name
				state = "set"
			elseif kind == "chain" then
				current = { name = name, rules = {} }
				model.chains[name] = current
				model.chain_order[#model.chain_order + 1] = name
				state = "chain"
			elseif line == "}" then
				state = "done"
			end
		elseif line == "}" then
			state = "table"
		elseif state == "set" then
			if line:match("^elements%s*=") then
				pending, pending_depth = { line }, brace_delta(line)
				if pending_depth <= 0 then
					local body = line:match("^elements%s*=%s*{(.*)}$") or ""
					for _, element in ipairs(split_elements(body)) do current.elements[#current.elements + 1] = element end
					pending = nil
				end
			else
				current.lines[#current.lines + 1] = line
			end
		elseif state == "chain" then
			if line:match("^type%s+%S+%s+hook%s") then
				current.hook = line
			else
				local delta = brace_delta(line)
				if delta > 0 then
					pending, pending_depth = { line }, delta
				else
					current.rules[#current.rules + 1] = line
				end
			end
		end
	end
	return model
end

local function element_set(list)
	local result = {}
	for _, element in ipairs(list or {}) do result[M.element_key(element)] = true end
	return result
end

local function same_elements(a, b)
	local sa, sb = element_set(a), element_set(b)
	for k in pairs(sa) do if not sb[k] then return false end end
	for k in pairs(sb) do if not sa[k] then return false end end
	return true
end

local function set_definition(set)
	local parts = {}
	for _, line in ipairs(set.lines) do parts[#parts + 1] = line end
	return table.concat(parts, "; ")
end

local function element_statement(table_name, name, elements)
	local list = {}
	for _, element in ipairs(elements) do list[#list + 1] = M.element_key(element) end
	return "add element " .. table_name .. " " .. name .. " { " .. table.concat(list, ", ") .. " }"
end

-- 集合在提交时的处理方式：
--   keep    运行中已有内容不动（直连写集合、影子启动沿用的规则集合）；
--   union   只补充缺少的元素（psw2_vps 也由前置 DNS 写入；psw2_wan 由防火墙重载补充）；
--   refresh 内容完全由启动流程决定，不同则在同一事务中清空并重填。
function M.set_class(name, options)
	options = options or {}
	if options.flush and options.flush[name] then return "refresh" end
	if options.preserved and options.preserved[name] then return "keep" end
	if name:match("_white6?$") then return "keep" end
	if name == "psw2_vps" or name == "psw2_vps6" or name == "psw2_wan" or name == "psw2_wan6" then return "union" end
	return "refresh"
end

-- 由目标规则集（影子表）与运行中的规则集生成一个 nft 事务：
-- 先补齐集合与链，再清空并按目标顺序重填全部链，最后删除不再使用的链。
-- 运行中的规则集为空（尚未加载防火墙）时等同于完整加载。不再使用的集合由调用者在旧进程停止后删除。
-- options: table（正式表名）、base（基础链名 → 钩子定义）、preserved / flush（集合名集合）。
function M.nft_commit(desired, current, options)
	local table_name = options.table
	current = current or { sets = {}, set_order = {}, chains = {}, chain_order = {} }
	local out, summary = { "add table " .. table_name }, { sets_added = {}, sets_refreshed = {}, sets_obsolete = {}, chains_added = {}, chains_removed = {}, rules_changed = false }
	for _, name in ipairs(desired.set_order) do
		local d, c = desired.sets[name], current.sets[name]
		if not c then
			out[#out + 1] = "add set " .. table_name .. " " .. name .. " { " .. set_definition(d) .. " }"
			if #d.elements > 0 then out[#out + 1] = element_statement(table_name, name, d.elements) end
			summary.sets_added[#summary.sets_added + 1] = name
		else
			if set_definition(d) ~= set_definition(c) then return nil, "集合 " .. name .. " 的定义发生变化" end
			local class = M.set_class(name, options)
			if class == "refresh" and not same_elements(d.elements, c.elements) then
				out[#out + 1] = "flush set " .. table_name .. " " .. name
				if #d.elements > 0 then out[#out + 1] = element_statement(table_name, name, d.elements) end
				summary.sets_refreshed[#summary.sets_refreshed + 1] = name
			elseif class == "union" then
				local have, missing = element_set(c.elements), {}
				for _, element in ipairs(d.elements) do
					if not have[M.element_key(element)] then missing[#missing + 1] = element end
				end
				if #missing > 0 then out[#out + 1] = element_statement(table_name, name, missing) end
			end
		end
	end
	for _, name in ipairs(current.set_order) do
		if not desired.sets[name] then summary.sets_obsolete[#summary.sets_obsolete + 1] = name end
	end
	local base = options.base or {}
	for _, name in ipairs(desired.chain_order) do
		if base[name] then
			out[#out + 1] = "add chain " .. table_name .. " " .. name .. " { " .. base[name] .. " }"
		else
			out[#out + 1] = "add chain " .. table_name .. " " .. name
		end
		if not current.chains[name] then summary.chains_added[#summary.chains_added + 1] = name end
	end
	for _, name in ipairs(desired.chain_order) do
		local d, c = desired.chains[name], current.chains[name]
		local same = c ~= nil and #d.rules == #c.rules
		if same then
			for i, rule in ipairs(d.rules) do
				if M.rule_key(rule) ~= M.rule_key(c.rules[i]) then same = false; break end
			end
		end
		if not same then summary.rules_changed = true end
		out[#out + 1] = "flush chain " .. table_name .. " " .. name
	end
	for _, name in ipairs(current.chain_order) do
		if not desired.chains[name] then
			out[#out + 1] = "flush chain " .. table_name .. " " .. name
			summary.chains_removed[#summary.chains_removed + 1] = name
			summary.rules_changed = true
		end
	end
	for _, name in ipairs(desired.chain_order) do
		for _, rule in ipairs(desired.chains[name].rules) do
			out[#out + 1] = "add rule " .. table_name .. " " .. name .. " " .. M.rule_key(rule)
		end
	end
	for _, name in ipairs(summary.chains_removed) do
		out[#out + 1] = "delete chain " .. table_name .. " " .. name
	end
	summary.changed = summary.rules_changed or #summary.sets_added > 0 or #summary.sets_refreshed > 0
	return table.concat(out, "\n") .. "\n", summary
end

-- 进程登记行（ln_run 的格式：“命令 参数… >输出”）。key 是配置文件路径（-c/-C/-f 之后），没有时用整条命令。
function M.parse_command(line)
	line = trim(line or "")
	if line == "" then return nil end
	local command, output = line:match("^(.-)%s*>%s*(%S*)$")
	if not command then command, output = line, "/dev/null" end
	local argv = {}
	for word in command:gmatch("%S+") do argv[#argv + 1] = word end
	if #argv == 0 then return nil end
	local config
	for i = 2, #argv - 1 do
		if argv[i] == "-c" or argv[i] == "-C" or argv[i] == "-f" then config = argv[i + 1]; break end
	end
	return {
		line = line, command = table.concat(argv, " "), output = output, argv = argv,
		name = argv[1]:match("([^/]+)$"), config = config, key = config or table.concat(argv, " ")
	}
end

-- 以 key 匹配目标进程与运行中的进程。signature(proc) 给出进程内容摘要（命令、配置与其引用的文件）。
-- 返回 start / change / keep / stop 四类列表。
function M.process_plan(desired, current, signature)
	local by_key, plan = {}, { start = {}, change = {}, keep = {}, stop = {} }
	for _, proc in ipairs(current) do by_key[proc.key] = proc end
	local seen = {}
	for _, proc in ipairs(desired) do
		local old = by_key[proc.key]
		seen[proc.key] = true
		if not old then
			plan.start[#plan.start + 1] = proc
		elseif old.command ~= proc.command or old.output ~= proc.output or signature(old, "current") ~= signature(proc, "desired") then
			plan.change[#plan.change + 1] = { old = old, new = proc }
		else
			plan.keep[#plan.keep + 1] = { old = old, new = proc }
		end
	end
	for _, proc in ipairs(current) do
		if not seen[proc.key] then plan.stop[#plan.stop + 1] = proc end
	end
	return plan
end

-- 解析“键 值”行（stable 文件、stage.env 用 KEY=VALUE）。
function M.parse_pairs(text, separator)
	local result = {}
	for line in (text or ""):gmatch("[^\n]+") do
		local key, value
		if separator == "=" then key, value = line:match("^([%w_]+)=(.*)$")
		else key, value = line:match("^(%S+)%s+(%S+)") end
		if key then result[key] = value end
	end
	return result
end

-- 解析 var 文件（KEY="VALUE"，同名以最后一行为准），保留首次出现的顺序。
function M.parse_var(text)
	local values, order = {}, {}
	for line in (text or ""):gmatch("[^\n]+") do
		local key, value = line:match('^([%w_]+)="(.*)"$')
		if key then
			if values[key] == nil then order[#order + 1] = key end
			values[key] = value
		end
	end
	return values, order
end

function M.format_var(values, order)
	local lines, seen = {}, {}
	for _, key in ipairs(order) do
		if values[key] ~= nil and not seen[key] then
			lines[#lines + 1] = key .. '="' .. values[key] .. '"'
			seen[key] = true
		end
	end
	local rest = {}
	for key, value in pairs(values) do if not seen[key] then rest[#rest + 1] = key end end
	table.sort(rest)
	for _, key in ipairs(rest) do lines[#lines + 1] = key .. '="' .. values[key] .. '"' end
	return #lines > 0 and table.concat(lines, "\n") .. "\n" or ""
end


-- ===== iptables 后端 =====
-- iptables.sh 把执行的命令按顺序记录为“规则配方”（ipt.log）；影子启动只记录不执行。这里用一个只覆盖
-- 启动脚本所用命令（-N/-F/-X/-A/-I/-D、-L 查询、iptables-restore 输入）的模拟重放配方，得到各表的目标规则，
-- 再生成按表原子提交的 iptables-restore --noflush 输入。其它程序的规则取自 iptables-save 快照，只用于定位插入位置。

local US, RS = "\031", "\030"

local function split_fields(line)
	local fields = {}
	for field in (line .. US):gmatch("([^" .. US .. "]*)" .. US) do fields[#fields + 1] = field end
	return fields
end

local function slice(list, first)
	local result = {}
	for i = first, #list do result[#result + 1] = list[i] end
	return result
end

-- 解析规则配方：C（iptables 命令）、R（iptables-restore 输入）、S（ipset 命令，-R 带输入）。
function M.ipt_log(text)
	local entries, pending = {}, nil
	for line in ((text or "") .. "\n"):gmatch("([^\n]*)\n") do
		if pending then
			if line == RS then entries[#entries + 1] = pending; pending = nil
			else pending.input[#pending.input + 1] = line end
		elseif line ~= "" then
			local fields = split_fields(line)
			if fields[1] == "C" then
				entries[#entries + 1] = { kind = "C", family = fields[2], table = fields[3], args = slice(fields, 4) }
			elseif fields[1] == "R" then
				pending = { kind = "R", family = fields[2], input = {} }
			elseif fields[1] == "S" then
				local entry = { kind = "S", args = slice(fields, 2) }
				local restore = false
				for _, arg in ipairs(entry.args) do if arg == "-R" or arg == "restore" then restore = true end end
				if restore then entry.input = {}; pending = entry else entries[#entries + 1] = entry end
			end
		end
	end
	return entries
end

local function ipt_table()
	return { chains = {}, order = {}, builtin = {} }
end

local function ipt_chain(model, name, builtin)
	if not model.chains[name] then
		model.chains[name] = {}
		model.order[#model.order + 1] = name
	end
	if builtin then model.builtin[name] = true end
	return model.chains[name]
end

-- iptables-save 输出 → { 表名 = 模型 }。
function M.ipt_parse_save(text)
	local tables, current = {}, nil
	for line in (text or ""):gmatch("[^\n]+") do
		local name = line:match("^%*(%S+)")
		if name then
			current = ipt_table()
			tables[name] = current
		elseif line == "COMMIT" then
			current = nil
		elseif current then
			local chain, policy = line:match("^:(%S+)%s+(%S+)")
			if chain then
				ipt_chain(current, chain, policy ~= "-")
			else
				local target, spec = line:match("^%-A%s+(%S+)%s*(.*)$")
				if target then table.insert(ipt_chain(current, target), spec) end
			end
		end
	end
	return tables
end

local function is_passwall(text)
	return text:find("PSW2", 1, true) ~= nil
end

-- 去掉 passwall2 自己的链与跳转，得到其它程序的规则（模拟的起点）。
function M.ipt_strip(tables)
	local result = {}
	for name, model in pairs(tables or {}) do
		local copy = ipt_table()
		for _, chain in ipairs(model.order) do
			if not chain:match("^PSW2") then
				local rules = ipt_chain(copy, chain, model.builtin[chain])
				for _, rule in ipairs(model.chains[chain]) do
					if not is_passwall(rule) then rules[#rules + 1] = rule end
				end
			end
		end
		result[name] = copy
	end
	return result
end

local function delete_chain(model, name)
	if not model.chains[name] then return false end
	model.chains[name] = nil
	for i, chain in ipairs(model.order) do
		if chain == name then table.remove(model.order, i); break end
	end
	return true
end

-- 在模型上执行一条命令；返回 false 表示失败（链不存在等），list 返回列出的链。
local function ipt_apply(model, args)
	local i = 1
	while args[i] do
		local op = args[i]
		if op == "-N" then
			if model.chains[args[i + 1] or ""] then return false end
			ipt_chain(model, args[i + 1])
			return true
		elseif op == "-F" then
			if not args[i + 1] then
				for _, chain in ipairs(model.order) do model.chains[chain] = {} end
				return true
			end
			if not model.chains[args[i + 1]] then return false end
			model.chains[args[i + 1]] = {}
			return true
		elseif op == "-X" then
			return delete_chain(model, args[i + 1] or "")
		elseif op == "-A" or op == "-I" or op == "-D" then
			local rules = model.chains[args[i + 1] or ""]
			if not rules then return false end
			local position, first = nil, i + 2
			if (op == "-I" or op == "-D") and tonumber(args[i + 2]) then position, first = tonumber(args[i + 2]), i + 3 end
			local spec = table.concat(slice(args, first), " ")
			if op == "-A" then
				rules[#rules + 1] = spec
			elseif op == "-I" then
				position = position or 1
				if position < 1 or position > #rules + 1 then return false end
				table.insert(rules, position, spec)
			else
				if position then
					if not rules[position] then return false end
					table.remove(rules, position)
				else
					for index, rule in ipairs(rules) do
						if rule == spec then table.remove(rules, index); return true end
					end
					return false
				end
			end
			return true
		elseif op == "-L" or op == "--list" or op:match("^%-[a-zA-Z]*L[a-zA-Z]*$") then
			local chain
			for j = i + 1, #args do if args[j]:sub(1, 1) ~= "-" then chain = args[j]; break end end
			return true, chain or ""
		end
		i = i + 1
	end
	return false
end

local function ipt_restore_input(models, family, lines)
	local current
	for _, line in ipairs(lines) do
		local name = line:match("^%*(%S+)")
		if name then
			local key = family .. " " .. name
			models[key] = models[key] or ipt_table()
			current = models[key]
		elseif line == "COMMIT" then
			current = nil
		elseif current then
			local chain = line:match("^:(%S+)")
			if chain then
				ipt_chain(current, chain)
				if not current.builtin[chain] then current.chains[chain] = {} end
			elseif line:match("^%-") then
				local args = {}
				for word in line:gmatch("%S+") do args[#args + 1] = word end
				ipt_apply(current, args)
			end
		end
	end
end

-- 从快照（已去掉 passwall2 规则）重放规则配方，返回 { ["4 nat"] = 模型, ... }。
function M.ipt_replay(base, entries)
	local models = {}
	for key, model in pairs(base or {}) do
		local copy = ipt_table()
		for _, chain in ipairs(model.order) do
			local rules = ipt_chain(copy, chain, model.builtin[chain])
			for _, rule in ipairs(model.chains[chain]) do rules[#rules + 1] = rule end
		end
		models[key] = copy
	end
	for _, entry in ipairs(entries or {}) do
		if entry.kind == "C" then
			local key = entry.family .. " " .. entry.table
			models[key] = models[key] or ipt_table()
			ipt_apply(models[key], entry.args)
		elseif entry.kind == "R" then
			ipt_restore_input(models, entry.family, entry.input)
		end
	end
	return models
end

-- 影子启动中的 -L 查询：与 iptables -n -L 一样先输出两行表头，带 --line-numbers 时行首是序号。
function M.ipt_list(models, family, tname, args)
	local model = models[family .. " " .. tname] or ipt_table()
	local ok, chain = ipt_apply(model, args)
	if not ok or not model.chains[chain] then return nil end
	local numbers = false
	for _, arg in ipairs(args) do if arg:match("^%-%-line%-number") then numbers = true end end
	local lines = { "Chain " .. chain .. (model.builtin[chain] and " (policy ACCEPT)" or " (0 references)"),
		(numbers and "num  " or "") .. "target     prot opt source               destination" }
	for index, rule in ipairs(model.chains[chain]) do
		lines[#lines + 1] = (numbers and (index .. "    ") or "") .. rule
	end
	return table.concat(lines, "\n") .. "\n"
end

-- 目标规则与当前规则是否一致：passwall2 的链内容，以及内置链中 passwall2 跳转的位置。
function M.ipt_equal(a, b)
	local keys = {}
	for key in pairs(a or {}) do keys[key] = true end
	for key in pairs(b or {}) do keys[key] = true end
	for key in pairs(keys) do
		local ma, mb = (a or {})[key] or ipt_table(), (b or {})[key] or ipt_table()
		local names = {}
		for name in pairs(ma.chains) do names[name] = true end
		for name in pairs(mb.chains) do names[name] = true end
		for name in pairs(names) do
			local ra, rb = ma.chains[name], mb.chains[name]
			if name:match("^PSW2") or ma.builtin[name] or mb.builtin[name] then
				if (ra == nil) ~= (rb == nil) then return false end
				if ra and #ra ~= #rb then return false end
				for i, rule in ipairs(ra or {}) do if rule ~= rb[i] then return false end end
			end
		end
	end
	return true
end

-- 一个地址族的 iptables-restore --noflush 输入：先声明（清空或新建）目标链与待删链，删除当前的 passwall2
-- 跳转后按目标位置插入新跳转，填充各链，最后删除不再使用的链；每张表在一次提交中原子生效。
-- current 是该地址族当前的 iptables-save 解析结果（-D 需要与其中的规则文本一致）。
function M.ipt_restore_script(desired, current, family)
	local out = {}
	for _, tname in ipairs({ "nat", "mangle" }) do
		local want, have = desired[family .. " " .. tname] or ipt_table(), (current or {})[tname] or ipt_table()
		local want_chains, have_chains, wanted = {}, {}, {}
		for _, name in ipairs(want.order) do
			if name:match("^PSW2") then want_chains[#want_chains + 1] = name; wanted[name] = true end
		end
		for _, name in ipairs(have.order) do
			if name:match("^PSW2") and not wanted[name] then have_chains[#have_chains + 1] = name end
		end
		local body = {}
		for _, name in ipairs(have.order) do
			if have.builtin[name] then
				for _, rule in ipairs(have.chains[name]) do
					if is_passwall(rule) then body[#body + 1] = "-D " .. name .. " " .. rule end
				end
			end
		end
		for _, name in ipairs(want.order) do
			if want.builtin[name] then
				for index, rule in ipairs(want.chains[name]) do
					if is_passwall(rule) then body[#body + 1] = "-I " .. name .. " " .. index .. " " .. rule end
				end
			end
		end
		for _, name in ipairs(want_chains) do
			for _, rule in ipairs(want.chains[name]) do body[#body + 1] = "-A " .. name .. " " .. rule end
		end
		for _, name in ipairs(have_chains) do body[#body + 1] = "-X " .. name end
		if #want_chains > 0 or #have_chains > 0 or #body > 0 then
			out[#out + 1] = "*" .. tname
			for _, name in ipairs(want_chains) do out[#out + 1] = ":" .. name .. " - [0:0]" end
			for _, name in ipairs(have_chains) do out[#out + 1] = ":" .. name .. " - [0:0]" end
			for _, line in ipairs(body) do out[#out + 1] = line end
			out[#out + 1] = "COMMIT"
		end
	end
	return #out > 0 and table.concat(out, "\n") .. "\n" or nil
end

-- 规则引用的集合（--match-set 名称），删除旧集合时不能删掉仍被引用的。
function M.ipt_referenced_sets(models)
	local result = {}
	for _, model in pairs(models or {}) do
		for _, rules in pairs(model.chains) do
			for _, rule in ipairs(rules) do
				for name in rule:gmatch("%-%-match%-set%s+(%S+)") do result[name] = true end
			end
		end
	end
	return result
end

local ipset_flags = { ["-!"] = true, ["-exist"] = true, ["-q"] = true, ["-quiet"] = true }

-- ipset 元素规范化：单个地址的 /32、/128 与 ipset list 的显示一致。
function M.ipset_element(text)
	local element = text:match("^(%S+)") or text
	return (element:gsub("/32$", ""):gsub("/128$", ""))
end

-- 重放 ipset 命令，得到目标集合：{ sets = { 名称 = { spec = 创建参数, elements = 元素集合 } }, order = { ... } }。
function M.ipset_model(entries)
	local model = { sets = {}, order = {} }
	local function create(name, spec)
		if not model.sets[name] then
			model.sets[name] = { spec = spec, elements = {} }
			model.order[#model.order + 1] = name
		end
	end
	local function add(name, element)
		local set = model.sets[name]
		if set and element and element ~= "" then set.elements[M.ipset_element(element)] = true end
	end
	local function apply(args)
		local words = {}
		for _, arg in ipairs(args) do if not ipset_flags[arg] then words[#words + 1] = arg end end
		local op = words[1]
		if op == "create" or op == "-N" or op == "n" then create(words[2], table.concat(slice(words, 3), " "))
		elseif op == "add" or op == "-A" or op == "a" then add(words[2], words[3])
		elseif op == "flush" or op == "-F" then if model.sets[words[2] or ""] then model.sets[words[2]].elements = {} end
		elseif op == "destroy" or op == "-X" then
			if words[2] and model.sets[words[2]] then
				model.sets[words[2]] = nil
				for i, name in ipairs(model.order) do if name == words[2] then table.remove(model.order, i); break end end
			end
		end
	end
	for _, entry in ipairs(entries or {}) do
		if entry.kind == "S" then
			if entry.input then
				for _, line in ipairs(entry.input) do
					local args = {}
					for word in line:gmatch("%S+") do args[#args + 1] = word end
					if args[1] and args[1] ~= "COMMIT" then apply(args) end
				end
			else
				apply(entry.args)
			end
		end
	end
	return model
end

-- 解析 ipset list 的输出：{ 名称 = { type = 类型, members = 元素集合 } }。
function M.ipset_parse_list(text)
	local result, current, members = {}, nil, false
	for line in ((text or "") .. "\n"):gmatch("([^\n]*)\n") do
		local name = line:match("^Name:%s*(%S+)")
		if name then
			current = { members = {} }
			result[name] = current
			members = false
		elseif current and line:match("^Type:") then
			current.type = line:match("^Type:%s*(%S+)")
		elseif current and line:match("^Members:") then
			members = true
		elseif current and members and line ~= "" then
			current.members[M.ipset_element(line)] = true
		elseif line == "" then
			members = false
		end
	end
	return result
end

-- ipset 的提交计划：新集合创建并填充；内容由启动流程决定的集合不同则经临时集合交换（逐个原子）；
-- psw2_vps/wan 只补充；直连写集合与沿用的规则集合不动。obsolete 是目标规则不再引用、可在提交后删除的集合。
function M.ipset_plan(desired, current, options)
	options = options or {}
	local plan = { create = {}, swap = {}, add = {}, obsolete = {} }
	for _, name in ipairs(desired.order) do
		local want, have = desired.sets[name], current[name]
		local elements = {}
		for element in pairs(want.elements) do elements[#elements + 1] = element end
		table.sort(elements)
		if not have then
			plan.create[#plan.create + 1] = { name = name, spec = want.spec, elements = elements }
		else
			local class = M.set_class(name, options)
			if class == "refresh" then
				local same = true
				for element in pairs(want.elements) do if not have.members[element] then same = false end end
				for element in pairs(have.members) do if not want.elements[element] then same = false end end
				if not same then plan.swap[#plan.swap + 1] = { name = name, spec = want.spec, elements = elements } end
			elseif class == "union" then
				local missing = {}
				for _, element in ipairs(elements) do if not have.members[element] then missing[#missing + 1] = element end end
				if #missing > 0 then plan.add[#plan.add + 1] = { name = name, elements = missing } end
			end
		end
	end
	local referenced = options.referenced or {}
	local names = {}
	for name in pairs(current) do names[#names + 1] = name end
	table.sort(names)
	for _, name in ipairs(names) do
		if name:match("^psw2_") and not name:match("^psw2_r%x+$") and not desired.sets[name] and
			not referenced[name] and not (options.preserved or {})[name] then
			plan.obsolete[#plan.obsolete + 1] = name
		end
	end
	return plan
end

-- 交换用的临时集合名：ipset 名称最长 31 个字符，由正式名称的散列得出（与 iptables.sh refresh_set 相同的前缀）。
function M.ipset_temp_name(name)
	local hash = 5381
	for i = 1, #name do hash = (hash * 33 + name:byte(i)) % 2147483647 end
	return string.format("psw2_r%08x", hash)
end

-- 命令行入口（影子启动的 -L 查询）：lua reconcile.lua ipt-list <ipt.log> <地址族> <表> <iptables 参数...>
local function ipt_cli(argv)
	local log = argv[2]
	local family, tname = argv[3], argv[4]
	local dir = log:match("^(.*)/[^/]*$") or "."
	local function read(path)
		local file = io.open(path)
		if not file then return "" end
		local content = file:read("*a")
		file:close()
		return content
	end
	local base = {}
	for _, f in ipairs({ "4", "6" }) do
		for name, model in pairs(M.ipt_strip(M.ipt_parse_save(read(dir .. "/ipt_snapshot_" .. f)))) do base[f .. " " .. name] = model end
	end
	local output = M.ipt_list(M.ipt_replay(base, M.ipt_log(read(log))), family, tname, slice(argv, 5))
	if not output then return 1 end
	io.write(output)
	return 0
end

if type(arg) == "table" and type(arg[0]) == "string" and arg[0]:match("reconcile%.lua$") and arg[1] == "ipt-list" then
	os.exit(ipt_cli(arg))
end

return M
