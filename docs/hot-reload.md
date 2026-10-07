# Passwall2 原生配置热重载

## 应用路径

`/etc/init.d/passwall2 reload` 会比较启动时的配置快照，选择以下路径：

1. **原生热更新（快速路径）**：配置指纹不变（全局节点、远程 DNS、日志级别等运行时选项）时，进程内生成新配置并校验，经修改后的核心 API 预加载新出站、路由和 DNS，成功后原子切换新流量的入口。代理核心 PID、前置 DNS 和防火墙不变；已有连接继续使用旧运行实例，结束后回收。全局节点切换、集合热刷新、节点地址变化、定时类选项也在这条路径上完成（见下文各节）。
2. **差量热重载**：其余所有配置变化——访问控制条目（来源、端口、模式、节点，含实例增删）、监听端口、本机／客户端代理、直连 DNS、DNS 劫持方式、TCP 转发方式、IPv6／ICMP、节点的出站网卡／直连写集合／GeoIP 预加载、Socks 与负载均衡实例、启动时派生的外部输入（dnsmasq 主实例段、`firewall.passwall2` include、ISP DNS、防火墙后端），以及快速路径无法处理的情形——用真实的启动流程做一次影子启动得到目标状态，再按组件比较提交：未变化的进程不动，核心原生热更新（含监听器变化），前置 DNS 蓝绿替换，新增实例先启动，防火墙规则一次事务替换，最后停止不再需要的进程（见下文“差量热重载”）。
3. **兼容重启核心**：跨核心切换（sing-box ↔ Xray）、核心二进制或日志输出位置变化、核心明确拒绝的静态部分（日志、控制接口、TUN／WireGuard、FakeIP 地址池等）变化时，只重启相关代理核心，不动 DNS、防火墙和其他实例。这条路径会断开该核心的已有连接，日志会明确说明。
4. **完整重启**：只剩没有启动快照或稳定分配记录（升级后首次应用）、上一次差量提交被中断、集合的定义（类型等）发生变化这几种情形，使用原有 stop/start 流程。

此外有三类不涉及核心配置的热更新，与核心热更新在同一次 reload 中完成：规则数据与分流规则内容的**集合热刷新**、**节点地址变化**（前置 DNS 的节点域名转发与直连白名单）、**定时类选项**（只重建计划任务与后台进程），见下文各节。

切换全局节点见下文“全局节点热切换”：nftables 下同核心切换走原生热更新（分流子链原子替换），跨核心切换走兼容路径（只替换核心进程）。

快照只比较这些真正影响运行状态的输入。其它脚本改写的 DHCP 域名记录、防火墙规则或接口定义不会让 reload 退化为完整重启——家里的 ZeroTier 定时脚本会周期性改写防火墙规则和 `dhcp.zt_dns_*` 记录，早期按整份 `dhcp`／`network`／`firewall` 比较时曾因此误判并完整重启一次。注意 passwall2 复制出的 dnsmasq 实例（11400）只在启动时复制主实例配置，这是上游已有行为，热重载不会顺带刷新它。

**触发方式**：LuCI 的“保存并应用”、节点列表的“使用”等都会经 ubus 提交 UCI，rpcd 发出 `config.change`，ucitrack 为 passwall2 注册的 procd 触发器在 1 秒防抖后执行 `/etc/init.d/passwall2 reload`。procd 的触发器全局串行、没有执行超时，运行期间再有提交会在结束后重排一次。`api.uci_save` 保持上游行为，不再额外调用 reload，避免重复触发。

普通认证参数、原生协议参数、核心内部路由及远程 DNS 更新可以进入核心重载。分流规则本身（`shunt_rules`）只影响核心路由时同样走核心重载；某个分流节点开启了直连写集合 DNS（`write_ipset_direct`）或 GeoIP 预加载（`enable_geoview_ip`）时，规则内容还会进入防火墙集合，由集合热刷新重建。分流节点进入防火墙的部分（“分流签名”）只在开启 GeoIP 预加载时按规则生成集合，且只取同组、已指定目标的规则；全局分流节点的签名变化由分流子链替换处理（nftables 与 iptables 都是），指定了具体节点的访问控制实例的分流签名变化由差量热重载重建其规则。

订阅（`subscribe_list`、`global_subscribe`）、测速与界面选项（`global_other`）、规则更新地址等只被订阅／规则更新脚本或 LuCI 读取，不参与比较；`global_rules` 只比较规则数据目录 `v2ray_location_asset`。没有启动时派生结构的普通节点（订阅增删、改类型）也不参与比较：被运行中的实例引用时，执行器按节点图检查核心类型与出站网卡，引用的节点缺失、核心不符或需要桥接进程时改用差量热重载。订阅更新完成后改为 `reload`（上游为 `restart`），由上述判断决定是否需要重启。

变基到上游 26.10.1 之后，默认（全局）实例的标识为 `acl_default`：配置 `/tmp/etc/passwall2/acl/acl_default.json`、前置 DNS `dnsmasq_acl_default`、缓存变量 `ACL_acl_default_node`。访问控制条目由 `app_acl.lua` 计算，`use="acl_default"` 的条目共用默认实例；指定了具体节点的条目总是有自己的实例，与全局节点无关，所以“访问控制节点恰好等于新／旧全局节点”不再影响全局节点热切换。

## 全局节点热切换

**防火墙结构**：全局节点（以及跟随全局的访问控制规则）的分流项不再逐条写进 `PSW2_NAT`／`PSW2_MANGLE` 等主链，而是放进 5 条专用子链：`PSW2_SHUNT_NAT`（IPv4 TCP 重定向）、`PSW2_SHUNT_MARK`／`PSW2_SHUNT_MARK6`（打标记交给 TPROXY）、`PSW2_SHUNT_ICMP`／`PSW2_SHUNT_ICMP6`。主链只在原位置保留一条跳转；子链中直连项用 `accept`（结束本钩子的基础链，与原先在主链里 `return` 等价），代理项沿用原动作。`nftables.sh shunt_switch <节点> <重定向端口>` 生成新节点的分流集合后，用一个 `nft -f` 事务清空并重填全部子链，主链、DNS 劫持、集合白名单及其它规则不动；最后补充新节点地址到 `psw2_vps` 并刷新防火墙 include 快照。`tests/nft_shunt_test.py` 在 sudo 创建的独立网络命名空间里，把 16 种转发组合 × 是否含 ACL 的规则展开子链后与上游脚本逐条比对。两处有意差异：

- 上游在重定向模式下把 NAT 动作写进 IPv6 mangle 链，nft 拒绝该规则，IPv6 直连分流项实际缺失；子链统一用打标记动作，修正了这一点。
- 打标记子链的跳转带 `ct mark != 0x50535732`：已经由代理接管的流量不再按分流集合重新分类。TCP 重定向本来只作用于连接首包，TPROXY 的 TCP 由 `PSW2_DIVERT` 的 socket 匹配维持；这条条件让已有 UDP 会话在切换全局节点、或目标 IP 之后才被写入直连集合时继续走原路径直至结束，而不是中途改道失效。

**iptables 后端**：iptables 的内置链为所有程序共享，子链里的 `ACCEPT` 会跳过其它程序（如 mwan3）的规则，`RETURN` 又只返回到主链，不能照搬 nftables 的写法。这里主链原来的分流项换成一条跳转（携带原来的端口限制，mangle 表加 `-m connmark ! --mark 0x50535732`），子链 `PSW2_SHUNT_NAT/ICMP/ICMP6/MARK/MARK6` 中代理项沿用原动作，直连项 goto 到 `PSW2_SHUNT_DIRECT` 置一次性标记位 `0x80000000`；主链紧接一条“带该标记则 goto `PSW2_SHUNT_RETURN`”的规则，后者清除标记后结束，按 goto 语义回到主链的调用者，与原先在主链中 `RETURN` 完全等价；兜底与 TPROXY 规则留在主链不动。`iptables.sh shunt_switch` 用 `iptables-restore --noflush` 声明并重填子链（每张表一次提交）。该标记位只在 PSW2 链求值期间短暂存在；若其它程序也使用 `0x80000000`，需要改成未用的位。`tests/ipt_shunt_test.py` 用 iptables-legacy 与解包的 ipset 在独立网络命名空间中，把 16 种组合 × 是否含 ACL 的规则展开后与上游逐条比对，另有一处有意修正：上游在重定向模式下给 IPv6 TCP 客户端分流项用了 nat 的 `REDIRECT`（同一处兜底是 `-j PSW2_RULE`），ip6tables 在 mangle 表拒绝这些代理项，导致直连项之后的判断失真；新版统一打标记。上游 iptables 版同样有“列表变量沿用上一条目”的缺陷，一并修正（`test_default_entry_keeps_global_lists_after_other_acl`）。

报文级验证：两个后端的测试都在命名空间里用本机代理的重定向模式实际发起 TCP 连接，按“代理端口／直连端口”的监听判断走向（代理集合、直连集合、默认目标、集合之外、代理端口之外五种目标），新旧脚本结果一致；热切换到普通节点后直连集合不再生效，切回后恢复。这验证了 nft 子链 `accept` 与 iptables goto 加标记的等价推断。注意网络命名空间不隔离进程：测试清理只能按记录的 PID 结束进程，root 的 `pkill -f` 会匹配到宿主上命令行含相同字样的进程（编写测试时就因此结束过执行命令的 shell 自身）。

**切换流程**（`reload.lua`，持服务锁执行）：

1. 判定：子链存在（`shunt_ready`，旧版本加载的规则没有子链则完整重启）、新旧全局节点都能由原生节点图表示；nftables 与 iptables 相同。全局节点不变、只是分流节点的直连／代理分类变化时，同样只替换子链。
2. 直连写集合 DNS：新节点开启 `write_ipset_direct` 时，复用已在运行的该节点服务，或经 `app.sh reload_direct_dns acl_default <节点>` 以 `dns_acl_default_direct_<节点>.conf` 新启一个（不覆盖仍在运行的旧服务；直连 DNS 协议与服务器取自上游的 `direct_dns`／`direct_dns_protocol`），核心的直连 DNS 指向它；切到未开启的节点时恢复启动时记录的原始直连 DNS（`direct_dns_base_proto/server/port`，旧版本记录缺失则完整重启）。切换离开的节点服务保留到下次完整重启，因为其它实例或前置 DNS 可能仍指向它，切回时直接复用。
3. 生成并校验新核心配置，原生热更新核心（已有连接留在旧运行实例）。
4. 原子替换分流子链；失败则恢复核心配置、子链与本次新启动的 DNS 服务。事务文件记录这些内容，进程中断后下次 reload 先恢复。
5. 更新缓存变量（`ACL_acl_default_node`、`node_<节点>_redir_port`）、各访问控制条目 var 文件中 `use="acl_default"` 条目的节点记录、实例记录与快照，以后重新生成防火墙规则时与运行状态一致。

**FakeIP**：sing-box 支持原生热重载时，生成器始终声明同一个 FakeIP 服务与缓存文件（没有规则引用时不分配地址）。这样从使用 FakeDNS 的分流节点切到普通节点，FakeIP 与 `experimental` 等静态配置不变，可以原生热更新；客户端缓存的 FakeIP（应答 TTL 可达 600 秒）仍由共享存储还原域名。Xray 新运行实例借用初始实例的 FakeDNS 引擎（见下）。

**跨核心切换**（sing-box ↔ Xray）无法无损：连接与 FakeIP 映射位于旧核心进程内。执行器按目标核心重算专有参数（sing-box 的 `tags`、日志、控制 API secret 与能力探测；Xray 的日志级别与 `api reloadconfig` 能力），校验后只替换核心进程，DNS 实例、dnsmasq、防火墙主链与其它实例保持不变，分流子链照常原子替换；经该核心的已有代理连接会断开，日志明确写出。替换后的核心可继续原生热更新。上游把排队启动的进程改为看门狗目录中的 `queued_N` 条目，执行器替换核心时同步改写为新核心的启动命令。

## 集合热刷新（规则数据与分流规则）

上游用一次性标志 `flush_set` 要求“清空集合后重建”：保存分流规则（`shunt_rules.lua` 的 `on_before_save`）、规则数据更新（`rule_update.lua`）、规则回滚与手动“清空集合”都会设置它，`nftables.sh stop` 消费它，于是这些操作全部变成完整重启（规则更新每次都造成一段 DNS 中断）。现在 `flush_set` 视为动作而不是配置变化；分流规则内容变化且有分流节点开启 GeoIP 预加载或直连写集合时，同样触发刷新（只影响核心路由时不刷新集合）。nftables 下 `nftables.sh refresh_sets <全局节点> <重定向端口> <flush>` 在**一个 nft 事务**中：

- 重建由规则派生的集合：`psw2_direct(6)`（`direct_ip` 含 geoip 代码、LAN 网段、ISP DNS）、全局节点与访问控制显式节点的 GeoIP 预加载集合（`psw2_<节点>_<规则>`）；`flush=1` 时先丢弃 geoip 解析缓存；
- 按上游语义清空直连写集合 `psw2_<节点>_white(6)`，由 DNS 重新写入；`psw2_vps/local/wan` 不动；
- 重填默认实例的分流子链（集合名可能因规则增删而变化），并刷新防火墙 include 快照。

事务失败时集合与子链完全不变（测试用非法地址验证）。实现上让 `insert_nftset`／`gen_nftset` 在设置 `NFT_SCRIPT` 时把语句写入脚本而不执行；提交前按集合归并：nft 1.1.6 对 `auto-merge` 区间集合，在同一事务中 flush 之后若同一集合的多条 `add element` 被其它集合的语句隔开，用户态合并会按陈旧缓存删除已清空的元素而报 ENOENT，归并成每个集合一条 `add element` 后正常（busybox awk 与 mawk 会先求值左侧数组元素，归并时用计数数组而不是 `in` 判断）。访问控制显式节点只刷新集合内容：其主链规则引用的集合名由分流签名保证不变。

核心侧：sing-box 由 geosite／geoip 转换出的规则集（`singbox_srss/*.srs`）先转换到临时文件再改名覆盖，sing-box 监视规则集所在目录，同名文件被创建即自动重载，不需要新建运行实例；FakeIP 缓存库不删除（上游完整重启会删掉 `singbox*`）。Xray 26 的 geodata 匹配器按“文件:代码”缓存，只重载配置会沿用旧数据（`test_xray_geodata_reload_updates_geosite_rules` 先断言了这一点），因此补丁新增 `ConfigReloadService/ReloadGeodata`：调用 Xray 自带的 `IPReg/DomainReg.Reload()` 原地重建所有已登记的匹配器（含仍在排空的旧运行实例），每个登记表全部构建成功才替换。`xray api reloadconfig --geodata [配置]` 先重载 geodata（不带配置时只做这一步），`--local` 输出 `"geodata":true` 供 `app.sh` 记录能力；不支持的核心改为重启核心。成功后执行器用命令行 `uci delete/commit` 消费 `flush_set`（不触发 procd 触发器），快照中同步去掉该选项。缺少分流子链时仍完整重启。

iptables 后端没有跨集合的事务：`iptables.sh refresh_sets` 让 `gen_shunt_list` 与 `fill_direct_sets` 写入临时集合（名称取正式集合名摘要，ipset 名最长 31 字符），全部填好后逐个 `ipset swap` 再销毁临时集合，每个集合的替换是原子的；直连写集合 `ipset flush`；最后用 `iptables-restore --noflush` 重填分流子链。

## 节点地址变化

节点的 `address`／`download_address`／`port` 与链式代理字段不再触发完整重启。启动时它们派生三处状态，执行器逐一热更新：

1. 前置 DNS（`dnsmasq_<实例>`）把所有节点域名转发到国内 DNS 并写入 `psw2_vps`。sing-box 用 `local` 解析器、Xray 用 `localhost` DNS 解析节点服务器域名，都会经过它：新节点域名若不在其中会拿到 FakeIP 甚至形成解析回环。`helper_dnsmasq.lua` 改为把节点域名的 `server=` 行写入 conf-dir 之外的 `servers-file`（目录内放一条 `servers-file=` 指令，并记录国内 DNS 到 `.local_dns`），热更新时 `update_servers` 重写该文件并向实例发送 SIGHUP：dnsmasq 重读 servers-file 并清空缓存，监听不中断。`nftset=` 行无法经 SIGHUP 重读，新域名的地址由执行器解析后加入 `psw2_vps`。缓存键加入布局标记，旧版本留下的缓存在升级后的首次启动时重建；旧布局的实例或接入系统 dnsmasq 时仍完整重启。
2. 直连白名单：与启动时一样加入所有节点的字面 IP；运行中节点图里地址变化的域名在 DNS 重读后解析加入。
3. 本机放行规则：生成器在热重载时也把直连拨号的节点写入 `direct_node_list`，执行器去重后经 `nftables.sh filter_direct_node_list` 补充新的“地址:端口”（已有的跳过）。直接调用时补齐启动阶段才有的工具函数与输出链变量（顺带修正上游 Socks 节点切换路径缺少该变量的问题）。

这些步骤只增加直连条目，先于核心更新执行，失败的重载回滚时无需撤销。iptables 后端补上了 `filter_vps_addr` 与对应的调用入口，处理方式相同；`app.sh reload_direct_dns` 也按后端改写 ipset 名，iptables 下全局切换同样可以新启直连写集合 DNS。

## 定时类选项

`global_delay` 的启停／重启时间与看门狗开关、`global_rules` 与订阅的自动更新时间单独比较（没有设置自动更新的订阅不计入）。变化时执行器调用 `app.sh reload_crontab`：结束看门狗与循环更新进程后按当前设置重新执行 `start_crontab`，核心、DNS 与防火墙不变；`start_delay` 只在开机时使用，不参与比较。OpenWrt 的 busybox 没有 `pkill`，这里与测试收尾都用 `busybox pgrep -f` 加 `kill`，模式用字符类写法避免匹配到调用者自身。

## 差量热重载（影子启动 + 按组件提交）

不再为每个选项写专用热更新，而是让启动流程可以在暂存目录里无副作用地重放，再写一个通用的比较提交器。

**影子启动**（`reload.lua` 调用 `app.sh stage`，环境变量 `PW2_STAGE=1`、`PW2_TMP_PATH=/tmp/etc/passwall2/reload/stage`）：完整执行 `start`，生成的配置、var、访问控制文件、实例记录都写入暂存目录（0700）；`ln_run` 只登记要启动的进程；nftables 规则写入不挂钩子的影子表 `inet passwall2_stage`（基础链建成普通链，规则照常生成、`nft list` 与按 handle 插入都可用，但不处理任何报文；内核只沿基础链校验 redirect/tproxy，所以这些规则能加入普通链）；iptables 命令与 ipset 修改只记录（`-L` 查询由 `reconcile.lua` 按快照重放模拟）；dnsmasq 主实例、dhcp uci、路由、sysctl、mwan3、计划任务、后台补集合、Socks 自动切换等系统副作用全部跳过并记录意图。缓存目录（规则集、geoip、FakeIP 缓存库）保持正式路径；前置 DNS 的实例缓存另写暂存目录（`PW2_DNSMASQ_CACHE`），不影响运行中实例在 SIGHUP 时重读的 servers-file。已有的规则集合在影子表里只建空集合并记录为沿用（内容由集合热刷新负责）。核心配置在影子启动中照常 `check`/`run -test`，校验失败则放弃本次变更、保留当前服务。

**稳定分配**：端口与 sing-box 控制接口 secret 按用途键记录在 `$TMP_PATH/stable`（`acl_default:redir`、`<条目>:dns`、`<条目>:api`、`<条目>:secret`、`<条目>:dnsmasq`、`<条目>:direct_dns:<节点>`、`nodesocks:<节点>:<中继端口>`、`tunnel:<条目>:<tag>`、`haproxy:<节>`），影子启动读运行中的记录沿用，新键避开已记录与正在监听的端口。没有它，影子启动会因端口被运行中进程占用而全部换端口，所有配置都“变了”。快速路径的跨核心切换同样沿用这些记录。配置不变时 `lua /usr/share/passwall2/reload.lua plan`（只读诊断入口）输出 `plan: none`：防火墙、进程、生成文件、var、稳定分配全部一致。

**比较与提交**（`luasrc/passwall2/reconcile.lua` 是不依赖 OpenWrt 运行库的纯逻辑，执行器在 `reload.lua`）：暂存路径改写成正式路径（含 JSON 中转义的 `\/` 写法），进程按配置文件路径对应：

- 核心（有实例记录的 sing-box/Xray）：配置相同不动；不同则原生热更新，静态部分变化或接口拒绝时重启核心；新实例先启动并确认监听端口属于该进程（按 socket inode 对照 /proc/net，端口被其它程序占着时不会误判）。
- 前置 DNS（`dnsmasq_<条目>`）与直连写集合 DNS：配置变化时换键再做一次影子启动得到新端口，新实例就绪后才切换防火墙（蓝绿），旧实例在提交后停止并按新实例重写 pid 文件（dnsmasq 退出时会删除自己的 pid 文件）；只有 servers-file／国内 DNS 记录变化时安装新文件并发送 SIGHUP，不重启。
- haproxy：`-sf` 软重载；其它桥接进程配置变化时就地重启；Socks、负载均衡与桥接实例启动失败时与完整启动一样跳过（如端口被占用），透明代理的核心与 DNS 失败则放弃本次重载。
- 防火墙（nftables）：解析影子表与正式表的 `nft list table`，生成一个事务——补齐集合与链 → 清空并按目标顺序重填全部链 → 删除旧链，先 `nft -c` 校验。集合语义：`psw2_vps/wan` 只补不删（前置 DNS 与防火墙重载会写入），直连写集合 `*_white` 不动（flush_set 或分流规则变化时清空），沿用的规则集合不动，其余（`psw2_local/direct`、新规则集合）内容不同则同一事务中清空重填；不再使用的集合在旧进程停止后删除。
- 防火墙（iptables）：`iptables.sh` 把执行的命令按顺序记录为规则配方（`ipt.log`，启动、提交与运行时改动都追加），差量比较重放两份配方判断是否变化；提交时 ipset 先行（新集合创建填充，内容不同的经临时集合 `swap`，旧内容留在临时集合中供回滚换回，`vps/wan` 只补充），规则按地址族各一个 `iptables-restore --noflush` 事务：声明（清空或新建）目标链、删除当前 passwall2 跳转、按目标位置插入新跳转、填充各链、删除旧链。完整启动时本来就会执行失败的单条命令（上游在端口为空、IPv4 来源写进 ip6tables 等情形下会生成）按 restore 报告的出错行剔除后重试，与逐条执行时失败被跳过一致；后续步骤失败时整表恢复提交前的 nat/mangle。
- 防火墙后端变化（nftables ↔ iptables）：先提交新后端，再清除旧后端的规则；前置 DNS 的集合写法随之变化而蓝绿替换。
- dnsmasq 主实例（DNS 劫持改为“只拦截发往本机的查询”时接入）：新接入时先安装配置并重启主实例、再切防火墙；离开或内容变化在提交后处理。dhcp 的 `dns_redirect` 迁移与启动时相同。
- 系统设置：`ip rule`/`ip route`（表 999，IPv6 随开关）、网桥 netfilter sysctl（按启动时的备份恢复）、mwan3 协作、防火墙重载时的恢复脚本（include）、负载均衡出口路由、Socks 自动切换与 lease2hosts，按目标状态补齐；定时选项、透明代理启停或总开关变化时重建计划任务。

提交点（防火墙事务）之前的任何失败都恢复原状态：新启动的进程停止、热更新过的核心恢复旧配置、被覆盖的文件还原、交换过的集合换回、新接入的 dnsmasq 主实例撤回。`reload/reconcile.json` 标记提交进行中，进程中断后下次 reload 完整重启。提交成功后按提交后的外部输入（防火墙后端记录、dnsmasq 主实例段）重写快照，避免下一次误判。

影子启动顺带暴露并修正了两处启动顺序缺陷：默认实例的分流子链在 `acl_node` 之前生成时，直连写集合还没登记，子链缺少它；而且生成器“分流规则变化即清空 `psw2_<节点>_*` 集合”会把刚填好的集合清空。现在实例先于分流子链启动（nftables.sh 与 iptables.sh 都是）。另外修正了 iptables.sh 的两个上游问题：`del_firewall_rule` 用循环变量 `ipt` 覆盖了 iptables 路径；独立调用 `gen_include`（热切换、集合刷新之后）时缺少转发方式与 ICMP 变量，恢复脚本会按重定向模式恢复 TCP 跳转。

## 核心源码与版本

两个核心源码保存在独立仓库中：

- sing-box：`/home/geoffrey/Sources/sing-box`，基于 `v1.14.2`，提交 `af6e64c3b69e6132ebaee0e1a3d24e93903f6709`。
- Xray-core：`/home/geoffrey/Sources/Xray-core`，基于 `v26.9.30`，提交 `b26a91de4f3294e26a0ad0a970b81a386a41f789`。

两个仓库及 Passwall2 使用各自的功能分支，没有推送。2026-10-04 经用户授权，家里路由器已完整覆盖本版应用文件与两个静态核心并完成实测；办公室路由器没有被连接或修改。现有用户节点、分流、订阅、ACL 和 FakeIP 配置保留。

可移植补丁位于 `patches/cores/`。补丁针对以上准确基线生成，不应忽略冲突强行应用到其他版本。

### sing-box

编译时必须包含 `with_clash_api`：

```sh
go build -tags with_clash_api,with_quic,with_utls \
  -ldflags '-X github.com/sagernet/sing-box/constant.Version=1.14.2-passwall2-hot-reload' \
  -o sing-box ./cmd/sing-box
```

能力探测：

```sh
sing-box hot-reload-capabilities
```

Passwall2 检测到这个命令后才生成 `hot_reload: true`。控制服务仅绑定 `127.0.0.1`，使用实例级随机 secret；含 secret 的配置和元数据限制为仅所有者可读写。

- `GET /configs/hot-reload`：返回 `hot_reload_version: 1`。
- `PUT /configs/hot-reload`：请求体是完整的 sing-box JSON 配置。成功返回协议版本与 `applied: true`；无效配置返回 400；明确需要重启时返回 409。

两个核心都支持入站（监听器）变化：入站按 tag 求差（没有 tag 或 tag 重复时视为需要重启），新运行实例启动成功后、切换之前，在初始实例的入站管理器上先关闭被删除或替换的旧入站，再创建新入站（先全部关闭再创建，换 tag 但沿用端口——如重定向改为 TPROXY——也能绑定）；任一步失败按相反顺序恢复原入站并放弃本次重载。关闭监听器不影响已经接受的连接。
- 原有 `PUT /configs` 仍保持上游兼容语义，不把其空 204 响应误当作重载成功。

### Xray-core

```sh
go build -o xray ./main
```

能力探测与应用：

```sh
xray api reloadconfig --local
xray api reloadconfig --server=127.0.0.1:2001 --check
xray api reloadconfig --server=127.0.0.1:2001 /path/to/next.json
xray api reloadconfig --server=127.0.0.1:2001 --geodata [/path/to/next.json]
```

控制配置需要 `HandlerService`。Passwall2 为原生版本使用独立的本机 `api.listen`，避免把 API 的连接本身转发到新数据运行实例。

- 退出码 0：成功，或者能力探测成功。
- 退出码 2：协议不支持或配置明确需要核心重启。
- 退出码 1：配置拒绝、通信失败等；不能直接当作成功或无条件完整重启。

服务端限制调用来源为 loopback。上游生成器总会输出 `env: {XRAY_LOCATION_ASSET: …}`，而 Xray 的 `env` 会在构建配置时调用 `os.Setenv`：补丁只接受与当前进程环境逐项相同的 `env`，否则返回需要重启（`env X changed`），避免预加载改动全局环境。拒绝时 `xray api reloadconfig` 输出 `requires_restart` 后附具体原因（如不支持的出站类型、`metrics`），Passwall2 据此走兼容路径。每个运行实例使用自身 DNS 与出站管理器进行拨号；预加载不替换全局日志或全局拨号依赖。

## 生命周期与边界

- 不把已建立的 TCP 连接“迁移”到另一台服务器；新连接使用新配置，已有连接沿用旧配置。
- 半关闭连接仍可能需要发送另一方向的数据，不能在看到单向 EOF 时就回收其所属实例。
- 两个核心将保留运行实例数量限制为 8；达到上限时明确要求重启，而不是无限增长或静默关闭仍在使用的连接。
- 家里实测（x86/64，生产分流配置含 FakeIP 与规则集）：每多保留一代运行实例，核心 RSS 约增加 4.1 MiB；同时保留 4 代时 RSS 从 64.7 MiB 升到 81.1 MiB。按上限 8 估算最坏约多 33 MiB。旧代回收后 Go 保留已释放堆供后续复用，RSS 不会立即回落，系统 `MemAvailable` 随即恢复。
- sing-box 在 FakeIP 的 tag、地址池等定义不变时共享初始实例的映射存储、互斥锁与分配游标，新实例不重新启动或关闭共享存储，因此可以保持现有 FakeIP 地址与旧连接。修改地址池仍需重启（Passwall2 生成器在原生热重载时始终声明同一 FakeIP 服务，避免节点切换造成“添加／删除”）。
- Xray 的 FakeDNS 地址池配置相同时，新运行实例借用初始实例的 FakeDNS 引擎（启动／关闭为空操作，生命周期仍归初始实例），DNS 应答与嗅探还原使用同一映射；地址池变化返回需要重启。旧版补丁判断 FakeDNS 应用时把 protobuf 全名写成了 `xray.app.fakedns.*`（实际为 `xray.app.dns.fakedns.*`），带 FakeDNS 的 Xray 配置会静默换成新地址池；已修正，并由 `TestHotReloadAppTypeNames` 对照真实消息类型校验。
- 监听器变化可以原生热更新（被替换的那个监听器会重新绑定）；TUN／WireGuard、FakeIP 地址映射迁移、日志与控制接口等静态部分，以及独占服务暂不支持无损原生重载，原生接口拒绝后 Passwall2 使用明确记录的兼容路径。
- sing-box 1.14 的 DNS 规则迁移（删除旧 action `strategy`，改用 `query_type` 条件）已由上游完成，本分支不再改写 DNS 规则。
- 核心更新包可能覆盖定制二进制。长期使用应把补丁接入自己的 OpenWrt 核心包／feed 构建流程，而不是只手工覆盖路由器上的文件。

## 变基到上游 26.10.1

功能分支已变基到上游 `origin/main` 的 `2de5aee7`（版本 26.10.1，相对原基线 `20a2f311` 新增 202 个提交）；变基前的分支保留为 `feat/hot-reload-pre-rebase`。上游已自带的修正不再由本分支维护：Xray 出站 `proxySettings` 改为 `sockopt.dialerProxy`、sing-box DNS `strategy` 迁移、`LOCK_PATH`（`/var/lock`）、直连 DNS 协议选项。热重载按上游的新结构改写：默认实例 `acl_default`、`app_acl.lua` 计算的访问控制条目与 var 文件、看门狗 `queued_N` 条目、`get_new_port auto` 动态端口。

实机部署暴露的上游兼容问题，本分支一并修正：

- 旧版本访问控制把 `sources` 保存为单个字符串（如 MAC 地址），上游 `app_acl.lua` 按列表遍历时报错 `ipairs table expected, got string`，透明代理退化为非代理模式。现在字符串按空白拆分为列表，LuCI 列表页也能显示旧格式。
- 旧配置中的端口选项可能是 `disable`／`default`，上游直接拼进 nft 集合（`udp dport {disable}` 语法错误）。现在 `disable`／空值视为不代理该类端口，`default` 继承默认实例的端口设置。
- 上游把服务端配置从“`user` 节内联凭据”改为 `server` 节 + 独立 `user` 凭据节（`users` 列表，SS-Rust／SSR 用单个 `user`），并删除了迁移逻辑；旧配置的服务端在新版本下全部不启动。`server_migrate.lua` 在 `server_app.lua start`（以及 uci-defaults 中的 `server_app.lua migrate`）时迁移带 `type` 选项的旧 `user` 节：保留节名与其它选项，凭据按协议转为 `user` 节（相同凭据复用，UUID／密码类按协议生成不重复的用户名），Xray／sing-box 的 Shadowsocks 改用 `ss_method`／`ss_password`，Xray `dokodemo-door` 改名 `tunnel`。旧版在未勾选“仅本机”时对所有来源放行端口，迁移为 `firewall_allow=1`、`firewall_allow_src='*'`；同时删除不再生成的 `firewall.passwall2_server` 包含及运行时 `PSW2-SERVER` 链。迁移幂等，新格式配置不受影响。

## 校验、回滚与互斥

重载先校验所有实例，再改变运行状态。无效生成配置不会触发 stop/start；失败输出另存为 `reload/check.failed.log`，不会被随后成功的校验覆盖。暂存配置命名为 `*.next.json`／`*.restore.json`：Xray 按扩展名判断配置格式，旧版的 `*.json.next` 会让 Xray 的校验与热更新必然失败。进程内生成 sing-box 配置后会补齐新用到的 geosite／geoip 规则集文件（启动路径原本只在脚本入口转换）。多实例应用失败时按相反顺序恢复已经处理的实例；API 超时也可能已经生效，因此失败恢复不能只依赖客户端是否收到成功响应。

`/tmp/etc/passwall2/reload/transaction.json` 保存恢复所需的旧配置。进程中断后，下次 reload 先处理未完成事务。该目录权限为 0700，配置和元数据为 0600，不要把它作为普通诊断日志公开。

服务互斥分为两个文件：

- `/var/lock/passwall2.flock` 是互斥锁本体，start、stop、restart、reload 与看门狗共用，保持同一 inode、从不删除，避免不同进程锁住不同 inode。
- `/var/lock/passwall2.lock` 恢复上游语义，只在服务操作期间存在。订阅与规则更新在计划任务模式下按它是否存在决定是否留下 `_cron.lock`，让随后的重启跳过重写 crontab。

init 脚本调用 `app.sh` 时关闭锁描述符（`9>&-`），看门狗重新拉起进程时关闭自己的锁描述符（`8>&-`），长期运行的核心、看门狗和 lease2hosts 不再继承锁；即使 init 脚本异常退出，锁也随进程结束释放。

各操作最多等锁 30 秒，以容忍看门狗的短暂持锁。reload 超时后写入 `/var/lock/passwall2_reload.pending` 并返回，持锁的 start／restart／reload 在解锁前补做排队的应用，避免配置提交丢失；start／restart 自己读取最新配置，开始时清除排队标记。

订阅／规则更新锁残留时，只有确认没有 `lua …/passwall2/<脚本>.lua` 进程才清理；`pgrep` 自身失败时按运行中处理。仍在运行则最多等 600 秒，超时后按上游行为清除锁继续。reload 未经过 start 时清除计划任务留下的 `_cron.lock`，避免它让以后的手动启动跳过定时任务配置。

## 本机验收

```sh
lua tests/reload_logic_test.lua "$PWD"
lua tests/reconcile_logic_test.lua "$PWD"   # 差量热重载纯逻辑：路径改写、nft 解析与事务、进程计划、iptables 模拟、ipset 计划
lua tests/server_migrate_test.lua "$PWD"
python3 tests/init_reload_test.py
python3 tests/direct_dns_test.py         # 直连 DNS 推导：选了 UDP 却未填写服务器时保持自动获取
python3 tests/nft_shunt_test.py          # 需要 nft、busybox 与免密 sudo，只在独立网络命名空间内操作
python3 tests/ipt_shunt_test.py          # 另需 iptables-legacy 与 ipset：apt-get download ipset libipset13 后 dpkg-deb -x 解包，
                                         # 用 PW2_IPSET_ROOT 指向解包目录（默认 /tmp/passwall2-hot-reload/ipset-pkg/root）
python3 tests/nft_reconcile_test.py      # 12 组配置变化：A 启动 → B 影子启动 → 事务提交，与直接按 B 启动逐条一致
python3 tests/ipt_reconcile_test.py      # 同上，iptables 后端（规则与 ipset 内容一致，配置不变判为无变化）
SING_BOX_BIN=/path/to/patched/sing-box \
XRAY_BIN=/path/to/patched/xray \
python3 tests/hot_reload_core_test.py
```

`nft_shunt_test.py` 用伪造的 `uci`、`jsonfilter` 与桩函数加载上游（`PW2_UPSTREAM_REF`，默认 `origin/main`）与新版 `nftables.sh`，校验展开子链后逐条等价、`shunt_switch` 往返只改子链、`stop` 清理全部 PSW2 链，以及旧规则缺少子链时拒绝切换（返回 2，reload 走完整重启）。注意上游 `gen_nftset` 在标准输入不是终端时会读取输入作为集合元素：测试与执行器调用都显式使用空输入。

核心仓库中的生命周期与竞态测试：

```sh
# 在 sing-box 源码目录
go test -race -tags with_clash_api,with_quic,with_utls -run HotReload .

# 在 Xray-core 源码目录
go test -race -run HotReload ./core
```

真实核心测试只使用本机 loopback 和临时目录，验证 PID／端口保持、旧长连接、新节点连接、DNS 替换、多轮切换排空、sing-box FakeIP 映射与分配游标、FakeIP 服务未被引用时仍能还原旧地址、Xray FakeDNS 跨运行实例保持映射（按时间戳分配，反序查询排除巧合）、坏配置和静态部分变更拒绝，以及监听器变化（换端口、增删入站、换 tag 沿用端口、端口冲突整体回滚、经旧监听器建立的连接保持）。

## 家里路由器验收与回滚

2026-10-04 实测目标为家里的 ImmortalWrt x86/64、Microsoft Hyper-V 虚拟机。完整覆盖通过受限备份和自动回滚保护进行；首次 30 分钟窗口到期确实恢复了旧版，修正后重新覆盖，最终验收成功后以 `commit` 标记确认保留部署。

已验证：

- 生产 sing-box 的 DNS 缓存选项与代理到代理的分流目标热更新，已有 Google TLS keep-alive 连接不中断，新 HTTPS 返回 204。
- 核心 PID、前置 DNS PID、`inet passwall2` 防火墙链和规则保持不变。
- 家里实际 FakeIP UDP DNS 回答仍为稳定的 `198.18.0.0/16` 地址；原 FakeIP、ACL、分流节点在测试后恢复保留。
- 无效协议配置被拒绝，当前核心 PID 不变；测试配置已恢复。
- 家里隔离 Xray 实例出站 A→B 重载后，旧连接仍到 A，新连接到 B；生产 sing-box 没有重启，隔离监听器已清理。

实际设备暴露的兼容性修正：`nixio.fs.chmod` 使用 `"600"`／`"700"` 字符串而非十进制整数；启动快照稳定检查后只把存活实例列为热重载目标。家里原有额外 Socks 配置端口 10801 被 `frps` 占用，这个实例未启动并被明确记录为 inactive；未移动 frps 或擅自修改 Socks 配置。

### 2026-10-04 下午的增量修正

复查已部署版本发现四个问题，均已修正、部署并实测：

1. 快照比较整份 `dhcp`／`network`／`firewall`，ZeroTier 定时脚本 15:08 改写防火墙规则后，15:38 的一次 reload 被误判为拓扑变化并完整重启（约 6 秒）。已收窄为上文的外部输入，并用当前运行状态以新格式刷新快照。
2. 生产核心、看门狗与 lease2hosts 继承了 init 脚本的锁描述符；看门狗持锁时 reload 会立即放弃而丢失配置提交；锁文件常驻破坏了订阅／规则更新的计划任务判断。已改为上文的双文件锁、关闭继承、限时等待与排队补做。
3. `api.uci_save` 新增的显式 reload 与 ucitrack 的 procd 触发器重复。已撤回，恢复上游原文件（与覆盖前哈希一致）。
4. 残留的订阅／规则更新锁会永久阻塞服务操作，`pgrep` 失败会被误判为进程已结束。已按进程存在性保守判断。

增量更新用 `tests/home_update_locks.sh` 完成：等待旧锁空闲后持新锁替换 5 个文件，只替换看门狗进程，未重启代理核心。之后实测：

- `tests/home_procd_trigger_test.py`：经 ubus 提交（与 LuCI 相同）由 procd 触发且只触发一次 reload，分流节点原生切换与恢复，旧 TLS 连接、新连接、核心／DNS PID 与 nft 规则不变；再写入一条禁用的防火墙规则和一条 DHCP 域名记录后 reload 为“无运行时变化”，两份配置随后逐字节恢复。
- `tests/home_memory_probe.py`：上文的逐代内存成本。
- 重跑 `home_live_reload_test.py` 与 `home_invalid_reload_test.py` 通过；上游节点偶发握手失败，测试只对“建立连接”最多重试 3 次，reload 后旧连接的可用性不重试。
- 家里 passwall2 配置与覆盖前原始文件逐字节一致；99 个覆盖文件与本地源码逐一哈希一致。

（该增量的暂存与回滚脚本已在变基部署后删除：它会把变基前的文件混入当前安装。）

手动回滚命令仅用于家里设备。变基部署之后必须先撤销变基（见文末），再恢复最初的原装文件：

```sh
/bin/sh /root/passwall2-hot-reload-test-20261003/rebase-20261004b/rollback.sh
/bin/sh /root/passwall2-hot-reload-test-20261003/rollback.sh
```

受限原始备份：`/root/passwall2-hot-reload-test-20261003/backup/original.tar.gz`。确认标记：`/root/passwall2-hot-reload-test-20261003/commit`。部署工具位于 `tests/build_home_overlay.py` 和 `tests/home_apply_overlay.sh`；它们主动排除现有 `/etc/config` 和首次安装初始化脚本。

该轮测试不等于对所有固件、iptables、IPv6、所有 ACL、监听拓扑、TUN／WireGuard 和 APK 升级路径的全面认证。当前是持久化文件覆盖，尚未安装自定义 APK；包管理器升级仍可能覆盖这些文件，长期使用应接入定制包／feed。

### 2026-10-04 晚间：全局节点热切换增量

增量用 `tests/home_global_switch_deploy.sh` 安装（暂存与备份：`/root/passwall2-hot-reload-test-20261003/global-switch-20261004/`），之后受控重启一次以建立分流子链。远端命令行不能出现 `passwall2/`：完整重启时 `app.sh stop` 会结束命令行含该字符串的全部进程，包括执行命令的 SSH 会话。实测：

- `tests/home_global_switch_test.py`：经 ubus（LuCI 同款）把全局节点从 FakeDNS 分流节点 `myshunt` 切到普通 sing-box 节点再切回。路由器自身经 nft 透明重定向保持的 TLS keep-alive 连接与 SOCKS 长连接在两次切换后都继续可用，新连接正常；切换前分配的 FakeIP（`www.google.com` → `198.18.0.4`）切到普通节点后仍能还原域名并返回 204；核心与 DNS 进程不变，主链逐条不变，分流子链先被清空、切回后与切换前逐条一致；日志为“全局节点热切换 … 防火墙分流子链已原子替换 / 原生热更新”。
- `tests/home_cross_core_test.py`：sing-box ↔ Xray 跨核心切换各一次，DNS 进程与主链不变、实例记录改为新核心，替换后的 Xray 与 sing-box 各自完成一次原生热更新（PID 不变）。该 Xray 节点本身的上游不可用（用路由器原装 Xray 25.12.8 隔离测试同样握手失败），只影响该节点的连通性验证。
- 重跑 `home_live_reload_test.py`、`home_procd_trigger_test.py`、`home_invalid_reload_test.py` 全部通过；测试后 passwall2 配置与覆盖前原始文件逐字节一致。

实测暴露并修正的问题：sing-box 1.14 DNS 迁移遇到没有匹配条件的兜底规则（普通节点的远程 DNS）会生成含空子规则的逻辑规则，sing-box 拒绝启动——此前全局节点一直是分流节点才未暴露，完整重启到普通节点同样会失败；Xray 暂存配置扩展名与 FakeDNS 类型名问题（见上）；校验失败日志被覆盖。

（该增量的暂存与回滚脚本已在变基部署后删除，原因同上。）

### 2026-10-04 夜间：变基版本部署

用 `tests/build_home_overlay.py` 生成覆盖包，`tests/home_rebase_deploy.sh` 安装（暂存与备份：`/root/passwall2-hot-reload-test-20261003/rebase-20261004b/`）：先校验 Lua 与 shell 语法，删除上游已删除或改名的残留文件，全部改动先备份；启动后核对默认实例核心、分流子链与透明 HTTPS（generate_204），任一失败立即回滚，120 分钟未确认自动回滚。第一次部署（`rebase-20261004`）因上文旧格式 `sources` 导致非代理模式，健康检查失败后约 25 秒内自动回滚；修正后第二次部署通过并已确认。

变基版本上重跑 `home_global_switch_test.py`、`home_cross_core_test.py`（sing-box ↔ Xray，替换后各自原生热更新）、`home_live_reload_test.py`、`home_procd_trigger_test.py`、`home_invalid_reload_test.py` 全部通过，passwall2 配置哈希不变。跨核心测试一度因 Xray 拒绝上游 `env` 字段而走兼容路径，据此修正了核心补丁（见上）。

部署后的 `passwall2_server restart` 暴露了上文的服务端配置格式问题，用 `server-migrate-20261004/` 增量安装迁移模块后实测：两个服务端（sing-box socks 31004、Xray VLESS REALITY xhttp 31003）进程运行并监听，生成新的 UCI 放行规则，旧包含与 `PSW2-SERVER` 链已删除，用户自定义的 WAN 限制规则保持；迁移前用备份中的旧代码从旧配置生成 JSON，与迁移后新代码的生成结果逐路径比对，差异只有上游新版生成器的字段（Xray `listen`、`streamSettings.method`、`minClientVer="1.0.0"`、`version`，sing-box 空 `endpoints`）与迁移生成的用户名。socks 认证生效（错误密码、无凭据被拒）；VLESS 用户在临时副本中换用兼容的 REALITY 目标后经 REALITY + xhttp 返回 204。两处与迁移无关的现状：31004 出站节点所在服务器的 TCP 端口不通；31003 配置的 REALITY 伪装目标在 ServerHello 之后不返回 ChangeCipherSpec，REALITY 认证通过后仍回落转发（开启 `show` 可见），需要换一个兼容的目标站。

回滚：`rebase-20261004b/rollback.sh` 会先调用 `server-migrate-20261004/rollback.sh` 恢复旧格式服务端配置与旧防火墙包含，再从 `backup/files.tar.gz` 恢复变基前的应用文件与 Xray 二进制；之后如需回到最初的原装文件与配置，再执行顶层 `rollback.sh`。部署确认后已删除覆盖包、payload、重复的 Xray 副本、第一次失败部署的暂存和测试基线文件，overlay 占用由 62% 降到 26%。

### 2026-10-04 夜间：集合热刷新、节点地址与定时选项

用 `tests/home_increment_deploy.sh <暂存名>` 增量安装（持服务锁替换、先备份、生成回滚脚本、不重启）：`refresh-sets-20261004`（集合热刷新与支持 `ReloadGeodata` 的 Xray）、`endpoints-20261004`（节点地址、定时选项、servers-file 布局）、`crontab-fix-20261004`（busybox 没有 `pkill`）。每次安装后受控重启一次，确认启动路径并让前置 DNS 按新布局重建缓存。实测：

- `tests/home_refresh_test.py`：经 ubus 提交 `flush_set=1`，约 10 秒完成热刷新（11 个 sing-box 规则集原地重写、China GeoIP 集合重新载入），核心与 DNS 进程、主链、分流子链不变，`flush_set` 被消费；给 myshunt 用到的规则追加测试网段，集合原子加入，恢复后原子移除；旧的透明代理 TLS 长连接与 SOCKS 长连接全程可用，配置逐字节恢复。
- `tests/home_endpoint_test.py`：新增一个地址为当前得到 FakeIP 的域名（www.cloudflare.com）的临时节点，热更新后前置 DNS 经 SIGHUP 改由国内 DNS 解析它（得到真实地址），下载地址的测试 IP 进入 `psw2_vps`；删除节点同样热更新；核心、DNS、防火墙规则不变。
- `tests/home_schedule_test.py`：关闭再打开看门狗只重建计划任务与后台进程，crontab 内容不变。

暴露的问题：路由器的 busybox 没有 `pkill`，早期的 `reload_crontab` 与家里测试的收尾清理都静默失败（看门狗重复、临时 openssl/sleep 进程残留到超时），已改为 `busybox pgrep -f` 加 `kill` 并清理。

增量 `iptables-20261004`（执行器按防火墙后端选择脚本、判定逻辑去掉 iptables 特例、`app.sh reload_direct_dns` 支持 ipset、新的 `iptables.sh`）安装后无需重启（家里是 nftables，iptables 版只能在本机命名空间中验证）；重跑 `home_global_switch_test.py`、`home_refresh_test.py`、`home_endpoint_test.py` 全部通过。

回滚顺序：按安装的相反顺序执行各增量暂存目录中的 `rollback.sh`（`iptables-20261004` → `crontab-fix-20261004` → `endpoints-20261004` → `refresh-sets-20261004`，每个都会恢复该增量之前的文件并重启 passwall2），再执行 `rebase-20261004b/rollback.sh`（连带撤销服务端迁移），最后才是顶层 `rollback.sh`。各增量的 payload 副本已删除，备份与回滚脚本保留。

### 2026-10-04 深夜：全部配置热重载（差量热重载）

四个增量，均用 `tests/home_increment_deploy.sh` 安装（先备份、生成回滚脚本）：`reconcile-20261004`（影子启动、稳定分配、差量提交、启动顺序修正）安装后受控重启一次以写出稳定分配记录；`listener-20261004`（支持监听器热更新的 sing-box 与 Xray、执行器改进）安装后受控重启一次换上新核心；`ipt-reconcile-20261004`（iptables 规则配方与差量提交）与 `sync-20261004`（init 脚本文案与注释）无需重启。之后 `reload.lua plan` 对当前配置输出 `plan: none`。

`tests/home_reconcile_test.py` 经 ubus（LuCI 同款）提交并恢复，全部没有完整重启，路由器上经透明代理的 TLS 长连接与 SOCKS 长连接在变更前后可用，passwall2 配置逐字节恢复：

- 本机代理、客户端代理开关，代理端口增加 8443：只替换防火墙规则（一个 nft 事务），恢复后主链与分流子链逐条一致。
- 新增／删除跟随全局的访问控制条目：只增删规则；新增／删除独立节点的条目：新核心与前置 DNS 先启动、就绪后才切防火墙，删除时停止。
- 直连 DNS 改为 223.5.5.5：核心原生热更新、前置 DNS 原地重读（SIGHUP）、直连 DNS 放行规则替换，进程都不重启。
- dnsmasq 主实例缓存条数变化（外部输入）：前置 DNS 蓝绿替换到新端口，DNS 劫持随事务切换，pid 文件指向新实例；dhcp 配置逐字节恢复。
- 全局 Socks 端口换到空闲端口：核心原生热更新监听器（PID 不变），经旧监听器建立的 SOCKS 连接保持，新端口可用、旧端口关闭；第一次误选了被 frps 占用的 1071，新入站绑定失败后核心恢复原监听器、差量提交整体回滚，行为正确。
- TCP 转发方式 重定向 ↔ TPROXY：防火墙事务替换与核心原生更换入站同时完成，切换前建立的透明连接全程可用。
- 分流节点开关直连写集合：按需启动／停止 chinadns-ng，白名单集合与子链在事务中增删；开关 GeoIP 预加载：规则集合删除与重建（China 集合重新载入 4000 余条）。
- DNS 劫持改为“只拦截发往本机的查询”再恢复：前置 DNS 实例停止／重启，dnsmasq 主实例先带上新配置重启再切防火墙；dhcp 中 server 列表与 noresolv 两行的先后顺序被上游的备份恢复逻辑改变（完整启动同样如此），语义不变，已按测试前的备份逐字节复原。
- Socks 实例换到空闲端口再恢复：新端口实例启动；恢复到被 frps 占用的端口时，热更新失败后改为重启核心，起不来则与完整启动一样跳过并记录。
- 关闭再打开 passwall2：透明代理（核心、前置 DNS、防火墙规则、ip rule、sysctl）整体拆除再整体拉起，恢复后规则与变更前一致。

重跑快速路径的 `home_global_switch_test.py`、`home_refresh_test.py`、`home_endpoint_test.py`、`home_schedule_test.py`、`home_live_reload_test.py`、`home_invalid_reload_test.py`、`home_procd_trigger_test.py`、`home_cross_core_test.py` 全部通过（跨核心测试的 Xray 节点上游仍不可用，只影响该节点连通性）。暴露并修正：差量提交后快照应记录提交后的外部输入；跨核心切换生成的新 secret 与稳定分配不一致会导致之后不必要的核心重启；跨核心测试改为不把直连拨号节点的本机放行规则（切换时补充、上游语义）计入主链比较。

未在实机验证：家里没有 ipset 且 dnsmasq 编译为 no-ipset，iptables 后端与防火墙后端切换只在本机命名空间中验证；家里未启用负载均衡，haproxy 软重载未实测。

回滚顺序：先按相反顺序执行 `sync-20261004`、`ipt-reconcile-20261004`、`listener-20261004`、`reconcile-20261004` 的 `rollback.sh`（每个都会恢复该增量之前的文件并重启 passwall2），再按上文顺序回滚更早的增量。

### 2026-10-05：办公室上线暴露的修正

五个增量，均无需重启：`dnsfix-20261005`（`app.sh` 直连 DNS 空值保护、主实例缓存标记，`helper_dnsmasq.lua`）、
`urltest-20261005`（`reload.lua` 不再登记测速等临时实例）、`stableoff-20261005` 与 `temporary-20261005`（临时实例不写
稳定分配与直连节点列表：`utils.sh`、`app.sh`、两个生成器）、`marker-20261005`（`reload.lua` 比较时忽略端口分配标记）。

节点测速（`test.sh url_test_node`，LuCI 节点列表会自动对全部节点测速）与 Socks 自动切换的探测（`test_node_*`）经
`app.sh run_socks` 启动临时核心，原先在运行目录留下四种痕迹：热重载实例记录、稳定分配中的 API 端口与 secret、生成器
追加到 `direct_node_list` 的被测节点（随后的重载据此补本机放行规则）、端口分配标记 `get_port_<端口>`。前三种不再产生
（`run_socks` 对这类 flag 设置 `PW2_TEMPORARY`）；分配标记保留（并行测速靠它错开端口），差量比较忽略它，提交时只写回
目标状态中的标记。

- `tests/home_main_dnsmasq_plan_test.py`：经 ubus 切到 dnsmasq 主实例模式（差量热重载）→ 完整重启 → `reload.lua plan`
  为 `plan: none` → 切回；passwall2 配置逐字节恢复，dhcp 按语义恢复后逐字节复原。修正前办公室在同样情形下完整启动后
  计划误报 `soft_dns: main`。
- `tests/home_url_test_record_test.py`：节点测速后没有 `instance_url_test_*` 记录、稳定分配中没有测速键、
  `direct_node_list` 没有新增（优先选不在列表中的节点），随后的重载仍是核心快速路径的“无运行时变化”，空跑计划与
  测速前相同。修正前，实例记录与直连节点登记两项由该测试复现失败（记录残留时重载转入差量热重载并“停止”了测速
  实例）；稳定分配中的测速键与测速后计划出现变化在家里和办公室直接观察到。

家里的 Socks 实例端口 10801 被 frps 占用（之前测试已知的冲突），监控每分钟记录一次该实例退出重启，与本次修正无关。

家里先前测试累积的直连节点放行规则用一次“UDP 不代理端口加 9 再恢复”的差量热重载清理，配置逐字节恢复，之后空跑
计划为 `plan: none`。

回滚顺序：先按相反顺序执行 `marker-20261005`、`temporary-20261005`、`stableoff-20261005`、`urltest-20261005`、
`dnsfix-20261005` 的 `rollback.sh`，再按上文顺序回滚更早的增量。

## 办公室路由器上线

2026-10-05 目标为办公室的京东云 RE-CS-02（qualcommax/ipq60xx，aarch64，LibWrt），原装 LibWrt 改版的 passwall2 26.1.19、
sing-box 1.12.17、Xray 26.1.18，dnsmasq-full（nftset、no-ipset），fw4。操作者经这台路由器上网，安装期间会断网，所以安装
完全在路由器上独立完成：`tests/build_home_overlay.py`（`PW2_OVERLAY_NAME=office`，`PW2_SINGBOX`／`PW2_XRAY` 指向 arm64 核心，
`PW2_LMO` 指向中文翻译）生成覆盖包，与 `tests/office_deploy.sh` 一起放到 `/root/pw2-office/`：

- `check` 只检查：设备身份、包校验与路径白名单、Lua／shell 语法、新核心能否运行与热重载能力、旧版本连通性基线，
  并预演直连 DNS 选项迁移（换算出的服务器必须能解析国内域名），不改动系统；
- `run` 备份文件与配置 → 启动独立看护进程 → 停止旧版本（断网开始）→ 安装、删除旧包残留 → 迁移选项 → 启动新版本 →
  健康检查（核心、分流子链、策略路由、主 dnsmasq 解析国内域名，Google／百度／Anthropic 并行探测，相对基线判定），
  失败立即回滚并确认旧版本恢复；
- `watch` 安装进程意外结束或 8 分钟未完成即回滚；成功后 15 分钟内未 `touch /root/pw2-office/commit` 同样回滚；
- 目录、命令行都不含 `passwall2/`（两版 `app.sh stop` 都会结束命令行含它的进程），等待只用 `sleep 5`。

第一次安装健康检查失败并自动回滚（百度不可达）：旧配置是 `direct_dns_protocol=udp` 加 LibWrt 专有的
`direct_dns_mode=smartdns`（直连 DNS 取 smartdns 端口 7053），没有 `direct_dns`；新版对空值调用 `parseDNS("")` 得到
`("", 53)`，拆分后直连 DNS 成了 `udp://53:`，国内域名全部解析失败。而且这台路由器的 dnsmasq 上游是旧版固定的
`127.0.0.1#15353`，新版不再监听，“自动获取”在这里也不可用。修正：`get_direct_dns` 在未填写服务器时保持自动获取；
部署脚本按旧模式换算（smartdns → `udp` + `127.0.0.1:<smartdns 端口>`，custom → 取 `direct_dns` 首项，auto → 自动）并删除
`direct_dns_mode`。

第二次安装：断网约 18 秒，健康检查第 1 轮通过。确认前在看护期内实测：无变化重载走核心快速路径（核心 PID 不变，期间
逐秒探测全部正常）；仅防火墙的改动（UDP 不代理端口加 9 再恢复）两次都是“差量热重载完成，未完整重启：防火墙规则已在
一个 nft 事务中替换”，配置逐字节恢复，旧版残留的白名单集合随首次提交清除。之后发现并修正上文各处问题，按“只换文件、
不重启”同步（持服务锁替换，先备份到 `/root/pw2-office/hotfix-20261005{,b,c,d,e}/backup.tar.gz`），再用一次差量热重载
清理测速留下的直连节点放行规则；最终空跑计划为 `plan: none`，三个节点测速 204 后仍为 `none`，重载为快速路径。
期间操作者在 LuCI 中把 Socks 实例端口由 10801 改为 10807：差量热重载在原核心进程上换了监听端口（PID 不变），新 LuCI
保存页面时写入了新版选项的缺省值（`remote_rewrite_ttl`、分流节点的 `enable_geoview_ip`、`write_ipset_direct`）。
Anthropic API 根路径的响应由旧版的 403 变为 404（两者都说明可达，出口不同）。

回滚到旧版：`sh /root/pw2-office/deploy.sh rollback` 用新版停止，恢复安装前的文件与四个配置（passwall2、passwall2_server、
dhcp、firewall 恢复到旧版停止后的状态，安装后的配置修改会丢失）再启动旧版；它覆盖上面同步的文件。第一次安装的备份保留在
`backup-attempt1/`。
