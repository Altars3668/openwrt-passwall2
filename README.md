# Passwall2 · 原生热重载定制版

**简体中文** | [English](README.en.md)

基于 [Openwrt-Passwall/openwrt-passwall2](https://github.com/Openwrt-Passwall/openwrt-passwall2) 的定制 fork，核心目标是：**把日常“保存并应用”从整套服务 stop/start，改成可校验、可回滚、按组件更新的应用流程**。

上游提供 LuCI 代理管理、节点、订阅、分流、DNS 和访问控制；我的改造集中在服务生命周期、sing-box / Xray 的原生配置更新、防火墙差量提交及旧配置迁移，**不是另写一个代理核心，也不把上游协议支持算作原创功能**。

当前定制线基于上游 **26.10.1**。GitHub `main` 是用于公开构建的**脱敏快照**；完整开发历史保留在私有 Gitea，两端 commit SHA 不应当被要求相同。

## 我的改造与特色

| 改造 | 实际作用 |
| --- | --- |
| **核心原生热更新** | 为匹配版本的 sing-box / Xray 提供补丁，校验并预加载新运行实例；新连接进入新配置，旧连接在旧实例中排空。 |
| **全局节点热切换** | 同核心切换保留已有连接，原子更新分流子链；DNS 与其他实例不必跟着整套重启。 |
| **影子启动 + 差量协调** | 用真实启动流程生成暂存目标状态，再按进程、监听器、DNS、集合、防火墙及系统派生项比较提交；未变化的组件保持不动。 |
| **规则 / 节点 / 计划任务热刷新** | 规则集合、节点域名 / 地址和更新计划分别处理，减少因为非核心变化而重启代理与 DNS。 |
| **nftables / iptables 支持** | nftables 使用规则事务；iptables 使用子链、restore 配方与 ipset swap，保留两者能力差异。 |
| **校验、事务与恢复** | 配置先检查，失败尽量恢复旧配置 / 进程 / 规则；处理中断和提交后的恢复路径有明确状态记录。 |
| **服务互斥修正** | 稳定 flock inode、关闭长驻子进程继承的锁、限时等待与排队应用，避免保存被丢弃或永久卡锁。 |
| **旧配置兼容** | 迁移旧 ACL 来源 / 端口写法与服务端凭据结构，修复直连 DNS 推导及旧 dnsmasq 缓存布局。 |
| **测速实例隔离** | 节点测试使用独立目录与实例标记，不把临时测速进程误当作热重载目标。 |

详解：[docs/hot-reload.md](docs/hot-reload.md) · 实现：[reload.lua](luci-app-passwall2/root/usr/share/passwall2/reload.lua) / [reconcile.lua](luci-app-passwall2/luasrc/passwall2/reconcile.lua) · 核心补丁：[patches/cores](patches/cores/) · 测试：[tests](tests/)。

## “无损”具体意味着什么

| 场景 | 行为与边界 |
| --- | --- |
| 同核心运行时配置 / 节点变化 | 能力检查通过时原生热更新；既有连接继续使用旧配置，新连接使用新配置。 |
| ACL、监听器或 DNS 等结构变化 | 暂存 / 校验后按组件提交；可能蓝绿替换 DNS 或重新绑定被改变的监听器，不能保证每个组件 PID 都不变。 |
| sing-box ↔ Xray 或不支持的静态变化 | 仅替换相关核心的兼容路径；该核心已有连接会断开，日志明确说明。 |
| 无有效启动快照、提交中断或不兼容集合定义 | 回到完整重启 / 恢复路径，不伪装成无损成功。 |
| 无效配置 | 拒绝应用并记录检查失败，不应先停掉正常服务再验证。 |

不会把一条已经连接服务器 A 的 TCP 会话搬到服务器 B。**“旧连接排空”与“连接迁移”是两回事**。TUN / WireGuard、FakeIP 地址池、日志和控制接口等静态部分仍有重启边界；保留代数达到上限时也可能需要重启。

## 构建与核心配套

当前补丁基线：

- **sing-box 1.14.2**，构建需包含 `with_clash_api`。
- **Xray-core 26.9.30**。
- 对应补丁按准确版本放在 [patches/cores](patches/cores/)；不能不处理冲突就套到其他版本。

只安装本 fork 的 LuCI 包、仍使用未经修改的上游核心，**不能获得本 fork 的原生热重载能力**。先检查核心能力，再谈是否无损应用：

```sh
sing-box hot-reload-capabilities
xray api reloadconfig --local
```

这些是定制核心的能力探测，不是上游所有版本都有的命令。能力不足或静态变更时会选择兼容路径；以日志和实际进程 / 连接状态为准。

在 OpenWrt SDK / 构建树中，将本仓库的 `luci-app-passwall2` 作为包源码，并为匹配的核心配方加入对应补丁。完整集成示例见配套 [OpenWRT-CI 的 Office/packages.sh](https://github.com/Altars3668/OpenWRT-CI/blob/main/Office/packages.sh)，包括固定核心来源、补丁版本检查和编译工具链处理。

当前没有可依赖的预编译应用 Release。配套固件是另外的发布产物，不能把“存在源码或补丁”当作“所有目标已编译通过”。

## 使用与诊断

1. 备份 UCI 配置和旧包 / 核心，保留独立的远程恢复通道。
2. 安装匹配的应用与定制核心，首次启动建立运行快照；首次升级可能仍需要完整重启。
3. 此后 LuCI 保存应用由 UCI / procd 触发 `reload`，执行器选择适合当前变化的路径。
4. 结合日志、进程 PID、DNS 状态及已有连接检查应用结果，而不是只看网页提示。

```sh
# 在已部署相应版本的路由器上诊断；plan 需要服务的运行状态
lua /usr/share/passwall2/reload.lua plan
logread -e passwall2
```

手工 `/etc/init.d/passwall2 reload` 是**状态变更操作**，不是只读检查；在经该路由器远程操作时应先安排保护与回滚。

## 验证与安全边界

[tests](tests/) 包含纯 Lua 逻辑、配置生成、独立网络命名空间中的防火墙等价性、真实核心 loopback 生命周期，以及实机应用 / 回滚测试。

```sh
# 不连接路由器的本地逻辑测试，在源码根目录运行
lua tests/reload_logic_test.lua "$PWD"
lua tests/reconcile_logic_test.lua "$PWD"
lua tests/server_migrate_test.lua "$PWD"
python3 -I tests/init_reload_test.py
python3 -I tests/direct_dns_test.py
```

- 防火墙命名空间测试有工具和权限要求；真实核心测试需要匹配的已打补丁二进制，不能混用结果。
- `home_*` / `office_deploy.sh` 是**可能改动真实设备的测试或部署工具**，不能当作普通单元测试一键执行。公开测试的设备入口需用自己的环境配置。
- 含 API secret 的配置、运行元数据及 `/tmp/etc/passwall2/reload/` 事务文件需要保密，不能原样上传诊断日志。
- 私有开发分支发布到 GitHub 前必须经过配套 CI 仓库的脱敏发布脚本；不要直接强制推送完整私有历史。
- 更换代理核心包可能覆盖定制二进制，应把补丁接入自己的包构建流程，而不是仅手工替换文件。

## 来源与许可证

保留 [Openwrt-Passwall](https://github.com/Openwrt-Passwall/openwrt-passwall2) 的来源、版权与许可证声明；定制服务逻辑和核心补丁由 Altars3668 维护。应用授权以仓库许可证和源码为准，sing-box / Xray 及其他依赖遵循各自许可证。

相关项目：[RE-CS-02 固件 CI](https://github.com/Altars3668/OpenWRT-CI) · [上游 Passwall packages](https://github.com/Openwrt-Passwall/openwrt-passwall-packages)。
