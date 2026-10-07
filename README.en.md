# Passwall2 · Native Hot-Reload Edition

[简体中文](README.md) | **English**

A custom fork of [Openwrt-Passwall/openwrt-passwall2](https://github.com/Openwrt-Passwall/openwrt-passwall2) focused on replacing routine whole-service stop/start with a **validated, recoverable, component-aware configuration application path**.

Upstream provides LuCI proxy management, nodes, subscriptions, routing, DNS and ACLs. My changes focus on lifecycle handling, native sing-box / Xray configuration updates, incremental firewall commits and legacy migration. **This is not a newly written proxy engine, and upstream protocol support is not claimed as my original work.**

The current custom line is based on upstream **26.10.1**. GitHub `main` is a **sanitised snapshot** for public builds; complete development history remains in private Gitea. The two forges are not expected to have identical commit SHAs.

## What I changed

| Change | Purpose |
| --- | --- |
| **Native engine configuration updates** | Version-matched sing-box / Xray patches validate and preload a new runtime; new connections use it while established connections drain in the old runtime. |
| **Global-node switching** | Same-engine switches retain existing connections and atomically replace routing subchains without restarting DNS and unrelated instances. |
| **Staged start and reconciliation** | Replays the real startup flow into a staging area, then compares processes, listeners, DNS, sets, firewall and derived system state; unchanged components stay untouched. |
| **Rule, endpoint and schedule refresh** | Separately updates rule sets, node domains / addresses and scheduled tasks to avoid unnecessary engine / DNS restarts. |
| **nftables and iptables paths** | Uses nftables transactions, or iptables subchains / restore recipes and ipset swaps, respecting their different atomicity guarantees. |
| **Validation, transactions and recovery** | Checks before applying and restores prior configuration / processes / rules where supported; interrupted and post-commit recovery paths have explicit state. |
| **Service-lock corrections** | Stable flock inode, no inherited locks in long-lived children, bounded waits and queued application prevent lost saves and stuck locks. |
| **Legacy configuration compatibility** | Migrates older ACL source / port forms and server credentials, and fixes direct-DNS inference and old dnsmasq cache layouts. |
| **Test-instance isolation** | Node tests use separate directories and instance markers rather than becoming hot-reload targets. |

Details: [docs/hot-reload.md](docs/hot-reload.md) · Implementation: [reload.lua](luci-app-passwall2/root/usr/share/passwall2/reload.lua) / [reconcile.lua](luci-app-passwall2/luasrc/passwall2/reconcile.lua) · [engine patches](patches/cores/) · [tests](tests/).

## What “lossless” actually means

| Situation | Behaviour and boundary |
| --- | --- |
| Same-engine runtime / node changes | Native update when capability checks pass: old connections keep the old runtime, new ones use the new configuration. |
| ACL, listener or DNS topology changes | Stage, validate and commit by component. DNS may be blue-green replaced and changed listeners rebound; not every PID is guaranteed to remain unchanged. |
| sing-box ↔ Xray or unsupported static changes | Compatibility path replaces the affected engine; its established connections disconnect, with an explicit log message. |
| Missing startup snapshot, interrupted commit or incompatible set definitions | Full restart / recovery rather than a false lossless-success claim. |
| Invalid configuration | Reject and retain the running service instead of stopping it before validation. |

An established TCP connection to server A is not moved to server B. **Draining connections is not migrating connections.** TUN / WireGuard, FakeIP pools, logging, control interfaces and other static components retain restart boundaries; the retained-runtime limit can also require a restart.

## Build and engine pairing

Current patch baselines:

- **sing-box 1.14.2**, with the `with_clash_api` build tag.
- **Xray-core 26.9.30**.
- Exact-version patches live in [patches/cores](patches/cores/). Do not apply them to other versions while ignoring conflicts.

Installing only this LuCI fork while keeping an unmodified upstream engine **does not enable its native hot-reload features**. Check engine capabilities first:

```sh
sing-box hot-reload-capabilities
xray api reloadconfig --local
```

These are custom-engine probes, not commands available in every upstream version. Unsupported capabilities or static changes select a compatibility path; verify logs, processes and connections.

In an SDK / buildroot, use this repository's `luci-app-passwall2` recipe and apply matching patches to the engine recipes. The companion [OpenWRT-CI Office/packages.sh](https://github.com/Altars3668/OpenWRT-CI/blob/main/Office/packages.sh) shows complete integration, including source pins, patch-version checks and toolchain handling.

There is currently no dependable prebuilt application Release. Companion firmware is a separate artifact; source or patch availability does not prove that all targets compile.

## Usage and diagnostics

1. Back up UCI, old packages and engines, and keep an independent recovery channel.
2. Install matching application and patched engines. Initial startup establishes snapshots; the first upgrade may still require a full restart.
3. Subsequent LuCI saves trigger `reload` through UCI / procd; the executor selects a path for the actual changes.
4. Verify logs, engine PIDs, DNS state and established connections, not just the browser's success message.

```sh
# Diagnostics on a router running this version; plan depends on service runtime state.
lua /usr/share/passwall2/reload.lua plan
logread -e passwall2
```

Manually calling `/etc/init.d/passwall2 reload` is a **state-changing operation**, not a read-only diagnostic. Arrange safeguards before doing it remotely through the same router.

## Verification and security boundaries

[Tests](tests/) cover pure Lua logic, configuration generation, firewall equivalence in separate network namespaces, real-engine loopback lifecycle and device deployment / rollback.

```sh
# Local logic tests from the source root; these do not connect to a router.
lua tests/reload_logic_test.lua "$PWD"
lua tests/reconcile_logic_test.lua "$PWD"
lua tests/server_migrate_test.lua "$PWD"
python3 -I tests/init_reload_test.py
python3 -I tests/direct_dns_test.py
```

- Namespace firewall tests require tools and permissions; real-engine tests require matching patched binaries. Do not conflate the results.
- `home_*` / `office_deploy.sh` are **device-facing tests or deployment tools**, not ordinary unit tests to run indiscriminately. Configure public test endpoints for your own environment.
- Configurations, metadata and `/tmp/etc/passwall2/reload/` transaction files can contain API secrets and must not be published unredacted.
- Publish private branches through the companion CI repository's sanitising publisher. Never force-push the complete private history directly to GitHub.
- Engine-package upgrades can replace custom binaries. Integrate patches into the package build instead of relying only on manual binary replacement.

## Attribution and licenses

Retains [Openwrt-Passwall](https://github.com/Openwrt-Passwall/openwrt-passwall2) attribution, copyright and license notices. Custom lifecycle logic and engine patches are maintained by Altars3668. Application terms are defined by repository notices and source; sing-box, Xray and other dependencies retain their own licenses.

Related: [RE-CS-02 firmware CI](https://github.com/Altars3668/OpenWRT-CI) · [upstream Passwall packages](https://github.com/Openwrt-Passwall/openwrt-passwall-packages).
