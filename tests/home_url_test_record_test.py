#!/usr/bin/env python3
"""家里实测：节点测速（LuCI 节点列表的 URL 测试，test.sh url_test_node）不留下热重载实例记录、稳定分配与
直连节点登记，之后的重载仍走核心快速路径。

测速经 app.sh run_socks 启动临时核心；若它也登记为重载实例，测速结束后记录残留，下一次重载会把它当作被删除的实例，
转入差量热重载并“停止”它（正在进行的测速会被打断）；它的 API 端口与 secret 写进稳定分配、被测节点写进
direct_node_list（随后的重载据此补放行规则）后，差量比较也总是“有变化”——办公室路由器上线时发现。
只针对家里路由器，不改配置；只读稳定分配的键，不输出值。
"""

from home_global_switch_test import remote
from home_reconcile_test import log_lines

RECORDS = "ls /tmp/etc/pass''wall2/reload/ | grep -c '^instance_url_test_' || true"
STABLE = "awk '{print $1}' /tmp/etc/pass''wall2/stable | grep -c -E '^(url_test|test_node)_' || true"
DIRECT = "sort -u /tmp/etc/pass''wall2/direct_node_list 2>/dev/null || true"
PLAN = "cd /usr/share/pass''wall2 && lua ./reload.lua plan 2>&1 | head -n 1"


def plain_node(listed):
    """普通节点，优先选不在 direct_node_list 中的（否则测不出是否被追加）。"""
    out = remote("uci -q show passwall2 | sed -n \"s/^passwall2\\.\\([A-Za-z0-9_]*\\)=nodes$/\\1/p\"")
    candidates = []
    for node in out.split():
        protocol = remote(f"uci -q get passwall2.{node}.protocol || true").strip()
        kind = remote(f"uci -q get passwall2.{node}.type || true").strip().lower()
        if kind in ("sing-box", "xray") and not protocol.startswith("_"):
            candidates.append(node)
    assert candidates, "家里没有可测速的普通节点"
    return next((node for node in candidates if node not in listed), candidates[0])


def main():
    direct_before = set(remote(DIRECT).split())
    plan_before = remote(PLAN, timeout=180).strip()
    node = plain_node(direct_before)
    assert int(remote(RECORDS).strip()) == 0, "测试前已有测速实例记录"
    assert int(remote(STABLE).strip()) == 0, "测试前稳定分配中已有测速实例的键"
    result = remote(f"cd /usr/share/pass''wall2 && ./test.sh url_test_node {node} urltest_node", timeout=60).strip()
    leaked = int(remote(RECORDS).strip())
    keys = int(remote(STABLE).strip())
    added = set(remote(DIRECT).split()) - direct_before
    print(f"  测速 {node}（{'不在' if node not in direct_before else '已在'}直连节点列表）：结果 {result or '空'}，"
          f"残留实例记录 {leaked} 个，稳定分配中的测速键 {keys} 个，新增直连节点登记 {len(added)} 个。")
    before = log_lines()
    remote("/etc/init.d/passwall2 reload", timeout=180)
    joined = "\n".join(log_lines()[len(before):])
    print("  测速后重载：" + " | ".join(line.split(": ", 1)[-1].strip() for line in joined.splitlines() if line.strip()))
    plan_after = remote(PLAN, timeout=180).strip()
    print(f"  空跑计划：测速前 {plan_before}，测速并重载后 {plan_after}。")
    assert leaked == 0, "测速留下了热重载实例记录"
    assert keys == 0, "测速写入了稳定分配"
    assert not added, "测速把节点写进了 direct_node_list"
    assert "已停止" not in joined and "差量热重载" not in joined and "完整重启" not in joined, joined
    assert "无运行时变化" in joined, joined
    # 测速的端口分配标记会留在运行记录里（并行测速靠它错开端口），但不应让差量比较出现变化。
    assert plan_after == plan_before, f"测速后空跑计划由 {plan_before} 变为 {plan_after}"
    print("PASS：测速不登记重载实例、不写稳定分配与直连节点列表，之后的重载仍走核心快速路径。")


if __name__ == "__main__":
    main()
