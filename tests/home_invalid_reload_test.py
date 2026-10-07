#!/usr/bin/env python3
"""家里实际服务拒绝坏配置后继续提供旧配置；最终恢复 UCI 测试改动。"""

import json
import os
import subprocess

SSH = ["ssh", "-4", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ControlPath=/tmp/passwall2-hot-reload/home-mux/control", "-p", os.environ.get("PW2_HOME_SSH_PORT", "22"), os.environ.get("PW2_HOME_SSH", "root@192.168.1.1")]
ROOT = "/root/passwall2-hot-reload-test-20261003"


def run(command, check=True):
    result = subprocess.run(SSH + [command], text=True, capture_output=True, timeout=60)
    if check and result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result


def pid():
    return run("lua -e 'local a=require \"luci.passwall2.api\"; for n in a.fs.dir(\"/proc\") do if n:match(\"^%d+$\") then local c=a.fs.readfile(\"/proc/\"..n..\"/cmdline\") or \"\"; if c:find(\"run\",1,true) and c:find(\"-c\",1,true) and c:find(a.TMP_ACL_PATH..\"/acl_default.json\",1,true) then print(n) end end end'").stdout.strip()


before = pid()
assert before
run(f"umask 077; uci export passwall2 > {ROOT}/invalid-baseline.uci")
try:
    run("uci set passwall2.SjyWplsT.protocol='test-invalid-protocol'; uci commit passwall2")
    result = run("/etc/init.d/passwall2 reload", check=False)
    assert result.returncode == 1, result.returncode
    assert pid() == before, "拒绝坏配置时重启了现有核心"
    health = run("curl --socks5-hostname 127.0.0.1:1070 --connect-timeout 8 --max-time 25 --retry 2 --retry-all-errors -sS -o /dev/null -w '%{http_code}' https://www.google.com/generate_204").stdout.strip()
    assert health == "204", health
    print("PASS：家里生产服务拒绝无效协议配置，核心 PID 未变，旧配置 HTTPS 仍正常。")
finally:
    run(f"uci import passwall2 < {ROOT}/invalid-baseline.uci; uci commit passwall2")
    run("/etc/init.d/passwall2 reload")
assert pid() == before
print("PASS：坏配置测试改动已恢复，原服务未中断。")
