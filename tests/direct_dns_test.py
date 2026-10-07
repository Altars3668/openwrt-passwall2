#!/usr/bin/env python3
"""app.sh 的 get_direct_dns：从 app.sh 中取出函数，在替身 uci/config_n_get/lua_api 下运行。

lua_api 替身复现 api.parseDNS 的行为：空值返回 ("", 53)，拆分后服务器变成“53”、端口为空。
协议选了 UDP 却没有填写服务器（不经页面保存的迁移配置）时必须保持自动获取的 dnsmasq 上游。
"""

import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "luci-app-passwall2/root/usr/share/passwall2/app.sh"

STUBS = r"""
config_n_get() { eval "echo \"\${OPT_$2:-$3}\""; }
uci() { [ "$1 $2" = "show dhcp.@dnsmasq[0]" ] && for s in $DHCP_SERVERS; do echo "dhcp.cfg01411c.server='$s'"; done; }
lua_api() {
	local dns=${1#parseDNS(\"}
	dns=${dns%\")}
	case "$dns" in
		*.*:*) echo "${dns%:*} ${dns##*:}" ;;
		*) echo "$dns 53" ;;
	esac
}
"""


def function(name):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", APP.read_text(), re.S | re.M)
    return match.group(0)


def direct_dns(protocol="", dns="", servers="127.0.0.1#7053"):
    script = STUBS + function("get_direct_dns") + \
        'get_direct_dns\necho "$DIRECT_DNS_PROTO|$DIRECT_DNS_SERVER|$DIRECT_DNS_PORT|$DIRECT_DNS_DNSMASQ_SERVER|$RETURN_DNS"\n'
    shell = shutil.which("busybox")
    argv = [shell, "sh", "-c", script] if shell else ["sh", "-c", script]
    env = {"PATH": "/usr/bin:/bin", "OPT_direct_dns_protocol": protocol, "OPT_direct_dns": dns, "DHCP_SERVERS": servers}
    return subprocess.run(argv, env=env, capture_output=True, text=True, check=True).stdout.strip().split("|")


class DirectDnsTest(unittest.TestCase):
    def test_udp_without_server_keeps_auto(self):
        self.assertEqual(direct_dns("udp", ""), ["udp", "127.0.0.1", "7053", "", "127.0.0.1#7053"])

    def test_udp_with_server(self):
        self.assertEqual(direct_dns("udp", "223.5.5.5"), ["udp", "223.5.5.5", "53", "223.5.5.5#53", "127.0.0.1#7053,223.5.5.5#53#udp"])
        self.assertEqual(direct_dns("udp", "127.0.0.1:7053", "127.0.0.1#15353")[:4], ["udp", "127.0.0.1", "7053", "127.0.0.1#7053"])

    def test_auto_ignores_server(self):
        self.assertEqual(direct_dns("", "223.5.5.5"), ["udp", "127.0.0.1", "7053", "", "127.0.0.1#7053"])


if __name__ == "__main__":
    unittest.main()
