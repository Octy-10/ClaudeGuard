import os
import plistlib
import socket
import sys
import unittest
from contextlib import nullcontext
from unittest.mock import patch

from guard import bridge, macos, macos_doctor, macos_protection, updater
from guard.clash_config import PROBE_PORT
from guard.config import GuardConfig
from guard.doctor import PROBE_PATH, CheckItem, ExitInfo

OLD_HEADER = "Proto Recv-Q Send-Q Local Address Foreign Address (state) rhiwat shiwat pid epid state options"
NEW_HEADER = "Proto Recv-Q Send-Q Local Address Foreign Address (state) rxbytes txbytes rhiwat shiwat process:pid state options"


class MacOSProbeTests(unittest.TestCase):
    def test_listener_parser_accepts_both_netstat_formats(self):
        old = f"{OLD_HEADER}\ntcp4 0 0 127.0.0.1.17897 *.* LISTEN 1 1 82 0 0x01 0x02"
        new = f"{NEW_HEADER}\ntcp4 0 0 127.0.0.1.17897 *.* LISTEN 0 0 1 1 Process With Spa:82 00100 0x02"
        for output in (old, new):
            self.assertEqual(macos.parse_tcp_listeners(output, PROBE_PORT), [("127.0.0.1", 82)])

    def test_only_verified_loopback_listener_is_used(self):
        occupied = "tcp4 0 0 127.0.0.1.17897 *.* LISTEN 1 1 82 0 0x01 0x02"
        exposed = "tcp46 0 0 *.17897 *.* LISTEN 1 1 83 0 0x01 0x02"
        for exposure, owner, expected in (
            ("", "/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo", True),
            ("", "/usr/bin/python3", False),
            (exposed, "/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo", False),
        ):
            with self.subTest(exposed=bool(exposure), owner=owner):
                output = f"{OLD_HEADER}\n{occupied}\n{exposure}"
                with patch.object(macos, "run_command", side_effect=[output, owner]):
                    self.assertEqual(macos.verify_proxy_listener(PROBE_PORT), expected)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS netstat")
    def test_native_netstat_includes_live_listener_owner(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            output = macos.run_command("/usr/sbin/netstat", "-anv", "-p", "tcp")
            self.assertIsNotNone(output)
            self.assertIn(("127.0.0.1", os.getpid()), macos.parse_tcp_listeners(output, port))

    def test_doctor_never_uses_unverified_tun_as_probe_route(self):
        with (
            patch.object(macos_doctor, "default_route_interface", return_value="utun4"),
            patch.object(macos_doctor, "default_dns_servers", return_value=[]),
            patch.object(macos_doctor, "process_paths", return_value=[]),
            patch.object(macos_doctor, "timezone_name", return_value="America/Los_Angeles"),
            patch.object(macos_doctor, "_audit_clash_verge_config", return_value=CheckItem("clash_config", "Clash", "WARN", "入口无法核实")),
            patch.object(macos_doctor, "query_exit_info") as query,
        ):
            report = macos_doctor.run_macos_doctor(GuardConfig())
        query.assert_not_called()
        self.assertEqual(report.overall, "yellow")
        self.assertFalse(report.states.firewall_active)
        self.assertEqual(report.exit_info.path, "")

    def test_doctor_detects_drift_on_the_verified_route(self):
        with (
            patch.object(macos_doctor, "default_route_interface", return_value="utun4"),
            patch.object(macos_doctor, "default_dns_servers", return_value=[]),
            patch.object(macos_doctor, "process_paths", return_value=[]),
            patch.object(macos_doctor, "timezone_name", return_value=""),
            patch.object(macos_doctor, "_audit_clash_verge_config", return_value=CheckItem("clash_config", "Clash", "PASS", "已核实")),
            patch.object(macos_doctor, "query_exit_info", return_value=ExitInfo(ip="203.0.113.2", path=PROBE_PATH)) as query,
        ):
            report = macos_doctor.run_macos_doctor(GuardConfig(monitored_probe_ip="203.0.113.1"))
        query.assert_called_once_with(PROBE_PORT, PROBE_PATH)
        self.assertEqual(report.overall, "red")
        self.assertIn("出口 IP 发生漂移", next(item.summary for item in report.items if item.id == "exit_ip"))

    def test_macos_bridge_rejects_uninstalled_protection_and_unverified_purity(self):
        with (
            patch.object(sys, "platform", "darwin"),
            patch.object(bridge, "load_config", return_value=GuardConfig()),
            patch.object(bridge, "check_probe_route", return_value="入口无法核实"),
            patch.object(bridge, "run_purity_check") as purity,
            patch.object(bridge, "system_change_lock", return_value=nullcontext(True)),
            patch.object(bridge.GuardBridge, "_run_doctor_unlocked"),
            patch.object(macos_protection, "app_relay_issue", return_value="缺少 Claude 专用入口"),
            patch.object(macos_protection, "host_available", return_value=False),
        ):
            instance = bridge.GuardBridge()
            for action in (instance.enable_all_protection, instance.run_rescue, instance.kill_claude_app, instance.elevate, instance.install_update):
                self.assertFalse(action()["ok"])
            for toggle in (instance.toggle_dns_lock, instance.toggle_killswitch, instance.toggle_ipv6):
                self.assertFalse(toggle(True)["ok"])
            self.assertFalse(instance.check_ip_purity()["ok"])
            self.assertTrue(instance.get_override_script()["ok"])
        purity.assert_not_called()

    def test_launch_requires_active_configured_filter_and_audited_listener(self):
        for status in ({"configured": True, "active": False}, {"configured": False, "active": True}):
            with patch.object(macos_protection, "filter_status", return_value=status), patch.object(macos_protection, "host_command") as call:
                self.assertFalse(macos_protection.launch_claude()["ok"])
                call.assert_not_called()
        with (
            patch.object(macos_protection, "filter_status", return_value={"configured": True, "active": True}),
            patch.object(macos_protection, "app_relay_issue", return_value="监听端口归属未知"),
            patch.object(macos_protection, "host_command") as call,
        ):
            self.assertFalse(macos_protection.launch_claude()["ok"])
            call.assert_not_called()

    def test_extension_status_checks_installed_version_and_active_state(self):
        extension_id = macos_protection.EXTENSION_ID
        version = macos_protection.__version__
        for output, expected in (
            (f"* * TEAMID {extension_id} ({version}/{version}) Guard [activated enabled]", True),
            (f"* * TEAMID {extension_id} (1.0.0/1.0.0) Guard [activated enabled]", False),
            (f"* * TEAMID {extension_id} ({version}/{version}) Guard [activated waiting for user]", False),
        ):
            with patch.object(macos_protection, "run_command", return_value=output):
                self.assertIs(macos_protection.extension_active(), expected)

    def test_rescue_preserves_partial_status_and_updates_the_filter_expectation(self):
        with (
            patch.object(macos_protection, "settings_command", return_value={"ok": False, "message": "网卡原值待恢复"}),
            patch.object(macos_protection, "host_command", side_effect=[{"ok": True}, {"ok": True, "browsers": {}}]) as call,
        ):
            result = macos_protection.rescue()
        self.assertFalse(result["ok"])
        self.assertFalse(result["filter_enabled"])
        self.assertIn("网卡原值待恢复", result["message"])
        self.assertEqual(call.call_args_list[0].args, ("filter-disable",))

    def test_browser_profile_is_stable_and_limits_changes_to_intended_domains(self):
        encoded = macos_protection.browser_profile()
        self.assertEqual(encoded, macos_protection.browser_profile())
        profile = plistlib.loads(encoded)
        self.assertEqual(profile["PayloadScope"], "System")
        policies = profile["PayloadContent"][0]["PayloadContent"]
        self.assertEqual(set(policies), {"com.google.Chrome", "com.microsoft.edgemac", "org.mozilla.firefox"})
        self.assertEqual(policies["org.mozilla.firefox"]["Forced"][0]["mcx_preference_settings"]["Preferences"][
            "media.peerconnection.enabled"], {"Value": False, "Status": "locked"})

    def test_macos_update_selects_current_architecture_and_pins_release_host(self):
        manifest = {"version": "1.4.0", "assets": {"arm64": {"sha256": "1" * 64, "url": "https://example.invalid"}}}
        with patch.object(updater.platform, "machine", return_value="arm64"), patch.object(updater, "_fetch_with_fallback", return_value=manifest):
            update = updater.check_for_macos_update("1.3.0")
        self.assertTrue(update.available)
        self.assertEqual(update.asset, "ClaudeGuard-macOS-arm64.pkg")
        self.assertTrue(updater.is_allowed_update_url(update.download_url))
        self.assertIn("/download/v1.4.0/", update.download_url)

    def test_relay_audit_rejects_direct_node_in_claude_group(self):
        config = {
            "mode": "rule",
            "listeners": [{"name": "claude-guard-app", "type": "http", "listen": "127.0.0.1", "port": 17898,
                           "proxy": "Guard-Claude", "users": []}],
            "proxy-groups": [{"name": "Guard-Claude", "type": "select", "proxies": ["REJECT", "Direct node"],
                              "default-selected": "REJECT", "empty-fallback": "REJECT"}],
            "proxies": [{"name": "Direct node", "type": "direct"}],
        }
        with patch.object(macos_protection, "read_config", return_value=config), patch.object(macos_protection, "verify_proxy_listener") as verify:
            self.assertTrue(macos_protection.app_relay_issue())
        verify.assert_not_called()
