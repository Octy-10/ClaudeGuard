import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from guard import bridge, config, doctor, firewall, hardening, net, probe, purity, ui


class UniversalTunTests(unittest.TestCase):
    def test_tun_regex_matches_universal_clients_and_excludes_teredo(self):
        for name, desc in (
            ("FlClash", "Wintun Userspace Tunnel"),
            ("sing-tun", "sing-box tun"),
            ("v2rayN-TUN", "Wintun Userspace Tunnel"),
            ("WireGuard Tunnel", "WireGuard Tunnel"),
            ("tun0", "TAP-Windows Adapter V9"),
            ("CloudflareWARP", "CloudflareWARP"),
        ):
            self.assertTrue(
                probe._TUN_NAME_RE.search(name) or probe._TUN_DESC_RE.search(desc),
                f"Expected TUN match for {name}/{desc}",
            )
        for bad_name, bad_desc in (
            ("Teredo Tunneling Pseudo-Interface", ""),
            ("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter"),
            ("WLAN", "Intel(R) Wi-Fi 6E AX211 160MHz"),
        ):
            excluded = probe._TUN_EXCLUDE_RE.search(bad_name) or probe._TUN_EXCLUDE_RE.search(bad_desc)
            matched = probe._TUN_NAME_RE.search(bad_name) or probe._TUN_DESC_RE.search(bad_desc)
            self.assertTrue(excluded or not matched, f"Unexpected TUN match for {bad_name}/{bad_desc}")

    def test_net_direct_tun_transport_uses_target_host_and_ssl_context(self):
        with patch.object(net.http.client, "HTTPSConnection") as connect:
            connection = connect.return_value
            response = connection.getresponse.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = b'{"ip":"198.51.100.9"}'
            data, err = net.fetch_ip_info(None)
            self.assertEqual(err, "")
            self.assertEqual(data["ip"], "198.51.100.9")
            connect.assert_called_once()
            self.assertEqual(connect.call_args.args, ("ipapi.co", 443))
            self.assertIsInstance(connect.call_args.kwargs["context"], ssl.SSLContext)
            connection.set_tunnel.assert_not_called()

    def test_doctor_runs_all_green_in_universal_tun_mode_without_clash(self):
        snapshot = {
            "procs": ["v2rayn.exe", "xray.exe"],
            "claude_procs": 0,
            "tuns": [{"name": "sing-tun", "status": "Up", "desc": "sing-box tun"}],
            "ipv6": [{"name": "WLAN", "status": "Up", "ipv6": False}],
            "dns": [{"name": "WLAN", "status": "Up", "servers": ["1.1.1.1", "8.8.8.8"]}],
            "old_svc": "",
        }
        fw_ok = firewall.KillSwitchStatus(
            True, 2, True, [], ["WLAN"], [],
            verified_rule_ids=["r1", "r2"],
            claude_apps=[r"C:\Apps\Claude.exe"],
        )
        rtc_ok = hardening.WebRtcPolicyState(True, True, False, {}, False, True, True)
        exit_ok = doctor.ExitInfo(
            ip="198.51.100.9",
            country="United States",
            country_code="US",
            timezone="America/Los_Angeles",
            path=doctor.TUN_PATH,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            missing_yaml = Path(tmpdir) / "missing-clash.yaml"
            with (
                patch.object(doctor, "CLASH_VERGE_RUNTIME_YAML", missing_yaml),
                patch.object(doctor, "_probe_system_snapshot", return_value=snapshot),
                patch.object(doctor, "get_firewall_status", return_value=fw_ok),
                patch.object(doctor, "get_webrtc_policy_state", return_value=rtc_ok),
                patch.object(doctor, "get_current_windows_timezone", return_value="Pacific Standard Time"),
                patch.object(doctor, "_check_old_hklm_run", return_value=False),
                patch.object(doctor, "query_exit_info", return_value=exit_ok) as q_exit,
                patch.object(doctor, "_probe_ipv6_egress", return_value="") as q_v6,
            ):
                report = doctor.run_doctor(config.GuardConfig())

        q_exit.assert_called_once_with(None, doctor.TUN_PATH)
        q_v6.assert_called_once_with(None)
        self.assertEqual(report.overall, "green")
        self.assertTrue(report.tun_up)
        self.assertEqual(report.exit_info.path, doctor.TUN_PATH)
        self.assertFalse(any(i.id == "clash_config" for i in report.items))

    def test_monitored_exit_ip_drift_is_fail_red_alert(self):
        exit_info = doctor.ExitInfo(ip="203.0.113.8", country_code="JP", country="Japan", path=doctor.TUN_PATH)
        cfg = config.GuardConfig(monitored_probe_ip="198.51.100.9")
        item = doctor._check_exit_ip(exit_info, cfg)
        self.assertEqual(item.level, "FAIL")
        self.assertIn("漂移", item.summary)

    def test_conflict_detection_allows_single_proxy_suite_and_flags_multi_or_accelerator(self):
        self.assertEqual(doctor._check_conflicts({"flclash.exe"}, "", False).level, "PASS")
        self.assertEqual(doctor._check_conflicts({"v2rayn.exe", "xray.exe"}, "", False).level, "PASS")
        self.assertEqual(doctor._check_conflicts({"clash-verge.exe", "verge-mihomo.exe"}, "", False).level, "PASS")
        self.assertEqual(doctor._check_conflicts({"v2rayn.exe", "flclash.exe"}, "", False).level, "WARN")
        self.assertEqual(doctor._check_conflicts({"uu.exe", "flclash.exe"}, "", False).level, "WARN")

    def test_purity_uses_universal_tun_when_clash_probe_absent(self):
        with (
            patch.object(bridge, "check_probe_route", return_value="missing clash"),
            patch.object(bridge, "_fast_check_tun_up", return_value=(True, ["FlClash"])),
            patch.object(purity, "_fetch_ippure", return_value=({"ip": "198.51.100.9", "fraudScore": 5}, "")) as ip_score,
            patch.object(purity, "fetch_ip_info", return_value=({"ip": "198.51.100.9"}, "")) as ip_info,
        ):
            res = bridge.GuardBridge().check_ip_purity()
        self.assertTrue(res["ok"])
        ip_score.assert_called_once_with(None)
        ip_info.assert_called_once_with(None)

    def test_ui_passes_icon_to_webview_start(self):
        fake_window = MagicMock()
        fake_tray = Mock()
        with (
            patch.object(ui, "SystemTrayIcon", return_value=fake_tray),
            patch.object(ui.webview, "create_window", return_value=fake_window),
            patch.object(ui.webview, "start") as start_mock,
            patch.object(ui, "is_admin", return_value=False),
        ):
            app_ui = ui.GuardApp()
            app_ui.run()
        start_mock.assert_called_once()
        self.assertEqual(start_mock.call_args.kwargs["icon"], str(ui.ICON_FILE))
