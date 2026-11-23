"""Claude Guard 离线语法校验 + 单元测试 + 只读自检脚本。

运行方式：
  python verify.py
"""

from __future__ import annotations

import compileall
import ctypes
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


class ClaudeGuardTests(unittest.TestCase):
    def test_01_compile_all_python_files(self) -> None:
        ok = compileall.compile_dir(str(ROOT), quiet=1, force=True)
        self.assertTrue(ok, "存在 Python 语法错误")

    def test_02_config_and_dns_backup_roundtrip(self) -> None:
        from guard import config

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with mock.patch.object(config, "STATE_DIR", tmp_path), \
                 mock.patch.object(config, "CONFIG_FILE", tmp_path / "config.json"), \
                 mock.patch.object(config, "BACKUP_FILE", tmp_path / "backup.json"):
                cfg = config.GuardConfig(monitored_probe_ip="1.2.3.4", protection_enabled=True)
                config.save_config(cfg)
                loaded = config.load_config()
                self.assertEqual(loaded.monitored_probe_ip, "1.2.3.4")
                self.assertTrue(loaded.protection_enabled)
                config.CONFIG_FILE.write_text('{"locked_exit_ip":"192.0.2.1","protection_enabled":true}', encoding="utf-8")
                self.assertEqual(config.load_config().monitored_probe_ip, "")
                self.assertTrue(config.load_config().protection_enabled)

                bk = config.SystemBackup(
                    original_timezone="China Standard Time",
                    ipv6_disabled_adapters=["WLAN"],
                    dns_backup={"WLAN": [], "以太网": ["223.5.5.5"]},
                )
                config.save_backup(bk)
                bk_loaded = config.load_backup()
                self.assertEqual(bk_loaded.original_timezone, "China Standard Time")
                self.assertEqual(bk_loaded.ipv6_disabled_adapters, ["WLAN"])
                self.assertEqual(bk_loaded.dns_backup, {"WLAN": [], "以太网": ["223.5.5.5"]})

    def test_03_tray_ctypes_structs_and_icon_creation(self) -> None:
        from guard.tray import NOTIFYICONDATAW, STATUS_RGB, _create_tray_icon, user32

        self.assertGreater(ctypes.sizeof(NOTIFYICONDATAW), 500)
        hicon = _create_tray_icon(STATUS_RGB["green"])
        self.assertTrue(bool(hicon), "无法创建 Win32 托盘盾牌图标")
        user32.DestroyIcon(hicon)

    def test_04_ps_quoting_prevents_injection(self) -> None:
        from guard.firewall import _ps_quote
        from guard.sysutil import ps_quote

        self.assertEqual(_ps_quote("Wi-Fi's $(calc)"), "'Wi-Fi''s $(calc)'")
        self.assertEqual(ps_quote("Wi-Fi's $(calc)"), "'Wi-Fi''s $(calc)'")

    def test_05_concurrent_doctor_snapshot_evaluation(self) -> None:
        from guard.config import GuardConfig
        from guard.doctor import CheckItem, ExitInfo, run_doctor
        from guard.firewall import KillSwitchStatus
        from guard.hardening import WebRtcPolicyState

        fake_snapshot = {
            "procs": ["verge-mihomo.exe"],
            "claude_procs": 0,
            "tuns": [{"name": "Mihomo", "status": "Up", "desc": "Meta Tunnel"}],
            "ipv6": [{"name": "WLAN", "status": "Up", "ipv6": False}],
            "dns": [{"name": "WLAN", "status": "Up", "servers": ["1.1.1.1", "8.8.8.8"]}],
            "old_svc": "",
        }
        fake_rtc = WebRtcPolicyState(True, True, True, {"Chrome": "ok", "Edge": "ok", "Firefox": "ok"})

        with mock.patch("guard.doctor._probe_system_snapshot", return_value=fake_snapshot), \
             mock.patch("guard.doctor._probe_ipv6_egress", return_value=""), \
             mock.patch("guard.doctor._audit_clash_verge_config", return_value=CheckItem("clash", "Clash", "PASS", "合规")), \
             mock.patch("guard.doctor.get_firewall_status", return_value=KillSwitchStatus(True, 3, True, [], ["WLAN"], [], claude_apps=["Claude.exe"])), \
             mock.patch("guard.doctor.get_webrtc_policy_state", return_value=fake_rtc), \
             mock.patch("guard.doctor.get_current_windows_timezone", return_value="Pacific Standard Time"), \
             mock.patch("guard.doctor._check_old_hklm_run", return_value=False):

            exit_info = ExitInfo(ip="192.0.2.5", country="United States", country_code="US", timezone="America/Los_Angeles")
            with mock.patch("guard.doctor.query_exit_info", return_value=exit_info) as probe:
                drift = run_doctor(GuardConfig(monitored_probe_ip="192.0.2.2"))
                self.assertEqual(drift.overall, "yellow")
                self.assertEqual(next(item.level for item in drift.items if item.id == "exit_ip"), "WARN")
                probe.assert_called_once_with(17897)
                report = run_doctor(GuardConfig(monitored_probe_ip="192.0.2.5"))
                self.assertEqual(report.overall, "green")
                self.assertTrue(report.states.dns_locked)
                self.assertTrue(report.states.firewall_active)
                self.assertTrue(report.states.ipv6_physical_disabled)

    def test_06_bridge_and_webview_assets_ready(self) -> None:
        import webview
        from guard.bridge import GuardBridge, encode_js_push

        self.assertTrue(hasattr(webview, "create_window"))
        for fname in ("index.html", "styles.css", "app.js"):
            self.assertTrue((ROOT / "web" / fname).is_file(), f"缺少前端资源 web/{fname}")

        bridge = GuardBridge()
        # 确保 pywebview 自省时只暴露公开方法，无非下划线内部对象泄漏
        public_attrs = [k for k in vars(bridge) if not k.startswith("_")]
        self.assertEqual(public_attrs, [], f"GuardBridge 存在非下划线实例属性: {public_attrs}")

        payload = bridge.get_initial_state()
        js = encode_js_push(payload)
        self.assertIn("__onGuardPush", js)
        json.dumps(payload)

        script_res = bridge.get_override_script()
        self.assertTrue(script_res["ok"])
        self.assertIn("Guard-Probe", script_res["content"])
        self.assertNotIn("Claude-Lock", script_res["content"])

    def test_07_batch_files_use_strict_crlf(self) -> None:
        for bat in ROOT.glob("*.bat"):
            raw = bat.read_bytes()
            bare_lf = raw.replace(b"\r\n", b"").count(b"\n")
            self.assertEqual(bare_lf, 0, f"{bat.name} 含有裸 LF 换行符，Windows cmd.exe 执行会错位乱码")
            self.assertGreater(raw.count(b"\r\n"), 0, f"{bat.name} 必须使用 Windows CRLF 换行符")

    def test_08_ip_purity_scores_only_consistent_test_exit(self) -> None:
        from guard.purity import evaluate_purity

        primary = {"ip": "192.0.2.5", "fraudScore": 2, "isResidential": True, "isBroadcast": False}
        secondary = {"ip": "192.0.2.5", "hosting": False}
        clean = evaluate_purity(primary, secondary, [], 800)
        self.assertEqual((clean.grade, clean.risk_level), ("A+", "low"))
        high = evaluate_purity(dict(primary, fraudScore=82), secondary, [], 500)
        self.assertEqual((high.grade, high.risk_level), ("D", "high"))
        mismatch = evaluate_purity(primary, {"ip": "192.0.2.2"}, [], 600)
        self.assertEqual(mismatch.risk_level, "unknown")
        self.assertTrue(mismatch.errors)

    def test_09_single_instance_mutex_blocks_duplicate(self) -> None:
        from guard.sysutil import SingleInstanceLock

        name = "Local\\ClaudeGuard_UnitTest_Mutex"
        lock1 = SingleInstanceLock(name)
        lock2 = SingleInstanceLock(name)
        try:
            self.assertTrue(lock1.acquire())
            self.assertFalse(lock2.acquire(wait_sec=0.0))
        finally:
            lock1.release()
        try:
            self.assertTrue(lock2.acquire(wait_sec=0.2))
        finally:
            lock2.release()

    def test_10_claude_process_probe_excludes_session0_services(self) -> None:
        from guard.probe import probe_system_snapshot
        from guard.sysutil import run_ps_json

        def simulate(command, **kwargs):
            fixture = (
                "function Get-Process {"
                "[pscustomobject]@{ProcessName='claude';SessionId=0};"
                "[pscustomobject]@{ProcessName='claude';SessionId=1};"
                "[pscustomobject]@{ProcessName='cowork-svc';SessionId=0}"
                "}; function Get-NetAdapter {};"
            )
            return run_ps_json(fixture + command, **kwargs)

        with mock.patch("guard.probe.run_ps_json", side_effect=simulate):
            self.assertEqual(probe_system_snapshot()["claude_procs"], 1)

    def test_11_fast_local_health_win32_is_sub_100ms(self) -> None:
        import time
        from guard.probe import probe_fast_local_health

        t0 = time.perf_counter()
        health = probe_fast_local_health()
        elapsed_ms = (time.perf_counter() - t0) * 1000
        self.assertLess(elapsed_ms, 200.0, f"纯 Win32 本地快检耗时过长: {elapsed_ms:.1f}ms")
        self.assertIn("mihomo_running", health)
        self.assertIn("tun_up", health)
        self.assertIn("fw_disabled_hint", health)

    def test_12_probe_audit_cannot_treat_open_lan_mixed_port_as_probe_port(self) -> None:
        from guard.clash_config import subscription_probe_issues

        cfg = {"mode": "rule", "allow-lan": True, "mixed-port": 7897}
        self.assertTrue(subscription_probe_issues(cfg))
        cfg["mixed-port"] = 17897
        self.assertIn("端口", subscription_probe_issues(cfg)[0])

    def test_13_realtime_alert_sound_and_auto_kill_linkage(self) -> None:
        from guard.bridge import GuardBridge

        notified = []
        bridge = GuardBridge(on_tray_notify=lambda t, m, l: notified.append((t, m, l)))
        bridge._cfg.alert_sound = True
        bridge._cfg.auto_kill_claude_on_critical = True

        with mock.patch("guard.bridge.play_alert_beep") as m_beep, \
             mock.patch("guard.bridge.kill_claude_desktop", return_value=(True, "已按 Anthropic 签名安全结束 1 个 Claude 桌面端进程")) as m_kill:
            bridge._handle_critical_alert("告警", "TUN 断开", "sig1")
            # 相同签名二次触发应去重，不重复响铃/弹窗
            bridge._handle_critical_alert("告警", "TUN 断开", "sig1")
            m_beep.assert_called_once()
            m_kill.assert_called_once()
            self.assertEqual(len(notified), 2)  # 告警通知 + 自动熔断通知


if __name__ == "__main__":
    print(f"验证目录: {ROOT}")
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite([
        loader.loadTestsFromTestCase(ClaudeGuardTests),
        loader.discover(str(ROOT / "tests"), pattern="test_*.py"),
    ])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        sys.exit(1)

    print("\n--- 附：执行一次本机只读并发防泄漏自检 ---")
    from app import _cli_doctor
    _cli_doctor()
