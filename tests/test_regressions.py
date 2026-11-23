"""Regression tests for failed system changes and unknown diagnostic states."""

import io
import json
import shutil
import subprocess
import tempfile
import threading
import unittest
from contextlib import nullcontext, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import app
from guard import adapters, bridge, clash_config, config, doctor, firewall, hardening, net, purity, tray, ui


class RecoveryTests(unittest.TestCase):
    def test_blank_backup_does_not_write_adapters_timezone_or_policies(self):
        with (
            patch.object(adapters, "is_admin", return_value=True),
            patch.object(adapters, "load_backup", return_value=config.SystemBackup()),
            patch.object(adapters, "run_ps") as powershell,
            patch.object(hardening, "is_admin", return_value=True),
            patch.object(hardening, "load_backup", return_value=config.SystemBackup()),
            patch.object(hardening, "disable_killswitch", return_value=(True, "removed")),
            patch.object(hardening, "set_autostart_enabled", return_value=(True, "disabled")) as autostart,
            patch.object(hardening, "run_cmd") as command,
            patch.object(hardening, "_set_policy") as registry,
        ):
            self.assertTrue(all(step.ok for step in hardening.run_rescue()))
        powershell.assert_not_called()
        command.assert_not_called()
        registry.assert_not_called()
        autostart.assert_called_once_with(False)

    def test_restore_removes_only_verified_backups(self):
        backup = config.SystemBackup(
            dns_backup={"Missing": [], "Present": ["192.0.2.53"]},
            ipv6_disabled_adapters=["Missing", "Present"],
        )
        with (
            patch.object(adapters, "is_admin", return_value=True),
            patch.object(adapters, "load_backup", return_value=backup),
            patch.object(adapters, "save_backup"),
            patch.object(adapters, "_write_dns", side_effect=[OSError("unavailable"), None]),
            patch.object(adapters, "_write_ipv6", side_effect=[OSError("unavailable"), None]),
        ):
            self.assertFalse(adapters.restore_physical_dns()[0])
            self.assertFalse(adapters.restore_physical_ipv6()[0])
        self.assertEqual(backup.dns_backup, {"Missing": []})
        self.assertEqual(backup.ipv6_disabled_adapters, ["Missing"])

    def test_rescue_failure_visible_to_cli_and_gui(self):
        steps = [hardening.StepResult("Firewall", True, "ok"), hardening.StepResult("DNS", False, "missing adapter")]
        with (
            patch.object(app, "is_admin", return_value=True),
            patch.object(app, "run_rescue", return_value=steps),
            patch.object(app, "save_config") as save,
            redirect_stdout(io.StringIO()),
        ):
            self.assertNotEqual(app._cli_rescue(), 0)
            save.assert_not_called()
        with (
            patch.object(bridge, "is_admin", return_value=True),
            patch.object(bridge, "load_config", side_effect=config.GuardConfig),
            patch.object(bridge, "run_rescue", return_value=steps),
            patch.object(bridge.GuardBridge, "_run_doctor_unlocked"),
            patch.object(bridge, "save_config") as save,
        ):
            result = bridge.GuardBridge().run_rescue()
            self.assertFalse(result["ok"])
            self.assertIn("DNS", result["message"])
            save.assert_not_called()

    def test_webrtc_preserves_original_registry_value(self):
        key = next(iter(hardening._POLICIES))
        expected = [hardening.winreg.REG_SZ, "original"]
        registry = {key: expected}
        backup = config.SystemBackup()
        with (
            patch.object(hardening, "is_admin", return_value=True),
            patch.object(hardening, "load_backup", return_value=backup),
            patch.object(hardening, "save_backup"),
            patch.object(hardening, "_browser_installed", side_effect=lambda name: name == "chrome.exe"),
            patch.object(hardening, "_read_policy", side_effect=lambda *key: registry.get(key)),
            patch.object(hardening, "_set_policy", side_effect=lambda subkey, name, value: registry.update({(subkey, name): value})),
        ):
            self.assertTrue(hardening.enable_webrtc_policies()[0])
            self.assertNotEqual(registry[key], expected)
            self.assertTrue(hardening.clear_webrtc_policies()[0])
        self.assertEqual(registry[key], expected)
        self.assertFalse(backup.webrtc_previous)

    def test_legacy_webrtc_marks_unrecoverable_originals(self):
        with (
            patch.object(hardening, "is_admin", return_value=True),
            patch.object(hardening, "load_backup", return_value=config.SystemBackup(webrtc_modified=True)),
            patch.object(hardening, "_set_policy") as setter,
        ):
            self.assertFalse(hardening.clear_webrtc_policies()[0])
        setter.assert_not_called()

    def test_corrupt_backup_is_never_replaced_with_empty_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backup.json"
            path.write_text("{bad json", encoding="utf-8")
            with patch.object(config, "STATE_DIR", path.parent), patch.object(config, "BACKUP_FILE", path):
                with self.assertRaises(ValueError):
                    config.load_backup()
            self.assertEqual(path.read_text(encoding="utf-8"), "{bad json")


class FirewallAndProbeTests(unittest.TestCase):
    def test_rule_creation_failure_does_not_remove_previous_generation(self):
        status = firewall.KillSwitchStatus(
            False, 1, True, [], ["Ethernet"], [],
            verified_rule_ids=["old-v4"],
            missing_rule_specs=[("Anthropic IPv6", config.ANTHROPIC_CIDRS_V6, "Any")],
        )
        with (
            patch.object(firewall, "is_admin", return_value=True),
            patch.object(firewall, "get_status", return_value=status),
            patch.object(firewall, "run_ps", return_value=(1, "", "creation failed")) as create,
            patch.object(firewall, "_remove_rules", return_value=(0, "", "")) as cleanup,
        ):
            self.assertFalse(firewall.enable_killswitch()[0])
            self.assertNotIn("Remove-NetFirewallRule", create.call_args.args[0])
            self.assertIn("$_.Name -like", cleanup.call_args.args[0])

    def test_rule_repair_preserves_effective_old_rule_and_adds_only_missing_scope(self):
        rule = {
            "id": "old-v4", "enabled": "True", "direction": "Outbound", "action": "Block",
            "profile": "Any", "protocol": "Any", "primary_status": "OK", "enforcement": [1],
            "local": ["Any"], "remote": config.ANTHROPIC_CIDRS_V4, "interfaces": ["Ethernet"], "program": "Any",
        }
        duplicate = {**rule, "id": "stale-duplicate", "primary_status": "Inactive", "enforcement": [25]}
        new = {**rule, "id": "ClaudeGuard-test-1", "remote": config.ANTHROPIC_CIDRS_V6}

        def evaluate(rules):
            return firewall._evaluate_rules({
                "rules": rules, "profiles": [{"name": "Private", "enabled": True}], "network_categories": ["Private"],
            }, ["Ethernet"], [])

        preflight = evaluate([rule, duplicate])
        self.assertEqual(preflight.verified_rule_ids, ["old-v4"])
        self.assertEqual(preflight.missing_scopes, ["Anthropic IPv6"])
        after_write = evaluate([rule, duplicate, new])
        after_cleanup = evaluate([rule, new])
        events = Mock()
        events.read.side_effect = [preflight, after_write, after_cleanup]
        events.create.return_value = events.remove.return_value = (0, "", "")

        with (
            patch.object(firewall, "is_admin", return_value=True),
            patch.object(firewall, "uuid4", return_value=Mock(hex="test")),
            patch.object(firewall, "get_status", events.read),
            patch.object(firewall, "run_ps", events.create),
            patch.object(firewall, "_remove_rules", events.remove),
        ):
            self.assertTrue(firewall.enable_killswitch()[0])
        self.assertEqual([call[0] for call in events.mock_calls], ["read", "create", "read", "remove", "read"])
        command = events.create.call_args.args[0]
        self.assertEqual(command.count("New-NetFirewallRule"), 1)
        self.assertIn("Anthropic IPv6", command)
        self.assertNotIn("Anthropic IPv4", command)
        events.remove.assert_called_once_with("$_.Name -notin @('old-v4','ClaudeGuard-test-1')")

    def test_existing_verified_generation_is_not_rewritten(self):
        status = firewall.KillSwitchStatus(True, 2, True, [], ["Ethernet"], [], verified_rule_ids=["old-v4", "old-v6"])
        with (
            patch.object(firewall, "is_admin", return_value=True),
            patch.object(firewall, "get_physical_adapters", return_value=["Ethernet"]),
            patch.object(firewall, "get_status", return_value=status),
            patch.object(firewall, "run_ps") as create,
            patch.object(firewall, "_remove_rules") as cleanup,
        ):
            self.assertTrue(firewall.enable_killswitch()[0])
            create.assert_not_called()
            cleanup.assert_not_called()

    def test_firewall_rejects_missing_scope_or_wrong_interface(self):
        rule = {
            "id": "fixture-1", "name": "IPv4", "enabled": "True", "direction": "Outbound",
            "action": "Block", "profile": "Any", "protocol": "Any",
            "primary_status": "OK", "enforcement": [1],
            "local": ["Any"], "remote": config.ANTHROPIC_CIDRS_V4,
            "interfaces": ["Ethernet"], "program": "Any",
        }
        data = {"network_categories": ["Private"], "profiles": [{"name": "Private", "enabled": True}], "rules": [rule]}
        self.assertFalse(firewall._evaluate_rules(data, ["Ethernet"], []).active)
        data["rules"].append({**rule, "id": "fixture-2", "remote": config.ANTHROPIC_CIDRS_V6})
        self.assertTrue(firewall._evaluate_rules(data, ["Ethernet"], []).active)
        self.assertFalse(firewall._evaluate_rules(data, ["Wi-Fi"], []).active)
        data["rules"][0]["enforcement"] = [16]
        self.assertFalse(firewall._evaluate_rules(data, ["Ethernet"], []).active)

    def test_firewall_evaluates_cim_states_for_active_profiles(self):
        scope = {
            "id": "fixture", "enabled": "True", "direction": "Outbound", "action": "Block", "profile": "Any",
            "protocol": "Any", "primary_status": "OK", "local": ["Any"], "program": "Any",
            "interfaces": ["WLAN", "Ethernet"],
        }
        rules = [{**scope, "remote": addresses} for addresses in (config.ANTHROPIC_CIDRS_V4, config.ANTHROPIC_CIDRS_V6)]
        profiles = [{"name": name, "enabled": name != "Domain"} for name in ("Domain", "Private", "Public")]
        data = {"network_categories": ["Public", "Public"], "profiles": profiles, "rules": rules}
        for states, expected in (
            ([2, 5, 1], True),
            ([2, 5, 2, 1], False),
            ([2, 5], False),
            ([2, 5, 1, 16], False),
            ([2, 5, 19], False),
            ([25], False),
        ):
            with self.subTest(states=states):
                for rule in rules:
                    rule["primary_status"] = "OK"
                    rule["enforcement"] = states
                self.assertEqual(firewall._evaluate_rules(data, scope["interfaces"], []).active, expected)

        for states in ([19], [2, 5, 19], [5], [25]):
            with self.subTest(primary_status="Inactive", states=states):
                for rule in rules:
                    rule["primary_status"] = "Inactive"
                    rule["enforcement"] = states
                self.assertFalse(firewall._evaluate_rules(data, scope["interfaces"], []).active)

        for rule in rules:
            rule["primary_status"] = "OK"
            rule["enforcement"] = [2, 5, 1]
        profiles[2]["local_rules_allowed"] = False
        status = firewall._evaluate_rules(data, scope["interfaces"], [])
        self.assertFalse(status.active)
        self.assertEqual(status.local_rules_blocked_profiles, ["Public"])
        profiles[2]["local_rules_allowed"] = True
        data["network_categories"].append("DomainAuthenticated")
        status = firewall._evaluate_rules(data, scope["interfaces"], [])
        self.assertFalse(status.active)
        self.assertEqual(status.disabled_profiles, ["Domain"])

    def test_tun_dns_yaml_comments_cannot_simulate_valid_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clash.yaml"
            path.write_text("ipv6: false\ntun: {enable: false, strict-route: true}\ndns: {enable: true}\n# Claude-Lock\n", encoding="utf-8")
            with patch.object(doctor, "CLASH_VERGE_RUNTIME_YAML", path):
                item = doctor._audit_clash_verge_config()
                self.assertEqual(item.level, "WARN")
                self.assertIn("TUN", item.detail)
                self.assertNotIn("Claude-Lock", item.detail)

    def test_script_wrapper_and_audit_preserve_vm_proxy(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is required to check the generated Clash configuration")
        script = bridge.OVERRIDE_SCRIPT_PATH.read_text(encoding="utf-8")
        source = """
const vm = require("node:vm");
const baseInput = {
  mode: "rule", "allow-lan": true, "mixed-port": 7897,
  proxies: [{name: "test", type: "vless"}, {name: "direct alias", type: "direct"}],
  "proxy-groups": [{name: "Daily", type: "select", proxies: ["test", "DIRECT"]}],
  rules: ["MATCH,Daily"],
};
const aiInput = {
  mode: "rule", "allow-lan": true, "mixed-port": 7897,
  proxies: [{name: "us-1", type: "vless"}],
  "proxy-groups": [
    {name: "🚀节点选择", type: "select", proxies: ["us-1", "DIRECT"]},
    {name: "🤖AI网站", type: "select", proxies: ["us-1", "DIRECT"]},
  ],
  rules: ["MATCH,🚀节点选择"],
};
const script = """ + json.dumps(script) + r"""
const wrapped = script + "\nJSON.stringify({base: main(main(baseInput), 'test'), ai: main(main(aiInput), 'ai')})";
console.log(vm.runInNewContext(wrapped, { baseInput, aiInput }));
"""
        proc = subprocess.run([node, "-"], input=source, capture_output=True, check=True, encoding="utf-8")
        res = json.loads(proc.stdout)
        generated = res["base"]
        ai_generated = res["ai"]

        self.assertTrue(generated["allow-lan"])
        self.assertEqual(generated["mixed-port"], 7897)
        self.assertNotIn("tun", generated)
        self.assertEqual(generated["rules"][-1], "MATCH,Daily")
        self.assertIn("PROCESS-NAME,claude.exe,Daily", generated["rules"])
        self.assertIn("DOMAIN-SUFFIX,challenges.cloudflare.com,Daily", generated["rules"])
        self.assertLess(
            generated["rules"].index("IP-CIDR,127.0.0.0/8,DIRECT,no-resolve"),
            generated["rules"].index("PROCESS-NAME,claude.exe,Daily"),
        )
        self.assertEqual(len(generated["proxy-groups"]), 1)
        self.assertIn("PROCESS-NAME,claude.exe,🤖AI网站", ai_generated["rules"])
        self.assertIn("DOMAIN-SUFFIX,claude.ai,🤖AI网站", ai_generated["rules"])

        audit_cfg = {
            "mode": "rule",
            "ipv6": False,
            "tun": {"enable": True, "auto-route": True, "strict-route": True},
            "dns": {"enable": True, "ipv6": False},
            "listeners": [{"name": clash_config.PROBE_INBOUND, "type": "http", "listen": "127.0.0.1", "port": clash_config.PROBE_PORT, "proxy": clash_config.PROBE_GROUP, "users": []}],
            "proxies": [{"name": "test", "type": "vless"}],
            "proxy-groups": [{"name": clash_config.PROBE_GROUP, "type": "select", "empty-fallback": "REJECT", "default-selected": "REJECT", "proxies": ["REJECT", "test"]}],
        }
        self.assertEqual(clash_config.subscription_probe_issues(audit_cfg), [])
        self.assertEqual(clash_config.tun_dns_issues(audit_cfg), [])

        with (
            patch.object(doctor, "read_config", return_value=audit_cfg),
            patch.object(doctor, "verify_proxy_listener", return_value=True) as verify,
        ):
            self.assertEqual(doctor._audit_clash_verge_config().level, "PASS")
            verify.assert_called_once_with(clash_config.PROBE_PORT)

            for invalid in ("DIRECT", "direct alias", "Daily", "missing"):
                with self.subTest(invalid=invalid):
                    audit_cfg["proxy-groups"][0]["proxies"] = ["REJECT", invalid]
                    verify.reset_mock()
                    self.assertEqual(doctor._audit_clash_verge_config().level, "WARN")
                    verify.assert_not_called()

            audit_cfg["proxy-groups"][0]["proxies"] = ["REJECT", "test"]
            audit_cfg["listeners"][0]["listen"] = "0.0.0.0"
            self.assertEqual(doctor._audit_clash_verge_config().level, "WARN")
            verify.assert_not_called()

            audit_cfg["listeners"][0]["listen"] = "127.0.0.1"
            verify.return_value = False
            self.assertEqual(doctor._audit_clash_verge_config().level, "WARN")

    def test_subscription_purity_uses_only_verified_local_probe_port(self):
        port = clash_config.PROBE_PORT
        with (
            patch.object(bridge, "check_probe_route", return_value=""),
            patch.object(purity, "_fetch_ippure", return_value=({"ip": "192.0.2.5", "fraudScore": 2}, "")) as ip_score,
            patch.object(purity, "fetch_ip_info", return_value=({"ip": "192.0.2.5"}, "")) as ip_info,
        ):
            result = bridge.GuardBridge().check_ip_purity()
            self.assertTrue(result["ok"])
            self.assertEqual(result["purity"]["ip"], "192.0.2.5")
            self.assertEqual(result["purity"]["risk_level"], "low")
            ip_score.assert_called_once_with(port)
            ip_info.assert_called_once_with(port)

    def test_https_transport_connects_only_to_configured_proxy(self):
        with patch.object(net.http.client, "HTTPSConnection") as connect:
            connection = connect.return_value
            response = connection.getresponse.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = b'{"ip":"192.0.2.5"}'
            self.assertEqual(net.fetch_ip_info(7897)[0]["ip"], "192.0.2.5")
            connect.assert_called_once_with("127.0.0.1", 7897, timeout=6.0, context=net.build_ssl_context())
            connection.set_tunnel.assert_called_once_with("ipapi.co", 443)
            self.assertEqual(connection.request.call_args.args[:2], ("GET", "/json/"))

    def test_unverified_report_cannot_set_monitor_baseline(self):
        stale = doctor.DoctorReport(
            checked_at="12:00:00", overall="red", exit_info=doctor.ExitInfo(ip="192.0.2.5"),
            tun_up=False, mihomo_running=False,
        )
        with (
            patch.object(bridge, "load_config", side_effect=config.GuardConfig),
            patch.object(bridge.GuardBridge, "_run_doctor_unlocked", return_value=stale),
            patch.object(bridge, "save_config") as save,
        ):
            self.assertFalse(bridge.GuardBridge().toggle_ip_monitor()["ok"])
        save.assert_not_called()

    def test_stop_monitoring_persists_and_is_idempotent_after_scan_failure(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(config, "STATE_DIR", Path(directory)),
            patch.object(config, "CONFIG_FILE", Path(directory) / "config.json"),
            patch.object(bridge, "system_change_lock", return_value=nullcontext(True)),
            patch.object(bridge.GuardBridge, "_run_doctor_unlocked", side_effect=RuntimeError("Clash unavailable")) as scan,
        ):
            config.save_config(config.GuardConfig(monitored_probe_ip="192.0.2.5"))
            guard = bridge.GuardBridge()
            result = guard.toggle_ip_monitor(False)
            self.assertTrue(result["ok"])
            self.assertIn("巡检未完成", result["message"])
            self.assertIsNone(result["report"])
            self.assertEqual(result["config"]["monitored_probe_ip"], "")
            saved = config.load_config()
            self.assertEqual(saved.monitored_probe_ip, "")
            self.assertTrue(guard.toggle_ip_monitor(False)["ok"])
            scan.assert_called_once()

    def test_stop_monitoring_reports_write_failure_and_preserves_state(self):
        previous = config.GuardConfig(monitored_probe_ip="192.0.2.5")
        with (
            patch.object(bridge, "load_config", return_value=previous),
            patch.object(bridge, "system_change_lock", return_value=nullcontext(True)),
            patch.object(bridge, "save_config", side_effect=PermissionError("read only")),
            patch.object(bridge.GuardBridge, "_run_doctor_unlocked") as scan,
        ):
            result = bridge.GuardBridge().toggle_ip_monitor(False)
            self.assertFalse(result["ok"])
            self.assertEqual(result["config"]["monitored_probe_ip"], "192.0.2.5")
            self.assertEqual(previous.monitored_probe_ip, "192.0.2.5")
            scan.assert_not_called()

    def test_empty_ipv6_and_missing_probe_data_are_unknown(self):
        item, disabled = doctor._evaluate_ipv6([], None)
        self.assertEqual(item.level, "UNKNOWN")
        self.assertIsNone(disabled)
        report = purity.evaluate_purity(None, None, ["timeout"], 100)
        self.assertEqual(report.risk_level, "unknown")
        self.assertEqual(report.ip, "")


class ProtectionLogicTests(unittest.TestCase):
    def test_run_steps_surfaces_unexpected_exceptions(self):
        def explode():
            raise RuntimeError("ctypes boom")

        steps = hardening.run_steps([("Step", explode)])
        self.assertFalse(steps[0].ok)
        self.assertIn("RuntimeError", steps[0].message)

    def test_firewall_normalizes_single_rule_json(self):
        rule = {
            "id": "one", "name": "IPv4", "enabled": "True", "direction": "Outbound",
            "action": "Block", "profile": "Any", "protocol": "Any", "primary_status": "OK",
            "enforcement": 1, "local": "Any", "remote": config.ANTHROPIC_CIDRS_V4,
            "interfaces": "Ethernet", "program": "Any",
        }
        data = {"network_categories": "Private", "profiles": {"name": "Private", "enabled": True}, "rules": rule}
        status = firewall._evaluate_rules(data, ["Ethernet"], [])
        self.assertEqual(status.rule_count, 1)
        self.assertFalse(status.active)
        data["rules"] = [rule, {**rule, "id": "two", "remote": config.ANTHROPIC_CIDRS_V6}]
        self.assertTrue(firewall._evaluate_rules(data, ["Ethernet"], []).active)

    def test_ipv6_requires_an_observed_ipv4_connection_to_pass(self):
        states = [{"name": "WLAN", "status": "Up", "ipv6": False}]
        item, disabled = doctor._evaluate_ipv6(states, "")
        self.assertEqual(item.level, "PASS")
        self.assertTrue(disabled)
        self.assertEqual(doctor._evaluate_ipv6(states, None)[0].level, "UNKNOWN")
        self.assertEqual(doctor._evaluate_ipv6(states, "2001:db8::1")[0].level, "WARN")

    def test_ipv6_probe_distinguishes_valid_ipv4_ipv6_and_unreachable(self):
        for result, expected in (
            (({"ip": "192.0.2.10"}, ""), ""),
            (({"ip": "2001:db8::1"}, ""), "2001:db8::1"),
            ((None, "timeout"), None),
            (({"ip": "invalid"}, ""), None),
        ):
            with (
                self.subTest(expected=expected),
                patch.object(doctor, "fetch_json", return_value=result),
            ):
                self.assertEqual(doctor._probe_ipv6_egress(7897), expected)

    def test_action_exception_becomes_a_failed_bridge_result(self):
        with (
            patch.object(bridge, "is_admin", return_value=True),
            patch.object(bridge, "load_config", side_effect=config.GuardConfig),
            patch.object(bridge, "run_rescue", side_effect=KeyError("bad snapshot")),
            patch.object(bridge.GuardBridge, "_run_doctor_unlocked") as refresh,
        ):
            result = bridge.GuardBridge().run_rescue()
        self.assertFalse(result["ok"])
        self.assertIn("KeyError", result["message"])
        refresh.assert_called_once()

    def test_firewall_bad_payload_remains_unknown(self):
        with (
            patch.object(firewall, "get_physical_adapters", return_value=["Ethernet"]),
            patch.object(firewall, "run_ps_json", return_value=(True, {"rules": "bad"}, "")),
            patch.object(firewall, "discover_claude_executables", return_value=[]),
        ):
            self.assertEqual(doctor._check_killswitch(firewall.get_status()).level, "UNKNOWN")

    def test_webrtc_requires_firefox_only_when_installed(self):
        base = dict(chrome_ok=True, edge_ok=True, firefox_ok=False, details={})
        self.assertTrue(doctor._check_webrtc(hardening.WebRtcPolicyState(**base, firefox_required=False))[1])
        self.assertFalse(doctor._check_webrtc(hardening.WebRtcPolicyState(**base, firefox_required=True))[1])

    def test_webrtc_reads_firefox_json_value(self):
        self.assertTrue(hardening._firefox_locked('{"Value": true, "Status": "locked"}'))
        self.assertTrue(hardening._firefox_locked('{"Status":"LOCKED","Value":true}'))
        self.assertFalse(hardening._firefox_locked('{"Value": false}'))
        self.assertFalse(hardening._firefox_locked(""))

    def test_firefox_only_does_not_require_chromium_policy(self):
        firefox = hardening.WebRtcPolicyState(False, False, True, {}, True, False, False)
        self.assertEqual(doctor._check_webrtc(firefox)[0].level, "PASS")
        original = [hardening.winreg.REG_MULTI_SZ, ['{"custom":{"Value":12}}']]
        applied = hardening._firefox_preferences(hardening._applied_policy(hardening._FIREFOX_POLICY, original))
        self.assertEqual(applied["custom"], {"Value": 12})
        self.assertTrue(hardening._firefox_locked(applied["media.peerconnection.ice.no_host"]))

    def test_ipv6_write_failure_cleans_backup_only_after_verifying_no_change(self):
        record = {"guid": "nic-id", "name": "WLAN", "value": True}
        for readback, remaining in (([record], []), ([], ["nic-id"])):
            backup = config.SystemBackup()
            with (
                self.subTest(remaining=remaining),
                patch.object(adapters, "is_admin", return_value=True),
                patch.object(adapters, "load_backup", return_value=backup),
                patch.object(adapters, "save_backup"),
                patch.object(adapters, "_read_adapters", side_effect=[[record], readback]),
                patch.object(adapters, "_write_ipv6", side_effect=OSError("simulated failure")),
            ):
                self.assertFalse(adapters.disable_physical_ipv6()[0])
            self.assertEqual(backup.ipv6_disabled_adapters, remaining)

    def test_killswitch_without_claude_apps_is_warn(self):
        status = firewall.KillSwitchStatus(True, 2, True, [], ["Ethernet"], [], claude_apps=[])
        self.assertEqual(doctor._check_killswitch(status).level, "WARN")

class LifecycleTests(unittest.TestCase):
    def test_concurrent_file_saves_use_distinct_temporary_paths(self):
        replacements = []
        barrier = threading.Barrier(2, timeout=2)
        replace = Path.replace

        def keep_both_temporary_paths(source, destination):
            if source not in replacements:
                replacements.append(source)
                barrier.wait()
            replace(source, destination)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            with (
                patch.object(config, "STATE_DIR", path.parent),
                patch.object(config, "CONFIG_FILE", path),
                patch.object(Path, "replace", keep_both_temporary_paths),
            ):
                from concurrent.futures import ThreadPoolExecutor

                with ThreadPoolExecutor(max_workers=2) as pool:
                    baseline = ("192.0.2.1", "192.0.2.2")
                    results = pool.map(config.save_config, [config.GuardConfig(monitored_probe_ip=ip) for ip in baseline])
                    list(results)
                self.assertIn(config.load_config().monitored_probe_ip, baseline)
            self.assertEqual(len(set(replacements)), 2)

    def test_system_change_lock_excludes_other_writers(self):
        from guard import sysutil

        with patch.object(sysutil, "SYSTEM_CHANGE_MUTEX", "Local\\ClaudeGuard_TestSystemWriter"):
            with sysutil.system_change_lock() as first:
                self.assertTrue(first)
                with sysutil.system_change_lock() as second:
                    self.assertFalse(second)
            with sysutil.system_change_lock() as third:
                self.assertTrue(third)

    def test_tray_exit_does_not_join_itself(self):
        app_ui = object.__new__(ui.GuardApp)
        app_ui._force_quit = False
        app_ui._bridge = Mock()
        app_ui._window = Mock()
        app_ui._tray = tray.SystemTrayIcon("Test", lambda: None, [("Exit", app_ui.quit_app)])
        app_ui._tray._hwnd = 1
        worker = threading.Thread(target=lambda: app_ui._tray._show_popup_menu(1))
        app_ui._tray._thread = worker
        with (
            patch.object(tray.user32, "PostMessageW", return_value=True),
            patch.object(tray.user32, "TrackPopupMenu", return_value=tray.FIRST_MENU_COMMAND),
        ):
            worker.start()
            worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        app_ui._window.destroy.assert_called_once()

    def test_tray_native_popup_marks_disabled_and_dispatches_selected_entry(self):
        selected = Mock()
        other = Mock()
        icon = tray.SystemTrayIcon("Test", lambda: None, [
            ("Open", other), (None, None), ("Needs administrator", None), ("Scan", selected),
        ])
        menu_state = tray.user32.GetMenuState
        menu_state.argtypes = [tray.wintypes.HMENU, tray.wintypes.UINT, tray.wintypes.UINT]
        menu_state.restype = tray.wintypes.UINT

        def pick(menu, flags, *args):
            self.assertEqual(flags & (tray.TPM_RETURNCMD | tray.TPM_NONOTIFY), tray.TPM_RETURNCMD | tray.TPM_NONOTIFY)
            self.assertTrue(menu_state(menu, tray.FIRST_MENU_COMMAND + 2, 0) & tray.MF_GRAYED)
            self.assertFalse(menu_state(menu, tray.FIRST_MENU_COMMAND + 3, 0) & tray.MF_GRAYED)
            return tray.FIRST_MENU_COMMAND + 3

        with (
            patch.object(tray.user32, "PostMessageW", return_value=True),
            patch.object(tray.user32, "TrackPopupMenu", side_effect=pick) as track,
        ):
            icon._show_popup_menu(1)
            selected.assert_called_once()
            other.assert_not_called()
            track.side_effect = None
            for command in (0, tray.FIRST_MENU_COMMAND + 2):
                track.return_value = command
                icon._show_popup_menu(1)
            selected.assert_called_once()
            other.assert_not_called()

    def test_tray_privileged_entries_are_disabled_without_admin(self):
        app_ui = object.__new__(ui.GuardApp)
        app_ui._bridge = Mock()
        app_ui._tray_action_async = Mock(side_effect=lambda label, action: action())
        regular = app_ui._tray_menu_items(False)
        privileged = app_ui._tray_menu_items(True)
        for index in (3, 4, 5):
            self.assertIn("需管理员权限", regular[index][0])
            self.assertIsNone(regular[index][1])
            privileged[index][1]()
        regular[1][1]()
        app_ui._bridge.enable_all_protection.assert_called_once_with()
        app_ui._bridge.toggle_killswitch.assert_called_once_with(False)
        app_ui._bridge.run_rescue.assert_called_once_with()
        app_ui._bridge.run_doctor.assert_called_once_with()

    def test_tray_worker_reports_failures_and_recovers(self):
        app_ui = object.__new__(ui.GuardApp)
        app_ui._force_quit = False
        app_ui._tray_action_lock = threading.Lock()
        app_ui._bridge = Mock()
        app_ui._notify_tray = Mock()
        app_ui._push_state_to_web = Mock()
        access_denied = {"ok": False, "report": None, "message": "Access denied"}
        result = {"ok": True, "report": None, "message": "Scan complete"}
        action = Mock(side_effect=[access_denied, RuntimeError("scan error"), result])
        with patch.object(ui.threading, "Thread", side_effect=lambda *, target, **kwargs: Mock(start=target)) as worker:
            with app_ui._tray_action_lock:
                app_ui._tray_action_async("Scan", action)
            worker.assert_not_called()
            self.assertEqual(app_ui._notify_tray.call_args.args[-1], "warn")

            app_ui._tray_action_async("Scan", action)
            self.assertEqual(app_ui._notify_tray.call_args.args[-2:], ("Access denied", "error"))
            self.assertEqual(app_ui._push_state_to_web.call_args.args[0], {**access_denied, "tray_action": True})
            app_ui._tray_action_async("Scan", action)
            self.assertEqual(app_ui._notify_tray.call_args.args[-1], "error")
            app_ui._bridge._append_log.assert_called_once()
            app_ui._tray_action_async("Scan", action)
            self.assertEqual(app_ui._notify_tray.call_args.args[-2:], ("Scan complete", "info"))
            self.assertEqual(app_ui._push_state_to_web.call_args.args[0], {**result, "tray_action": True})
            self.assertFalse(app_ui._tray_action_lock.locked())

    def test_frozen_exe_paths_and_relaunch_omit_script_arg(self):
        from guard import sysutil

        with (
            patch.object(sysutil.sys, "frozen", True, create=True),
            patch.object(sysutil.sys, "_MEIPASS", r"C:\Temp\_MEI123", create=True),
            patch.object(sysutil.sys, "executable", r"C:\Apps\ClaudeGuard.exe"),
            patch.object(sysutil.sys, "argv", [r"C:\Apps\ClaudeGuard.exe", "--minimized"]),
            patch.object(sysutil.ctypes.windll.shell32, "ShellExecuteW", return_value=42) as shell_exec,
        ):
            self.assertEqual(sysutil.get_bundle_root(), Path(r"C:\Temp\_MEI123"))
            self.assertTrue(sysutil.relaunch_as_admin(r"C:\Ignored\app.py", extra_args=["--handoff"]))
            args = shell_exec.call_args.args
            self.assertEqual(args[1], "runas")
            self.assertEqual(args[2], r"C:\Apps\ClaudeGuard.exe")
            self.assertEqual(args[3], '"--minimized" "--handoff"')
            self.assertEqual(args[4], r"C:\Apps")

    def test_open_author_page_uses_allowlisted_douyin_url(self):
        instance = object.__new__(bridge.GuardBridge)
        with patch.object(bridge.webbrowser, "open", return_value=True) as mock_open:
            res = instance.open_author_page()
        self.assertTrue(res["ok"])
        mock_open.assert_called_once_with(bridge.AUTHOR_DOUYIN_URL, new=2)
        self.assertTrue(bridge.AUTHOR_DOUYIN_URL.startswith("https://www.douyin.com/user/"))
