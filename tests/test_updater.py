import hashlib
import io
import json
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from guard import bridge, tray, updater


class FakeResponse:
    def __init__(self, payload: bytes, *, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self._buf = io.BytesIO(payload)
        self.status = status
        self._headers = {k.lower(): v for k, v in (headers or {}).items()}

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self._headers.get(name.lower(), default)

    def close(self) -> None:
        self._buf.close()


class UpdaterTests(unittest.TestCase):
    def test_version_parsing_and_comparison(self):
        self.assertEqual(updater.parse_version("v1.1.4"), (1, 1, 4))
        self.assertEqual(updater.parse_version("V2.10.3-beta.1"), (2, 10, 3))
        self.assertTrue(updater.is_newer_version("v1.2.0", "1.1.9"))
        self.assertTrue(updater.is_newer_version("1.10.0", "1.2.0"))
        self.assertTrue(updater.is_newer_version("1.1.4.1", "1.1.4"))
        self.assertFalse(updater.is_newer_version("1.1.4", "1.1.4"))
        self.assertFalse(updater.is_newer_version("1.1.3", "1.1.4"))

    def test_allowed_update_urls(self):
        self.assertTrue(updater.is_allowed_update_url("https://github.com/Octy-10/ClaudeGuard/releases/latest"))
        self.assertTrue(
            updater.is_allowed_update_url("https://objects.githubusercontent.com/github-production-release-asset-2e65be/a.exe")
        )
        for bad in (
            "",
            "http://github.com/Octy-10/ClaudeGuard",
            "https://evilgithub.com/a.exe",
            "https://github.com.evil.com/a.exe",
            "https://githubusercontent.com/a.exe",
            "https://github.com@evil.com/a.exe",
            "https://github.com:8443/a.exe",
            "https://127.0.0.1/a.exe",
            "file:///C:/a.exe",
        ):
            self.assertFalse(updater.is_allowed_update_url(bad), f"Expected rejection for {bad}")

    def test_check_for_update_states_and_validation(self):
        valid_sha = "a" * 64
        asset_url = "https://github.com/Octy-10/ClaudeGuard/releases/download/v1.2.0/ClaudeGuard.exe"

        def mock_fetch(manifest: dict):
            raw = json.dumps(manifest).encode("utf-8")
            return patch.object(
                updater,
                "_open_https",
                return_value=(Mock(), FakeResponse(raw)),
            )

        with patch.object(updater, "detect_local_proxy_port", return_value=None):
            with mock_fetch(
                {
                    "version": "1.2.0",
                    "asset": "ClaudeGuard.exe",
                    "sha256": valid_sha,
                    "url": asset_url,
                    "release_url": "https://github.com/Octy-10/ClaudeGuard/releases/tag/v1.2.0",
                    "notes": "Fix leak guard",
                }
            ):
                info = updater.check_for_update("1.1.4")
            self.assertTrue(info.available)
            self.assertEqual(info.latest_version, "1.2.0")
            self.assertEqual(info.error, "")

            with mock_fetch({"version": "1.1.4", "sha256": valid_sha, "url": asset_url}):
                info_same = updater.check_for_update("1.1.4")
            self.assertFalse(info_same.available)
            self.assertEqual(info_same.error, "")

            with mock_fetch({"version": "1.2.0", "sha256": "not-a-sha", "url": asset_url}):
                info_bad_sha = updater.check_for_update("1.1.4")
            self.assertFalse(info_bad_sha.available)
            self.assertIn("SHA-256", info_bad_sha.error)

            with mock_fetch({"version": "1.2.0", "sha256": valid_sha, "url": "https://evil.example.com/a.exe"}):
                info_bad_url = updater.check_for_update("1.1.4")
            self.assertFalse(info_bad_url.available)
            self.assertIn("白名单", info_bad_url.error)

    def test_download_update_verifies_pe_and_sha256(self):
        pe_bytes = b"MZ" + b"\x90" * 4096
        pe_sha = hashlib.sha256(pe_bytes).hexdigest()
        info = updater.UpdateInfo(
            current_version="1.1.4",
            latest_version="1.2.0",
            available=True,
            asset="ClaudeGuard.exe",
            sha256=pe_sha,
            download_url="https://github.com/Octy-10/ClaudeGuard/releases/download/v1.2.0/ClaudeGuard.exe",
        )
        progress_events = []

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_dir = Path(tmpdir)
            with (
                patch.object(updater, "detect_local_proxy_port", return_value=None),
                patch.object(
                    updater,
                    "_open_https",
                    return_value=(Mock(), FakeResponse(pe_bytes, headers={"Content-Length": str(len(pe_bytes))})),
                ),
            ):
                staged = updater.download_update(info, dest_dir, progress_cb=lambda d, t: progress_events.append((d, t)))
            self.assertTrue(staged.is_file())
            self.assertEqual(staged.read_bytes(), pe_bytes)
            self.assertGreaterEqual(len(progress_events), 1)
            self.assertEqual(progress_events[-1], (len(pe_bytes), len(pe_bytes)))

            bad_sha_info = updater.UpdateInfo(
                current_version="1.1.4",
                latest_version="1.2.0",
                available=True,
                sha256="f" * 64,
                download_url=info.download_url,
            )
            with (
                patch.object(updater, "detect_local_proxy_port", return_value=None),
                patch.object(updater, "_open_https", return_value=(Mock(), FakeResponse(pe_bytes))),
            ):
                with self.assertRaises(ValueError):
                    updater.download_update(bad_sha_info, dest_dir)
            self.assertFalse((dest_dir / updater.STAGED_FILENAME).exists())

            non_pe = b"NOT_AN_EXE_HTML"
            non_pe_info = updater.UpdateInfo(
                current_version="1.1.4",
                latest_version="1.2.0",
                available=True,
                sha256=hashlib.sha256(non_pe).hexdigest(),
                download_url=info.download_url,
            )
            with (
                patch.object(updater, "detect_local_proxy_port", return_value=None),
                patch.object(updater, "_open_https", return_value=(Mock(), FakeResponse(non_pe))),
            ):
                with self.assertRaises(ValueError):
                    updater.download_update(non_pe_info, dest_dir)
            self.assertFalse((dest_dir / updater.STAGED_FILENAME).exists())

    def test_replace_script_quotes_unicode_and_includes_rollback(self):
        staged = Path(r"E:\工具\ClaudeGuard.update.tmp")
        target = Path(r"E:\工具\O'Neil\ClaudeGuard-一键配置环境.exe")
        script = updater.build_replace_ps_script(staged, target, 4321)
        self.assertIn("O''Neil", script)
        self.assertIn("ClaudeGuard-一键配置环境.exe", script)
        self.assertIn("--handoff", script)
        self.assertIn(".old", script)
        self.assertIn("-LiteralPath $backup", script)

    def test_bridge_check_update_notifies_badge(self):
        badge_calls = []
        tray_notifies = []
        avail_info = updater.UpdateInfo(
            current_version="1.1.4",
            latest_version="1.2.0",
            available=True,
            asset="ClaudeGuard.exe",
            sha256="a" * 64,
            download_url="https://github.com/Octy-10/ClaudeGuard/releases/download/v1.2.0/ClaudeGuard.exe",
        )
        up_to_date_info = updater.UpdateInfo(current_version="1.1.4", latest_version="1.1.4", available=False)

        with patch.object(bridge, "load_config", return_value=bridge.GuardConfig()):
            instance = bridge.GuardBridge(
                on_tray_notify=lambda t, m, l: tray_notifies.append((t, m, l)),
                on_update_badge=lambda avail, ver: badge_calls.append((avail, ver)),
            )

        with patch.object(bridge, "check_for_update", return_value=avail_info):
            res = instance.check_update()
        self.assertTrue(res["ok"])
        self.assertTrue(res["update"]["available"])
        self.assertEqual(badge_calls[-1], (True, "1.2.0"))
        self.assertEqual(len(tray_notifies), 1)

        with patch.object(bridge, "check_for_update", return_value=up_to_date_info):
            res_same = instance.check_update()
        self.assertTrue(res_same["ok"])
        self.assertFalse(res_same["update"]["available"])
        self.assertEqual(badge_calls[-1], (False, ""))

    def test_ssl_context_enforces_verification_and_loads_certifi(self):
        updater._build_ssl_context.cache_clear()
        ctx = updater._build_ssl_context()
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertGreater(ctx.cert_store_stats().get("x509_ca", 0), 0)

    def test_tray_badge_icon_and_tooltip_state(self):
        hicon = tray._create_tray_icon(tray.STATUS_RGB["green"], badge=True)
        self.assertTrue(hicon)
        tray.user32.DestroyIcon(hicon)

        icon = tray.SystemTrayIcon("Claude Guard (GREEN)", lambda: None, [])
        icon._hwnd = 1
        icon._icons = {"green": 10, "green:badge": 20}
        with patch.object(tray.shell32, "Shell_NotifyIconW", return_value=True) as notify_mock:
            icon.update("green", "Claude Guard (GREEN)")
            icon.set_update_badge(True, "1.2.0")
            self.assertEqual(notify_mock.call_args.args[1]._obj.hIcon, 20)
            self.assertIn("有新版 v1.2.0", icon._tooltip)
            icon.set_update_badge(False, "")
            self.assertEqual(notify_mock.call_args.args[1]._obj.hIcon, 10)
            self.assertNotIn("有新版", icon._tooltip)
