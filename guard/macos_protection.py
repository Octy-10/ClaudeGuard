"""macOS 已安装组件的授权调用、过滤状态和浏览器策略。"""

from __future__ import annotations

import ctypes
import json
import os
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import __version__
from .clash_config import read_config, subscription_probe_issues
from .config import CLASH_VERGE_RUNTIME_YAML, STATE_DIR
from .macos import run_command, verify_proxy_listener

APP_ID = "io.github.octy-10.claudeguard"
EXTENSION_ID = APP_ID + ".filter"
SETTINGS_HELPER = Path("/Library/PrivilegedHelperTools") / (APP_ID + ".settings")
APP_PROXY_PORT = 17898
APP_PROXY_GROUP = "Guard-Claude"
APP_PROXY_INBOUND = "claude-guard-app"
PROFILE_ID = APP_ID + ".webrtc"
PROFILE_SETTINGS = "x-apple.systempreferences:com.apple.Profiles-Settings.extension"
_ELEVATION_SCRIPT = """on run argv
    set helperCommand to quoted form of (item 1 of argv)
    repeat with position from 2 to (count of argv)
        set helperCommand to helperCommand & space & quoted form of (item position of argv)
    end repeat
    do shell script helperCommand with administrator privileges
end run"""


def _result_error(message: str) -> dict[str, Any]:
    return {"ok": False, "message": message}


def _response(data: bytes | str) -> dict[str, Any]:
    decoded = json.loads(data)
    if not isinstance(decoded, dict) or type(decoded.get("ok")) is not bool:
        raise ValueError("系统组件结果无效")
    return decoded


@lru_cache(maxsize=1)
def _host_library():
    path = Path(sys.executable).parent.parent / "Frameworks" / "libClaudeGuardHost.dylib"
    library = ctypes.CDLL(str(path))
    library.claude_guard_host_command.argtypes = (ctypes.c_char_p,)
    library.claude_guard_host_command.restype = ctypes.c_void_p
    library.claude_guard_host_free.argtypes = (ctypes.c_void_p,)
    library.claude_guard_host_free.restype = None
    return library


def host_available() -> bool:
    if sys.platform != "darwin" or not getattr(sys, "frozen", False):
        return False
    return (Path(sys.executable).parent.parent / "Frameworks" / "libClaudeGuardHost.dylib").is_file()


def host_command(verb: str) -> dict[str, Any]:
    if not host_available():
        return _result_error("需要安装 macOS Claude Guard 应用包。")
    try:
        library = _host_library()
        pointer = library.claude_guard_host_command(verb.encode("ascii"))
        if not pointer:
            return _result_error("未收到系统组件响应。")
        try:
            return _response(ctypes.string_at(pointer))
        finally:
            library.claude_guard_host_free(pointer)
    except (OSError, ValueError, AttributeError) as error:
        return _result_error(f"系统组件不可用：{error}")


def _trusted_settings_helper() -> bool:
    try:
        for directory in (SETTINGS_HELPER.parent, SETTINGS_HELPER.parent.parent):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return False
        info = SETTINGS_HELPER.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not (info.st_mode & 0o7022)


def settings_command(verb: str, value: str = "") -> dict[str, Any]:
    if not host_available() or not _trusted_settings_helper():
        return _result_error("系统设置需要通过 Claude Guard 的签名安装包安装。")
    args = [str(SETTINGS_HELPER), verb]
    if value:
        args.append(value)
    if verb != "status" and os.geteuid() != 0:
        args = ["/usr/bin/osascript", "-e", _ELEVATION_SCRIPT, *args]
    try:
        completed = subprocess.run(args, capture_output=True, encoding="utf-8", timeout=8 if verb == "status" else 300)
        if completed.returncode != 0:
            if "(-128)" in completed.stderr:
                return _result_error("已取消管理员授权。")
            return _result_error("无法完成管理员操作，请查看系统授权并重试。")
        return _response(completed.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return _result_error("未收到系统设置组件响应，请重新巡检。")


def installed() -> bool:
    return host_available() and _trusted_settings_helper()


def extension_active() -> bool | None:
    output = run_command("/usr/bin/systemextensionsctl", "list")
    if output is None:
        return None
    for line in output.splitlines():
        if line.split()[:2] != ["*", "*"] or EXTENSION_ID not in line.split() or "[activated enabled]" not in line:
            continue
        version = re.search(r"\(([0-9.]+)(?:/[0-9.]+)?\)", line)
        if version and version[1] == __version__:
            return True
    return False


def filter_status() -> dict[str, Any]:
    result = host_command("filter-status")
    return {**result, "active": extension_active() if result.get("configured") else False}


def app_relay_issue() -> str:
    try:
        config = read_config(CLASH_VERGE_RUNTIME_YAML)
    except (OSError, ValueError):
        return "请先应用 macOS Clash 扩展脚本。"
    issues = subscription_probe_issues(config, group=APP_PROXY_GROUP, inbound=APP_PROXY_INBOUND, port=APP_PROXY_PORT)
    if issues:
        return issues[0]
    if not verify_proxy_listener(APP_PROXY_PORT):
        return f"无法核实本机 Claude 专用入口 127.0.0.1:{APP_PROXY_PORT}。"
    return ""


def set_filter(enabled: bool) -> dict[str, Any]:
    if enabled:
        issue = app_relay_issue()
        if issue:
            return _result_error(issue)
        existing = filter_status()
        if existing.get("configured") is True and existing.get("active") is True:
            return {"ok": True, "filter_enabled": True, "message": "当前版本的断网锁已启用。"}
    result = host_command("filter-enable" if enabled else "filter-disable")
    if result["ok"] and enabled:
        status = filter_status()
        if status.get("active") is not True or not status.get("configured"):
            return _result_error("网络过滤配置已提交。请在系统设置中批准扩展，然后重新巡检。")
    return {**result, "filter_enabled": enabled} if result["ok"] else result


def launch_claude() -> dict[str, Any]:
    status = filter_status()
    if not status.get("configured") or status.get("active") is not True:
        return _result_error("请先启用并核实 Claude Desktop 断网锁。")
    issue = app_relay_issue()
    return _result_error(issue) if issue else host_command("claude-launch")


def browser_profile() -> bytes:
    def metadata(identifier: str, payload_type: str, title: str) -> dict[str, Any]:
        return {
            "PayloadIdentifier": identifier,
            "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_DNS, identifier)).upper(),
            "PayloadType": payload_type,
            "PayloadDisplayName": title,
            "PayloadVersion": 1,
        }

    policies = {
        "com.google.Chrome": {"WebRtcIPHandling": "disable_non_proxied_udp"},
        "com.microsoft.edgemac": {"WebRtcLocalhostIpHandling": "disable_non_proxied_udp"},
        "org.mozilla.firefox": {
            "EnterprisePoliciesEnabled": True,
            "Preferences": {"media.peerconnection.enabled": {"Value": False, "Status": "locked"}},
        },
    }
    payload = metadata(PROFILE_ID + ".preferences", "com.apple.ManagedClient.preferences", "浏览器 WebRTC 防护")
    payload["PayloadContent"] = {domain: {"Forced": [{"mcx_preference_settings": settings}]} for domain, settings in policies.items()}
    profile = metadata(PROFILE_ID, "Configuration", "Claude Guard WebRTC")
    profile.update(PayloadContent=[payload], PayloadScope="System", PayloadOrganization="Claude Guard")
    return plistlib.dumps(profile)


def open_profile_settings(enable: bool) -> dict[str, Any]:
    temporary = None
    try:
        if enable:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=STATE_DIR, delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(browser_profile())
            profile = STATE_DIR / "ClaudeGuard-WebRTC.mobileconfig"
            temporary.replace(profile)
            completed = subprocess.run(["/usr/bin/open", str(profile)], capture_output=True, timeout=8)
            if completed.returncode != 0:
                return _result_error("无法打开 WebRTC 描述文件。")
        subprocess.run(["/usr/bin/open", PROFILE_SETTINGS], capture_output=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired) as error:
        return _result_error(f"无法打开系统设置：{error}")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    verb = "安装" if enable else "移除"
    return {"ok": True, "message": f"请在系统设置的「设备管理」中{verb} Claude Guard WebRTC 描述文件，再重启浏览器。"}


def rescue() -> dict[str, Any]:
    system = settings_command("rescue")
    # Restore network settings before removing our filter, including after a partial failure.
    filtered = host_command("filter-disable")
    errors = [entry.get("message") for entry in (system, filtered) if not entry["ok"]]
    browsers = host_command("webrtc-status").get("browsers", {})
    if (STATE_DIR / "ClaudeGuard-WebRTC.mobileconfig").exists() and any(browsers.values()):
        errors.append("请在系统设置中移除 Claude Guard WebRTC 描述文件。")
    if errors:
        result = _result_error("；".join(str(message) for message in errors if message))
    else:
        result = {"ok": True, "message": "系统网络设置和断网锁恢复已完成。"}
    if filtered["ok"]:
        result["filter_enabled"] = False
    return result
