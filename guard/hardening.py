"""Browser policy and timezone changes, plus ordered system recovery."""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import sys
import winreg
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .adapters import disable_physical_ipv6, lock_physical_dns, restore_physical_dns, restore_physical_ipv6
from .config import IANA_TO_WINDOWS_TZ, load_backup, save_backup
from .firewall import disable_killswitch
from .sysutil import is_admin, run_cmd, run_ps_json


@dataclass
class WebRtcPolicyState:
    chrome_ok: bool
    edge_ok: bool
    firefox_ok: bool
    details: Dict[str, str]
    firefox_required: bool = False
    chrome_required: bool = True
    edge_required: bool = True


_POLICIES = {
    (r"SOFTWARE\Policies\Google\Chrome", "WebRtcIPHandling"): "disable_non_proxied_udp",
    (r"SOFTWARE\Policies\Microsoft\Edge", "WebRtcIPHandling"): "disable_non_proxied_udp",
    (r"SOFTWARE\Policies\Microsoft\Edge", "WebRtcLocalhostIpHandling"): "disable_non_proxied_udp",
    (r"SOFTWARE\Policies\Mozilla\Firefox\Preferences", "media.peerconnection.ice.default_address_only"): '{"Value": true, "Status": "locked"}',
    (r"SOFTWARE\Policies\Mozilla\Firefox\Preferences", "media.peerconnection.ice.no_host"): '{"Value": true, "Status": "locked"}',
}


def _read_policy(subkey: str, name: str) -> list | None:
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ) as key:
            value, kind = winreg.QueryValueEx(key, name)
            return [kind, list(value) if isinstance(value, bytes) else value]
    except FileNotFoundError:
        return None


def _same_policy(current: list | None, expected: list | None) -> bool:
    """回读比较需要按注册表类型归一化（REG_BINARY 读回为 int 列表）。"""
    if current is None and expected is None:
        return True
    if current is None or expected is None or current[0] != expected[0]:
        return False
    actual, wanted = current[1], expected[1]
    if isinstance(wanted, bytes):
        try:
            return bytes(actual) == wanted
        except (TypeError, ValueError):
            return False
    return actual == wanted


def _set_policy(subkey: str, name: str, entry: list | None) -> None:
    if entry is None:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass
    else:
        kind, value = entry
        if kind in (winreg.REG_BINARY, winreg.REG_NONE):
            value = None if value is None else bytes(value)
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, kind, value)
    if not _same_policy(_read_policy(subkey, name), entry):
        raise OSError(f"注册表策略回读不匹配：{name}")


_CHROME, _EDGE, _EDGE_LOCALHOST, _FIREFOX_DEFAULT, _FIREFOX_NOHOST = list(_POLICIES)

_FIREFOX_POLICY = (r"SOFTWARE\Policies\Mozilla\Firefox", "Preferences")
_BROWSER_LOCATIONS = {
    "chrome.exe": Path("Google/Chrome/Application"),
    "msedge.exe": Path("Microsoft/Edge/Application"),
    "firefox.exe": Path("Mozilla Firefox"),
}


def _browser_installed(executable: str) -> bool:
    subkey = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{executable}"
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view) as handle:
                    path, _ = winreg.QueryValueEx(handle, "")
                if Path(os.path.expandvars(str(path).strip('"'))).is_file():
                    return True
            except OSError:
                continue
    return bool(shutil.which(executable)) or any(
        (Path(root) / _BROWSER_LOCATIONS[executable] / executable).is_file()
        for name in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA")
        if (root := os.environ.get(name))
    )


def _firefox_locked(raw: str | dict) -> bool:
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return False
    return (
        isinstance(parsed, dict) and parsed.get("Value") is True
        and str(parsed.get("Status", "")).casefold() == "locked"
    )


def _firefox_preferences(entry: list | None) -> dict:
    if entry is None:
        return {}
    kind, content = entry
    if kind == winreg.REG_MULTI_SZ and isinstance(content, list):
        content = "\n".join(content)
    elif kind != winreg.REG_SZ or not isinstance(content, str):
        raise ValueError("Firefox Preferences 注册表类型无法解析")
    settings = json.loads(content)
    if not isinstance(settings, dict):
        raise ValueError("Firefox Preferences 必须是 JSON 对象")
    return settings


def _applied_policy(key: tuple[str, str], original: list | None) -> list:
    if key != _FIREFOX_POLICY:
        return [winreg.REG_SZ, _POLICIES[key]]
    settings = _firefox_preferences(original)
    for _, pref in (_FIREFOX_DEFAULT, _FIREFOX_NOHOST):
        settings[pref] = {"Value": True, "Status": "locked"}
    return [winreg.REG_MULTI_SZ, [json.dumps(settings, ensure_ascii=False)]]


def _policy_value(key: Tuple[str, str]) -> str:
    try:
        entry = _read_policy(*key)
    except OSError:
        return "读取失败"
    return str(entry[1]) if entry else ""


def get_webrtc_policy_state() -> WebRtcPolicyState:
    chrome = _policy_value(_CHROME)
    edge = _policy_value(_EDGE)
    edge_local = _policy_value(_EDGE_LOCALHOST)
    firefox_required = _browser_installed("firefox.exe")
    firefox_ok = False
    firefox = "未安装"
    if firefox_required:
        try:
            preferences = _firefox_preferences(_read_policy(*_FIREFOX_POLICY))
            firefox_ok = all(_firefox_locked(preferences.get(pref)) for _, pref in (_FIREFOX_DEFAULT, _FIREFOX_NOHOST))
            firefox = "已锁定" if firefox_ok else "WebRTC 首选项未全部锁定"
        except (OSError, ValueError):
            firefox = "读取失败"
    return WebRtcPolicyState(
        chrome_ok=chrome == "disable_non_proxied_udp",
        edge_ok=edge == "disable_non_proxied_udp",
        firefox_ok=firefox_ok,
        details={
            "Chrome": chrome or "未设置",
            "Edge": f"IPHandling={edge or '未设置'}, Localhost={edge_local or '未设置'}",
            "Firefox": firefox,
        },
        firefox_required=firefox_required,
        chrome_required=_browser_installed("chrome.exe"),
        edge_required=_browser_installed("msedge.exe"),
    )



def enable_webrtc_policies() -> Tuple[bool, str]:
    if not is_admin():
        return False, "修改 WebRTC 策略需要管理员权限"
    backup = load_backup()
    if backup.webrtc_modified:
        return False, "旧版 WebRTC 备份缺少原值，请先手动核对组策略"
    errors = []
    targets = []
    if _browser_installed("chrome.exe"):
        targets.append(_CHROME)
    if _browser_installed("msedge.exe"):
        targets.extend((_EDGE, _EDGE_LOCALHOST))
    if _browser_installed("firefox.exe"):
        targets.append(_FIREFOX_POLICY)
    if not targets:
        return True, "未发现需要配置的受支持浏览器"
    for subkey, name in targets:
        key = f"{subkey}\\{name}"
        try:
            current = _read_policy(subkey, name)
            previous = backup.webrtc_previous.get(key, current)
            expected = _applied_policy((subkey, name), previous)
            if _same_policy(current, expected):
                continue
            if not _same_policy(current, previous):
                raise ValueError("策略已由其他程序修改")
            if key not in backup.webrtc_previous:
                backup.webrtc_previous[key] = previous
                save_backup(backup)
            _set_policy(subkey, name, expected)
        except (OSError, ValueError) as exc:
            errors.append(f"{name}：{exc}")
    return (False, "；".join(errors)) if errors else (True, "已核对 WebRTC 策略，重启浏览器后生效")


def clear_webrtc_policies() -> Tuple[bool, str]:
    if not is_admin():
        return False, "恢复 WebRTC 策略需要管理员权限"
    backup = load_backup()
    errors = []
    for subkey, name in (*_POLICIES, _FIREFOX_POLICY):
        key = f"{subkey}\\{name}"
        if key not in backup.webrtc_previous:
            continue
        previous = backup.webrtc_previous[key]
        try:
            current = _read_policy(subkey, name)
            if not _same_policy(current, previous):
                if not _same_policy(current, _applied_policy((subkey, name), previous)):
                    raise ValueError("策略已由其他程序修改")
                _set_policy(subkey, name, previous)
            del backup.webrtc_previous[key]
            save_backup(backup)
        except (OSError, ValueError) as exc:
            errors.append(f"{name}：{exc}")
    if backup.webrtc_modified:
        errors.append("旧版 WebRTC 备份缺少原值，请手动核对组策略")
    return (False, "；".join(errors)) if errors else (True, "已核对所有已备份的 WebRTC 策略")


def _tzutil(*args: str) -> Tuple[int, str, str]:
    executable = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\tzutil.exe")
    return run_cmd([executable, *args])


def get_current_windows_timezone() -> str:
    rc, out, _ = _tzutil("/g")
    return out if rc == 0 and out else "未知"


def _set_timezone(target: str) -> Tuple[bool, str]:
    rc, out, error = _tzutil("/s", target)
    if rc != 0:
        return False, error or out or f"时区修改失败（退出码 {rc}）"
    if get_current_windows_timezone() != target:
        return False, "时区回读验证失败"
    return True, f"系统时区已设为 {target}"


def align_timezone_to_iana(iana_tz: str) -> Tuple[bool, str]:
    if not is_admin():
        return False, "修改时区需要管理员权限"
    target = IANA_TO_WINDOWS_TZ.get(iana_tz)
    if not target:
        return False, f"未收录 IANA 时区 {iana_tz} 的 Windows 映射"
    current = get_current_windows_timezone()
    if current == "未知":
        return False, "无法读取原时区"
    if current == target:
        return True, f"系统时区已是 {target}"
    backup = load_backup()
    if not backup.original_timezone:
        backup.original_timezone = current
        save_backup(backup)
    return _set_timezone(target)


def restore_timezone() -> Tuple[bool, str]:
    if not is_admin():
        return False, "恢复时区需要管理员权限"
    backup = load_backup()
    if not backup.original_timezone:
        return True, "当前没有由 Claude Guard 记录的时区改动"
    target = backup.original_timezone
    ok, message = (True, f"系统时区已是 {target}") if get_current_windows_timezone() == target else _set_timezone(target)
    if ok:
        backup.original_timezone = None
        save_backup(backup)
    return ok, message


def kill_claude_desktop() -> Tuple[bool, str]:
    """按 Anthropic 代码签名精确匹配并安全结束用户会话中运行中的 Claude 客户端进程（排除 Session-0 后台服务）。"""
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$killed = @();"
        "$procs = @(Get-Process | Where-Object { $_.SessionId -gt 0 -and $_.ProcessName -match '^claude$' -and $_.Path });"
        "foreach ($p in $procs) {"
        "  $sig = Get-AuthenticodeSignature -FilePath $p.Path;"
        "  $subj = if ($sig -and $sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { '' };"
        "  if ($subj -match 'Anthropic' -or $p.Path -match 'AnthropicClaude|WindowsApps\\\\Claude_|\\\\\\.local\\\\bin\\\\claude\\.exe$') {"
        "    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue;"
        "    $killed += ($p.ProcessName + ' (PID ' + $p.Id + ')');"
        "  }"
        "}"
        "[pscustomobject]@{ count=$killed.Count; items=$killed } | ConvertTo-Json -Compress"
    )
    ok, data, err = run_ps_json(ps, timeout=15)
    if not ok:
        return False, f"检索 Claude 进程失败: {err}"
    count = int(data.get("count", 0)) if isinstance(data, dict) else 0
    if count == 0:
        return True, "当前未检测到运行中的 Anthropic Claude 桌面端进程"
    items = data.get("items") or []
    if isinstance(items, str):
        items = [items]
    return True, f"已按 Anthropic 签名安全结束 {count} 个 Claude 桌面端进程（{', '.join(items[:4])}）"



@dataclass
class StepResult:
    label: str
    ok: bool
    message: str

    def log(self) -> str:
        status = "成功" if self.ok else "失败"
        return f"[{status}] {self.label}：{self.message}"


def run_steps(steps: list[tuple[str, Callable[[], tuple[bool, str]]]]) -> list[StepResult]:
    results = []
    for label, action in steps:
        try:
            ok, message = action()
        except Exception as exc:
            # 任何非预期异常都必须变成失败步骤，不能穿透到前端或中断后续恢复
            ok, message = False, f"{type(exc).__name__}: {exc}"
        results.append(StepResult(label, ok, message))
    return results


HKCU_RUN_SUBKEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_VALUE_NAME = "ClaudeGuard"
APP_ENTRY_PATH = Path(__file__).resolve().parent.parent / "app.py"


def play_alert_beep() -> None:
    """播放 Windows 原生严重告警提示音（不依赖外部音频文件）。"""
    try:
        ctypes.windll.user32.MessageBeep(0x00000010)  # MB_ICONHAND
    except Exception:
        pass


def get_autostart_enabled() -> bool:
    """检查是否已在当前用户 HKCU\\Run 中启用开机静默最小化托盘守护。"""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, HKCU_RUN_SUBKEY, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, AUTOSTART_VALUE_NAME)
            return bool(str(val).strip())
    except OSError:
        return False


def set_autostart_enabled(enable: bool) -> Tuple[bool, str]:
    """开启或关闭当前用户登录自启（最小化到托盘，不创建系统服务）。"""
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, HKCU_RUN_SUBKEY, 0, winreg.KEY_SET_VALUE) as key:
            if enable:
                if getattr(sys, "frozen", False):
                    cmd = f'"{Path(sys.executable).resolve()}" --minimized'
                else:
                    py_dir = Path(sys.executable).resolve().parent
                    pyw = py_dir / "pythonw.exe"
                    exe = str(pyw) if pyw.is_file() else (shutil.which("pythonw") or sys.executable)
                    cmd = f'"{exe}" "{APP_ENTRY_PATH}" --minimized'
                winreg.SetValueEx(key, AUTOSTART_VALUE_NAME, 0, winreg.REG_SZ, cmd)
                return True, "已开启开机静默托盘守护（仅写入当前用户启动项，无系统服务）"
            try:
                winreg.DeleteValue(key, AUTOSTART_VALUE_NAME)
            except FileNotFoundError:
                pass
            return True, "已关闭开机静默托盘守护"
    except OSError as exc:
        return False, f"修改开机自启项失败: {exc}"


def run_rescue() -> list[StepResult]:
    return run_steps([
        ("防火墙 Kill Switch", disable_killswitch),
        ("物理网卡 DNS", restore_physical_dns),
        ("浏览器 WebRTC 策略", clear_webrtc_policies),
        ("物理网卡 IPv6", restore_physical_ipv6),
        ("系统时区", restore_timezone),
        ("开机静默自启项", lambda: set_autostart_enabled(False)),
    ])
