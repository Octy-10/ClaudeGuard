"""系统底层工具函数：权限检测、安全命令执行与 Claude 进程路径发现。"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import time
from contextlib import contextmanager
from ctypes import wintypes
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator, List, Optional, Tuple

CREATE_NO_WINDOW = 0x08000000
ERROR_ALREADY_EXISTS = 183
SINGLE_INSTANCE_MUTEX = "Local\\ClaudeGuard_SingleInstance_v1"
SYSTEM_CHANGE_MUTEX = "Global\\ClaudeGuard_SystemChanges_v1"
PHYSICAL_ADAPTER_FILTER = (
    "$_.HardwareInterface -eq $true -and "
    "$_.InterfaceDescription -notmatch 'Mihomo|Wintun|Meta Tunnel|sing-tun|WireGuard|TAP-Windows|Loopback'"
)

_kernel32_err = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32_err.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
_kernel32_err.CreateMutexW.restype = wintypes.HANDLE
_kernel32_err.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32_err.CloseHandle.restype = wintypes.BOOL


class SingleInstanceLock:
    """基于 Win32 Named Mutex 的单实例锁，防止重复双击出现多个托盘图标。"""

    def __init__(self, name: str = SINGLE_INSTANCE_MUTEX) -> None:
        self._name = name
        self._handle: Optional[int] = None

    def acquire(self, wait_sec: float = 0.0) -> bool:
        deadline = time.monotonic() + max(0.0, wait_sec)
        while True:
            ctypes.set_last_error(0)
            handle = _kernel32_err.CreateMutexW(None, False, self._name)
            err = ctypes.get_last_error()
            if handle and err != ERROR_ALREADY_EXISTS:
                self._handle = int(handle)
                return True
            if handle:
                _kernel32_err.CloseHandle(handle)
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.1)

    def release(self) -> None:
        if self._handle:
            _kernel32_err.CloseHandle(wintypes.HANDLE(self._handle))
            self._handle = None


@contextmanager
def system_change_lock() -> Iterator[bool]:
    """Serialize GUI and CLI system changes independently of the window instance."""
    lock = SingleInstanceLock(SYSTEM_CHANGE_MUTEX)
    acquired = lock.acquire()
    try:
        yield acquired
    finally:
        if acquired:
            lock.release()


def show_info_dialog(title: str, message: str) -> None:
    """弹出原生 Win32 信息提示框（无 Tkinter 依赖）。"""
    try:
        user32 = ctypes.windll.user32
        user32.MessageBoxW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
        user32.MessageBoxW.restype = ctypes.c_int
        user32.MessageBoxW(None, message, title, 0x40)
    except Exception:
        pass


def ps_quote(value: str) -> str:
    """将字符串安全包裹为 PowerShell 单引号字面量，防止命令注入。"""
    return "'" + value.replace("'", "''") + "'"


def get_bundle_root() -> Path:
    """返回资源根目录：PyInstaller 打包态指向 sys._MEIPASS，源码态指向项目根目录。"""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parent.parent


def is_admin() -> bool:
    """检查当前进程是否具有 Windows 管理员权限。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(script_path: Optional[str] = None, extra_args: Optional[List[str]] = None) -> bool:
    """触发标准 UAC 提权弹窗，以管理员身份重启当前应用。"""
    frozen = bool(getattr(sys, "frozen", False))
    forwarded = list(sys.argv[1:])
    if extra_args:
        for arg in extra_args:
            if arg not in forwarded:
                forwarded.append(arg)
    if frozen:
        params = " ".join(f'"{a}"' for a in forwarded)
        workdir = os.path.dirname(sys.executable) or None
    else:
        target = script_path or os.path.abspath(sys.argv[0])
        params = f'"{target}"'
        if forwarded:
            params = f"{params} " + " ".join(f'"{a}"' for a in forwarded)
        workdir = os.path.dirname(target) or None
    shell32 = ctypes.windll.shell32
    shell32.ShellExecuteW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    rc = shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        workdir,
        1,
    )
    return int(rc or 0) > 32


def run_cmd(args: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    """静默执行原生命令（不弹黑框），返回 (returncode, stdout, stderr)。"""
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"命令超时 ({timeout}s): {' '.join(args[:3])}"
    except Exception as exc:
        return -1, "", str(exc)


def run_ps(script: str, timeout: int = 25) -> Tuple[int, str, str]:
    """通过固定系统路径的 PowerShell 执行脚本并强制 UTF-8 输出。"""
    ps_exe = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        r"System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    wrapped = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + script
    return run_cmd(
        [ps_exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", wrapped],
        timeout=timeout,
    )


def run_ps_json(script: str, timeout: int = 25) -> Tuple[bool, Any, str]:
    """执行返回 JSON 的 PowerShell 脚本。"""
    rc, out, err = run_ps(script, timeout=timeout)
    if rc != 0:
        return False, None, err or out or f"PowerShell exit={rc}"
    if not out:
        return True, None, ""
    try:
        return True, json.loads(out), ""
    except json.JSONDecodeError as exc:
        return False, None, f"JSON 解析失败: {exc} | 原始输出: {out[:200]}"


@lru_cache(maxsize=64)
def _scan_claude_root(root: Path, modified: int, refresh_period: int, store_package: bool) -> tuple[Path, ...]:
    return tuple(
        item for item in root.rglob("*.exe")
        if ("claude" in item.name.casefold() if not store_package else item.name.casefold().startswith("claude"))
    )


def discover_claude_executables(extra_paths: Optional[List[str]] = None) -> List[str]:
    """发现本机已安装的 Claude Desktop / Claude Code 可执行文件路径。"""
    candidates: List[Path] = []
    local_app = Path(os.environ.get("LOCALAPPDATA", ""))
    user_home = Path.home()

    search_roots = [
        local_app / "AnthropicClaude",
        local_app / "Programs" / "claude",
        user_home / ".local" / "bin",
        user_home / ".local" / "share" / "claude",
    ]

    win_apps = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WindowsApps"
    roots = [(root, False) for root in search_roots]
    try:
        roots.extend((root, True) for root in win_apps.glob("Claude_*"))
    except OSError:
        pass
    # A bounded refresh also catches changes below the root directory.
    refresh_period = int(time.monotonic() // 300)
    for root, store_package in roots:
        try:
            candidates.extend(_scan_claude_root(root, root.stat().st_mtime_ns, refresh_period, store_package))
        except OSError:
            continue

    if extra_paths:
        for p in extra_paths:
            path_obj = Path(p)
            if path_obj.is_file():
                candidates.append(path_obj)

    seen = set()
    result: List[str] = []
    for p in candidates:
        if not p.is_file():
            continue
        norm = str(p.resolve())
        key = norm.lower()
        if key not in seen:
            seen.add(key)
            result.append(norm)
    return result


def get_physical_adapters() -> List[str]:
    """获取本机所有物理网卡别名（排除 Mihomo/Wintun/虚拟隧道网卡）。"""
    ps = (
        "$ErrorActionPreference='Stop';"
        f"@(Get-NetAdapter | Where-Object {{ {PHYSICAL_ADAPTER_FILTER} }} "
        "| ForEach-Object { $_.Name }) | ConvertTo-Json -Compress"
    )
    ok, data, _ = run_ps_json(ps)
    if not ok or not data:
        return []
    if isinstance(data, str):
        return [data]
    return [str(x) for x in data if x]
