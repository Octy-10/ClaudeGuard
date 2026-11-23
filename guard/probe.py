"""Windows 系统状态只读采集层（注册表 0ms 直读 + 单次 PowerShell 网络快照）。

职责单一：只负责采集原始系统事实，不做风控判定或文案拼装。
"""

from __future__ import annotations

import ctypes
import re
import winreg
from ctypes import wintypes
from typing import Any, Dict, List, Tuple

from .config import FIREWALL_PROFILE_KEYS
from .sysutil import PHYSICAL_ADAPTER_FILTER, run_ps_json

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_BUFFER_OVERFLOW = 111
GAA_FLAG_FAST_MINIMAL = 0x000F  # SKIP_UNICAST|ANYCAST|MULTICAST|DNS_SERVER
IF_OPER_STATUS_UP = 1
_TUN_NAME_RE = re.compile(r"Mihomo|Clash", re.IGNORECASE)
_TUN_DESC_RE = re.compile(r"Wintun|Meta Tunnel|Mihomo", re.IGNORECASE)


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class _IP_ADAPTER_ADDRESSES_MIN(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("IfIndex", wintypes.DWORD),
        ("Next", ctypes.c_void_p),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.c_void_p),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", wintypes.LPWSTR),
        ("Description", wintypes.LPWSTR),
        ("FriendlyName", wintypes.LPWSTR),
        ("PhysicalAddress", ctypes.c_ubyte * 8),
        ("PhysicalAddressLength", wintypes.DWORD),
        ("Flags", wintypes.DWORD),
        ("Mtu", wintypes.DWORD),
        ("IfType", wintypes.DWORD),
        ("OperStatus", ctypes.c_int),
    ]


_kernel32 = ctypes.windll.kernel32
_kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
_kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
_kernel32.Process32FirstW.restype = wintypes.BOOL
_kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
_kernel32.Process32NextW.restype = wintypes.BOOL
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL

_iphlpapi = ctypes.windll.iphlpapi
_iphlpapi.GetAdaptersAddresses.argtypes = [
    wintypes.ULONG,
    wintypes.ULONG,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.ULONG),
]
_iphlpapi.GetAdaptersAddresses.restype = wintypes.ULONG


def _fast_list_process_names() -> set[str]:
    """纯 Win32 Toolhelp 快照读取运行中进程名（~2ms，零子进程）。"""
    names: set[str] = set()
    snap = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return names
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        if _kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            while True:
                if entry.szExeFile:
                    names.add(entry.szExeFile.lower())
                if not _kernel32.Process32NextW(snap, ctypes.byref(entry)):
                    break
    finally:
        _kernel32.CloseHandle(snap)
    return names


def _fast_check_tun_up() -> Tuple[bool, List[str]]:
    """纯 Win32 GetAdaptersAddresses 检查 Mihomo/Wintun 虚拟网卡在线状态（~2ms，零子进程）。"""
    buf_len = wintypes.ULONG(32768)
    for _ in range(3):
        buf = ctypes.create_string_buffer(buf_len.value)
        rc = _iphlpapi.GetAdaptersAddresses(0, GAA_FLAG_FAST_MINIMAL, None, buf, ctypes.byref(buf_len))
        if rc == 0:
            up_names: List[str] = []
            ptr = ctypes.addressof(buf)
            while ptr:
                node = _IP_ADAPTER_ADDRESSES_MIN.from_address(ptr)
                fname = node.FriendlyName or ""
                desc = node.Description or ""
                if (_TUN_NAME_RE.search(fname) or _TUN_DESC_RE.search(desc)) and node.OperStatus == IF_OPER_STATUS_UP:
                    up_names.append(fname or desc)
                ptr = node.Next
            return len(up_names) > 0, up_names
        if rc != ERROR_BUFFER_OVERFLOW:
            break
    return False, []


def _fast_read_firewall_disabled_hint() -> List[str]:
    """Read local profile hints. The full ActiveStore probe decides actual enforcement."""
    disabled: List[str] = []
    for label, sub in FIREWALL_PROFILE_KEYS.items():
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{sub}",
                0,
                winreg.KEY_READ,
            ) as key:
                val, _ = winreg.QueryValueEx(key, "EnableFirewall")
                if not bool(val):
                    disabled.append(label)
        except OSError:
            pass
    return disabled


def probe_fast_local_health() -> Dict[str, Any]:
    """超轻量纯 Win32 本地健康快检（~5ms，零 PowerShell，零外网请求），供 3 秒实时哨兵使用。"""
    procs = _fast_list_process_names()
    mihomo_running = "verge-mihomo.exe" in procs or "verge-mihomo-alpha.exe" in procs
    tun_up, tun_names = _fast_check_tun_up()
    return {
        "mihomo_running": mihomo_running,
        "tun_up": tun_up,
        "tun_names": tun_names,
        "fw_disabled_hint": _fast_read_firewall_disabled_hint(),
    }


def normalize_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def read_old_service() -> str:
    old_svc = ""
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\cc-hahaeasy",
            0,
            winreg.KEY_READ,
        ):
            old_svc = "Installed"
    except OSError:
        old_svc = ""

    return old_svc


def check_old_hklm_run() -> bool:
    """检查是否存在旧版 cc-hahaeasy 开机自启注册表项。"""
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_READ,
        ) as key:
            winreg.QueryValueEx(key, "cc-hahaeasy")
            return True
    except OSError:
        return False


def probe_system_snapshot() -> Dict[str, Any]:
    """单次 PowerShell 采集网卡、DNS、进程并补充旧服务状态。

    注意：Claude 进程统计严格限定为用户交互会话（SessionId > 0）且进程名为 `claude`，
    避免将 WindowsApps 安装的 Session-0 后台服务（如 CoworkVMService / cowork-svc.exe）
    误报为「运行中的 Claude 客户端」。
    """
    old_svc = read_old_service()
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$rawProcs = @(Get-Process);"
        "$procs = @($rawProcs | ForEach-Object { $_.ProcessName + '.exe' } | Select-Object -Unique);"
        "$claudeProcs = @($rawProcs | Where-Object { "
        "  $_.SessionId -gt 0 -and $_.ProcessName -match '^claude$' "
        "}).Count;"
        "$allNet = @(Get-NetAdapter);"
        "$tuns = @($allNet | Where-Object { "
        "  $_.Name -match 'Mihomo|Clash' -or $_.InterfaceDescription -match 'Wintun|Meta Tunnel|Mihomo' "
        "} | ForEach-Object { [pscustomobject]@{ name=[string]$_.Name; status=[string]$_.Status; desc=[string]$_.InterfaceDescription } });"
        f"$phys = @($allNet | Where-Object {{ {PHYSICAL_ADAPTER_FILTER} }});"
        "$ipv6 = @($phys | ForEach-Object { "
        "  $b = Get-NetAdapterBinding -Name ([WildcardPattern]::Escape($_.Name)) -ComponentID ms_tcpip6; "
        "  $enabled = if ($null -ne $b -and $null -ne $b.Enabled) { [bool]$b.Enabled }; "
        "  [pscustomobject]@{ name=[string]$_.Name; status=[string]$_.Status; ipv6=$enabled } "
        "});"
        "$dns = @($phys | ForEach-Object { "
        "  $d = Get-DnsClientServerAddress -InterfaceAlias $_.Name -AddressFamily IPv4; "
        "  [pscustomobject]@{ name=[string]$_.Name; status=[string]$_.Status; servers=@($d.ServerAddresses) } "
        "});"
        "[pscustomobject]@{ procs=$procs; claude_procs=$claudeProcs; tuns=$tuns; ipv6=$ipv6; dns=$dns } | ConvertTo-Json -Depth 4 -Compress"
    )
    ok, data, error = run_ps_json(ps, timeout=12)
    base: Dict[str, Any] = data if (ok and isinstance(data, dict)) else {
        "procs": [],
        "claude_procs": 0,
        "tuns": [],
        "ipv6": [],
        "dns": [],
        "error": error or "系统网络快照不可用",
    }
    base["old_svc"] = old_svc
    return base
