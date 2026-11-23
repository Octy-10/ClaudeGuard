"""纯 Win32 API（ctypes）原生系统托盘图标，零第三方依赖。

支持：
- 动态绘制抗锯齿 32x32 彩色状态灯图标（绿 / 黄 / 红 / 灰）
- 左键单击 / 双击唤起主窗口
- 右键原生弹出菜单
- Windows 系统气泡通知（出口 IP 漂移 / TUN 断开告警）
"""

from __future__ import annotations

import ctypes
import math
import threading
from ctypes import wintypes
from typing import Callable, Dict, List, Optional, Tuple

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

WM_NULL = 0x0000
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_USER = 0x0400
WM_TRAYICON = WM_USER + 20
WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205

NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002

NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
NIF_INFO = 0x00000010

NIIF_INFO = 0x00000001
NIIF_WARNING = 0x00000002
NIIF_ERROR = 0x00000003

MF_STRING = 0x00000000
MF_GRAYED = 0x00000001
MF_SEPARATOR = 0x00000800
TPM_LEFTALIGN = 0x0000
TPM_BOTTOMALIGN = 0x0020
TPM_RIGHTBUTTON = 0x0002
TPM_NONOTIFY = 0x0080
TPM_RETURNCMD = 0x0100
FIRST_MENU_COMMAND = 1001

BI_RGB = 0
DIB_RGB_COLORS = 0


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.UINT),
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HICON),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
        ("hIconSm", wintypes.HICON),
    ]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uTimeoutOrVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", ctypes.c_byte * 16),
        ("hBalloonIcon", wintypes.HICON),
    ]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class ICONINFO(ctypes.Structure):
    _fields_ = [
        ("fIcon", wintypes.BOOL),
        ("xHotspot", wintypes.DWORD),
        ("yHotspot", wintypes.DWORD),
        ("hbmMask", wintypes.HBITMAP),
        ("hbmColor", wintypes.HBITMAP),
    ]


user32 = ctypes.windll.user32
shell32 = ctypes.windll.shell32
gdi32 = ctypes.windll.gdi32
kernel32 = ctypes.windll.kernel32

# 显式声明 64 位安全的函数签名，防止指针截断
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE

user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
user32.RegisterClassExW.restype = wintypes.ATOM

user32.CreateWindowExW.argtypes = [
    wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
    wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
]
user32.CreateWindowExW.restype = wintypes.HWND

user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.DefWindowProcW.restype = LRESULT

user32.DestroyWindow.argtypes = [wintypes.HWND]
user32.DestroyWindow.restype = wintypes.BOOL

user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.PostMessageW.restype = wintypes.BOOL

user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
user32.GetMessageW.restype = wintypes.BOOL

user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
user32.TranslateMessage.restype = wintypes.BOOL

user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
user32.DispatchMessageW.restype = LRESULT

user32.PostQuitMessage.argtypes = [ctypes.c_int]
user32.PostQuitMessage.restype = None

user32.CreatePopupMenu.argtypes = []
user32.CreatePopupMenu.restype = wintypes.HMENU

user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
user32.AppendMenuW.restype = wintypes.BOOL

user32.DestroyMenu.argtypes = [wintypes.HMENU]
user32.DestroyMenu.restype = wintypes.BOOL

user32.TrackPopupMenu.argtypes = [
    wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int,
    ctypes.c_int, wintypes.HWND, wintypes.LPVOID,
]
user32.TrackPopupMenu.restype = wintypes.BOOL

user32.SetForegroundWindow.argtypes = [wintypes.HWND]
user32.SetForegroundWindow.restype = wintypes.BOOL

user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
user32.GetCursorPos.restype = wintypes.BOOL

user32.CreateIconIndirect.argtypes = [ctypes.POINTER(ICONINFO)]
user32.CreateIconIndirect.restype = wintypes.HICON

user32.DestroyIcon.argtypes = [wintypes.HICON]
user32.DestroyIcon.restype = wintypes.BOOL

gdi32.CreateDIBSection.argtypes = [
    wintypes.HDC, ctypes.POINTER(BITMAPINFOHEADER), wintypes.UINT,
    ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE, wintypes.DWORD,
]
gdi32.CreateDIBSection.restype = wintypes.HBITMAP

gdi32.CreateBitmap.argtypes = [ctypes.c_int, ctypes.c_int, wintypes.UINT, wintypes.UINT, wintypes.LPVOID]
gdi32.CreateBitmap.restype = wintypes.HBITMAP

gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
gdi32.DeleteObject.restype = wintypes.BOOL

shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
shell32.Shell_NotifyIconW.restype = wintypes.BOOL


STATUS_RGB: Dict[str, Tuple[int, int, int]] = {
    "green": (46, 204, 121),
    "yellow": (245, 176, 65),
    "red": (239, 90, 98),
    "gray": (152, 158, 176),
}

CHECK_INK: Tuple[int, int, int] = (18, 20, 26)

# 与 web/index.html #i-guard 同构的盾牌几何（归一化坐标）
_SHIELD = {"left": 0.165, "right": 0.835, "top": 0.095, "bottom": 0.925, "taper": 0.34, "radius": 0.20}
_CHECK_POINTS = ((0.345, 0.505), (0.452, 0.615), (0.672, 0.375))


def _in_rounded_rect(nx: float, ny: float, left: float, right: float, top: float, bottom: float, r: float) -> bool:
    cx, cy = (left + right) / 2, (top + bottom) / 2
    dx = abs(nx - cx) - ((right - left) / 2 - r)
    dy = abs(ny - cy) - ((bottom - top) / 2 - r)
    if dx <= 0 and dy <= 0:
        return True
    return dx * dx + dy * dy <= r * r


def _in_shield(nx: float, ny: float) -> bool:
    left, right = _SHIELD["left"], _SHIELD["right"]
    top, bottom = _SHIELD["top"], _SHIELD["bottom"]
    if not (left <= nx <= right and top <= ny <= bottom):
        return False
    shoulder = top + (bottom - top) * _SHIELD["taper"]
    radius = (right - left) * _SHIELD["radius"]
    if ny <= shoulder:
        return _in_rounded_rect(nx, ny, left, right, top, shoulder + radius, radius)
    t = (ny - shoulder) / (bottom - shoulder)
    half = (right - left) / 2 * math.sqrt(max(0.0, 1.0 - t * t))
    center = (left + right) / 2
    return abs(nx - center) <= half


def _check_coverage(nx: float, ny: float, thickness: float) -> float:
    """点到对勾折线的最短距离，用于判定笔画覆盖。"""
    best = float("inf")
    for (x1, y1), (x2, y2) in zip(_CHECK_POINTS, _CHECK_POINTS[1:]):
        dx, dy = x2 - x1, y2 - y1
        length = dx * dx + dy * dy
        t = 0.0 if length == 0 else max(0.0, min(1.0, ((nx - x1) * dx + (ny - y1) * dy) / length))
        best = min(best, math.hypot(nx - (x1 + t * dx), ny - (y1 + t * dy)))
    return 1.0 if best <= thickness else 0.0


def _create_tray_icon(rgb: Tuple[int, int, int], size: int = 32, badge: bool = False) -> wintypes.HICON:
    """在内存中绘制带抗锯齿的盾牌状态图标（盾牌着色 + 镂空对勾 + 可选右上角更新红点）。"""
    bmi = BITMAPINFOHEADER()
    bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.biWidth = size
    bmi.biHeight = -size  # Top-down DIB
    bmi.biPlanes = 1
    bmi.biBitCount = 32
    bmi.biCompression = BI_RGB

    bits_ptr = ctypes.c_void_p()
    hbm_color = gdi32.CreateDIBSection(None, ctypes.byref(bmi), DIB_RGB_COLORS, ctypes.byref(bits_ptr), None, 0)
    if not hbm_color or not bits_ptr.value:
        if hbm_color:
            gdi32.DeleteObject(hbm_color)
        return wintypes.HICON(0)

    r_col, g_col, b_col = rgb
    buf = bytearray(size * size * 4)
    samples = 4  # 4x4 超采样，托盘缩小到 16px 依然干净
    thickness = 0.072
    total = samples * samples
    badge_cx, badge_cy = 0.79, 0.21
    badge_inner_r, badge_outer_r = 0.155, 0.215

    for y in range(size):
        for x in range(size):
            hits = 0
            r_sum = 0.0
            g_sum = 0.0
            b_sum = 0.0
            for sy in range(samples):
                for sx in range(samples):
                    nx = (x + (sx + 0.5) / samples) / size
                    ny = (y + (sy + 0.5) / samples) / size
                    if badge:
                        dist = math.hypot(nx - badge_cx, ny - badge_cy)
                        if dist <= badge_outer_r:
                            hits += 1
                            if dist <= badge_inner_r:
                                r_sum += 239
                                g_sum += 68
                                b_sum += 68
                            else:
                                r_sum += CHECK_INK[0]
                                g_sum += CHECK_INK[1]
                                b_sum += CHECK_INK[2]
                            continue
                    if _in_shield(nx, ny):
                        hits += 1
                        if _check_coverage(nx, ny, thickness) > 0:
                            r_sum += CHECK_INK[0]
                            g_sum += CHECK_INK[1]
                            b_sum += CHECK_INK[2]
                        else:
                            r_sum += r_col
                            g_sum += g_col
                            b_sum += b_col
            if not hits:
                continue
            r = round(r_sum / hits)
            g = round(g_sum / hits)
            b = round(b_sum / hits)
            a = round(255 * hits / total)
            idx = (y * size + x) * 4
            # Win32 32-bit DIB 使用预乘 BGRA
            buf[idx] = (b * a) // 255
            buf[idx + 1] = (g * a) // 255
            buf[idx + 2] = (r * a) // 255
            buf[idx + 3] = a

    ctypes.memmove(bits_ptr.value, (ctypes.c_ubyte * len(buf)).from_buffer(buf), len(buf))
    mask_stride = ((size + 15) // 16) * 2  # Each monochrome scan line is WORD-aligned.
    mask = (ctypes.c_ubyte * (size * mask_stride))()
    for y in range(size):
        for x in range(size):
            if buf[(y * size + x) * 4 + 3] == 0:
                mask[y * mask_stride + x // 8] |= 0x80 >> (x % 8)
    hbm_mask = gdi32.CreateBitmap(size, size, 1, 1, mask)
    if not hbm_mask:
        gdi32.DeleteObject(hbm_color)
        return wintypes.HICON(0)

    info = ICONINFO()
    info.fIcon = True
    info.xHotspot = 0
    info.yHotspot = 0
    info.hbmMask = hbm_mask
    info.hbmColor = hbm_color
    hicon = user32.CreateIconIndirect(ctypes.byref(info))

    gdi32.DeleteObject(hbm_color)
    if hbm_mask:
        gdi32.DeleteObject(hbm_mask)
    return hicon


class SystemTrayIcon:
    """运行在后台线程的 Windows 原生系统托盘管理器。"""

    def __init__(
        self,
        tooltip: str,
        on_open: Callable[[], None],
        menu_items: List[Tuple[Optional[str], Optional[Callable[[], None]]]],
    ) -> None:
        self._base_tooltip = tooltip[:127]
        self._tooltip = self._base_tooltip
        self._on_open = on_open
        self._menu_items = list(menu_items)
        self._hwnd: Optional[wintypes.HWND] = None
        self._icons: Dict[str, wintypes.HICON] = {}
        self._current_color = "gray"
        self._has_badge = False
        self._badge_version = ""
        self._ready = threading.Event()
        self._lock = threading.Lock()
        self._wndproc_ref = WNDPROC(self._wnd_proc)
        self._thread = threading.Thread(target=self._run_loop, name="TrayThread", daemon=True)

    def start(self) -> None:
        self._thread.start()
        self._ready.wait(timeout=3.0)

    def _run_loop(self) -> None:
        hinst = kernel32.GetModuleHandleW(None)
        class_name = f"ClaudeGuardTray_{id(self)}"

        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.lpfnWndProc = self._wndproc_ref
        wc.hInstance = hinst
        wc.lpszClassName = class_name
        user32.RegisterClassExW(ctypes.byref(wc))

        self._hwnd = user32.CreateWindowExW(
            0, class_name, "ClaudeGuardTray", 0,
            0, 0, 0, 0, None, None, hinst, None,
        )

        for name, rgb in STATUS_RGB.items():
            self._icons[name] = _create_tray_icon(rgb, badge=False)
            self._icons[f"{name}:badge"] = _create_tray_icon(rgb, badge=True)

        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self._hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_TRAYICON
        nid.hIcon = self._icons[self._current_color]
        nid.szTip = self._tooltip
        shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))

        self._ready.set()

        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        # 退出前清理托盘图标与 HICON 资源
        del_nid = NOTIFYICONDATAW()
        del_nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        del_nid.hWnd = self._hwnd
        del_nid.uID = 1
        shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(del_nid))

        for hicon in self._icons.values():
            if hicon:
                user32.DestroyIcon(hicon)
        self._icons.clear()

    def _show_popup_menu(self, hwnd: wintypes.HWND) -> None:
        with self._lock:
            menu_items = list(self._menu_items)
        hmenu = user32.CreatePopupMenu()
        if not hmenu:
            return
        try:
            for command, (label, callback) in enumerate(menu_items, start=FIRST_MENU_COMMAND):
                if label is None:
                    user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)
                else:
                    flags = MF_STRING if callback is not None else MF_STRING | MF_GRAYED
                    user32.AppendMenuW(hmenu, flags, command, label)
            pt = wintypes.POINT()
            user32.GetCursorPos(ctypes.byref(pt))
            user32.SetForegroundWindow(hwnd)
            selected = user32.TrackPopupMenu(
                hmenu, TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON | TPM_NONOTIFY | TPM_RETURNCMD,
                pt.x, pt.y, 0, hwnd, None,
            )
            user32.PostMessageW(hwnd, WM_NULL, 0, 0)
        finally:
            user32.DestroyMenu(hmenu)

        index = selected - FIRST_MENU_COMMAND
        if 0 <= index < len(menu_items):
            _, callback = menu_items[index]
            if callback is not None:
                callback()

    def _wnd_proc(self, hwnd: wintypes.HWND, msg: wintypes.UINT, wparam: wintypes.WPARAM, lparam: wintypes.LPARAM) -> int:
        if msg == WM_TRAYICON:
            ev = lparam & 0xFFFF
            if ev in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                self._on_open()
                return 0
            if ev == WM_RBUTTONUP:
                self._show_popup_menu(hwnd)
                return 0
        elif msg == WM_DESTROY:
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _apply_icon_and_tip_locked(self) -> None:
        if not self._hwnd:
            return
        icon_key = f"{self._current_color}:badge" if self._has_badge else self._current_color
        hicon = self._icons.get(icon_key) or self._icons.get(self._current_color)
        if not hicon:
            return
        tip = self._base_tooltip
        if self._has_badge:
            suffix = f" · 有新版 v{self._badge_version}" if self._badge_version else " · 发现新版本"
            max_base = 127 - len(suffix)
            tip = (tip[:max_base] if max_base > 0 else "") + suffix
        self._tooltip = tip[:127]
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self._hwnd
        nid.uID = 1
        nid.uFlags = NIF_ICON | NIF_TIP
        nid.hIcon = hicon
        nid.szTip = self._tooltip
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))

    def update(self, color: str, tooltip: str) -> None:
        """线程安全地更新托盘颜色（green/yellow/red/gray）和悬浮提示。"""
        with self._lock:
            if not self._hwnd or color not in STATUS_RGB:
                return
            self._current_color = color
            self._base_tooltip = tooltip[:127]
            self._apply_icon_and_tip_locked()

    def set_update_badge(self, has_update: bool, version: str = "") -> None:
        """线程安全地切换托盘更新红点与悬浮提示后缀。"""
        with self._lock:
            self._has_badge = bool(has_update)
            self._badge_version = str(version or "").strip().lstrip("vV")
            self._apply_icon_and_tip_locked()

    def set_menu_items(self, menu_items: List[Tuple[Optional[str], Optional[Callable[[], None]]]]) -> None:
        """线程安全地刷新托盘右键菜单项。"""
        with self._lock:
            self._menu_items = list(menu_items)

    def notify(self, title: str, message: str, level: str = "info") -> None:
        """弹出 Windows 系统气泡提醒。"""
        with self._lock:
            if not self._hwnd:
                return
            flag = {"info": NIIF_INFO, "warn": NIIF_WARNING, "error": NIIF_ERROR}.get(level, NIIF_INFO)
            nid = NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
            nid.hWnd = self._hwnd
            nid.uID = 1
            nid.uFlags = NIF_INFO
            nid.szInfoTitle = title[:63]
            nid.szInfo = message[:255]
            nid.dwInfoFlags = flag
            shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))

    def stop(self) -> None:
        if self._hwnd:
            user32.PostMessageW(self._hwnd, WM_CLOSE, 0, 0)
            if threading.current_thread() is not self._thread:
                self._thread.join(timeout=2.0)
