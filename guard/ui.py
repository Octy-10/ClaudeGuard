"""Claude Guard 现代桌面窗口宿主（pywebview + Edge WebView2 + 自绘标题栏 + 系统托盘）。"""

from __future__ import annotations

import ctypes
import threading
from ctypes import wintypes
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import webview

from . import __version__
from .bridge import GuardBridge, encode_js_push
from .config import APP_NAME, STATE_DIR
from .sysutil import get_bundle_root, is_admin
from .tray import SystemTrayIcon

_BUNDLE_ROOT = get_bundle_root()
WEB_DIR = _BUNDLE_ROOT / "web"
INDEX_HTML = WEB_DIR / "index.html"
ICON_FILE = _BUNDLE_ROOT / "assets" / "icon.ico"
SHELL_COLOR = "#F8F8F8"

# Keep a native sizing border and system commands around the custom caption.
GWL_STYLE = -16
WS_THICKFRAME = 0x00040000
WS_SYSMENU = 0x00080000
WS_MINIMIZEBOX = 0x00020000
WS_MAXIMIZEBOX = 0x00010000
SWP_REFRESH_FRAME = 0x0037  # FRAMECHANGED | NOACTIVATE | NOZORDER | NOMOVE | NOSIZE
WM_NCCALCSIZE = 0x0083
WM_NCDESTROY = 0x0082
DWMWA_USE_IMMERSIVE_DARK_MODE = 20
DWMWA_WINDOW_CORNER_PREFERENCE = 33
DWMWA_BORDER_COLOR = 34
DWMWCP_ROUND = 2
FRAME_COLOR_LIGHT = 0x00DFDFDF  # COLORREF for #DFDFDF
FRAME_COLOR_DARK = 0x002E2E2E   # COLORREF for #2E2E2E

WM_SETICON = 0x0080
ICON_SMALL = 0
ICON_BIG = 1
IMAGE_ICON = 1
LR_LOADFROMFILE = 0x0010
SM_CXICON = 11
SM_CXSMICON = 49

_SUBCLASSPROC = ctypes.WINFUNCTYPE(
    ctypes.c_ssize_t,
    wintypes.HWND,
    wintypes.UINT,
    wintypes.WPARAM,
    wintypes.LPARAM,
    ctypes.c_size_t,
    ctypes.c_size_t,
)


class _RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


class _NCCALCSIZE_PARAMS(ctypes.Structure):
    _fields_ = [("rgrc", _RECT * 3), ("lppos", ctypes.c_void_p)]


_user32 = ctypes.windll.user32
_user32.LoadImageW.argtypes = [
    wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
    ctypes.c_int, ctypes.c_int, wintypes.UINT,
]
_user32.LoadImageW.restype = wintypes.HANDLE
_user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_user32.SendMessageW.restype = ctypes.c_ssize_t
_user32.GetSystemMetrics.argtypes = [ctypes.c_int]
_user32.GetSystemMetrics.restype = ctypes.c_int
_user32.IsZoomed.argtypes = [wintypes.HWND]
_user32.IsZoomed.restype = wintypes.BOOL
_user32.IsIconic.argtypes = [wintypes.HWND]
_user32.IsIconic.restype = wintypes.BOOL
_user32.BringWindowToTop.argtypes = [wintypes.HWND]
_user32.BringWindowToTop.restype = wintypes.BOOL
_user32.SetForegroundWindow.argtypes = [wintypes.HWND]
_user32.SetForegroundWindow.restype = wintypes.BOOL

_comctl32 = ctypes.windll.comctl32
_comctl32.SetWindowSubclass.argtypes = [wintypes.HWND, _SUBCLASSPROC, ctypes.c_size_t, ctypes.c_size_t]
_comctl32.SetWindowSubclass.restype = wintypes.BOOL
_comctl32.RemoveWindowSubclass.argtypes = [wintypes.HWND, _SUBCLASSPROC, ctypes.c_size_t]
_comctl32.RemoveWindowSubclass.restype = wintypes.BOOL
_comctl32.DefSubclassProc.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_comctl32.DefSubclassProc.restype = ctypes.c_ssize_t


def _frameless_subclass_proc(hwnd, msg, wparam, lparam, uid, _refdata):
    """消除 WS_THICKFRAME 在无边框窗口顶部产生的 7px 非客户区黑条，同时保留原生缩放/贴靠与圆角。"""
    if msg == WM_NCCALCSIZE and wparam:
        params = _NCCALCSIZE_PARAMS.from_address(lparam)
        orig_top = params.rgrc[0].top
        ret = _comctl32.DefSubclassProc(hwnd, msg, wparam, lparam)
        if not _user32.IsZoomed(hwnd):
            params.rgrc[0].top = orig_top
        return ret
    if msg == WM_NCDESTROY:
        _comctl32.RemoveWindowSubclass(hwnd, _FRAMELESS_PROC_REF, uid)
    return _comctl32.DefSubclassProc(hwnd, msg, wparam, lparam)


_FRAMELESS_PROC_REF = _SUBCLASSPROC(_frameless_subclass_proc)


APP_USER_MODEL_ID = "ClaudeGuard.Desktop.App"


def _set_app_user_model_id() -> None:
    """为进程设置独立 AppUserModelID，避免 Win11 任务栏沿用 pythonw.exe 默认图标。"""
    try:
        shell32 = ctypes.windll.shell32
        shell32.SetCurrentProcessExplicitAppUserModelID.argtypes = [wintypes.LPCWSTR]
        shell32.SetCurrentProcessExplicitAppUserModelID.restype = ctypes.c_long
        shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
    except Exception:
        pass


def _apply_window_icon(hwnd: wintypes.HWND, native_form: Any = None) -> list[int]:
    """为无边框窗口挂上品牌图标，任务栏与 Alt+Tab 均显示 Claude 盾牌图标。"""
    if not ICON_FILE.exists():
        return []
    path = str(ICON_FILE)
    if native_form is not None:
        try:
            import clr  # type: ignore[import-not-found]
            clr.AddReference("System.Drawing")
            import System.Drawing as _sd  # type: ignore[import-not-found]
            native_form.ShowIcon = True
            native_form.Icon = _sd.Icon(path)
        except Exception:
            pass
    icons: list[int] = []
    for metric, slot in ((SM_CXICON, ICON_BIG), (SM_CXSMICON, ICON_SMALL)):
        size = _user32.GetSystemMetrics(metric)
        hicon = _user32.LoadImageW(None, path, IMAGE_ICON, size, size, LR_LOADFROMFILE)
        if hicon:
            _user32.SendMessageW(hwnd, WM_SETICON, slot, hicon)
            icons.append(int(hicon))
    return icons


class GuardApp:
    """协调 WebView2 窗口、GuardBridge API 与 Windows 原生系统托盘。"""

    def __init__(self, start_minimized: bool = False) -> None:
        self._start_minimized = start_minimized
        self._force_quit = False
        self._hide_notified = False
        self._tray_action_lock = threading.Lock()
        self._window: Optional[webview.Window] = None
        self._tray: Optional[SystemTrayIcon] = None
        self._window_icons: list[int] = []

        self._bridge = GuardBridge(
            on_tray_update=self._update_tray,
            on_tray_notify=self._notify_tray,
            on_push_state=self._push_state_to_web,
            on_request_quit=self.quit_app,
            on_update_badge=self._on_update_badge,
        )

    def _update_tray(self, color: str, tooltip: str) -> None:
        if self._tray:
            self._tray.update(color, tooltip)

    def _notify_tray(self, title: str, message: str, level: str) -> None:
        if self._tray:
            self._tray.notify(title, message, level=level)

    def _on_update_badge(self, available: bool, version: str) -> None:
        if self._tray:
            self._tray.set_update_badge(available, version)
            self._tray.set_menu_items(
                self._tray_menu_items(is_admin(), update_version=version if available else "")
            )

    def _open_update_modal_from_tray(self) -> None:
        self.show_window()
        self._push_state_to_web({"open_update_modal": True})

    def _push_state_to_web(self, payload: Dict[str, Any]) -> None:
        if not self._window or self._force_quit:
            return
        try:
            self._window.evaluate_js(encode_js_push(payload))
        except Exception:
            pass

    def _tray_action_async(self, label: str, action: Callable[[], Dict[str, Any]]) -> None:
        """运行一个托盘操作，并在窗口隐藏时也反馈结果。"""
        if self._force_quit:
            return
        if not self._tray_action_lock.acquire(blocking=False):
            self._notify_tray(APP_NAME, "已有托盘操作正在执行，请稍候。", "warn")
            return

        def _worker() -> None:
            try:
                start_msg = f"正在执行「{label}」…"
                self._notify_tray(APP_NAME, start_msg, "info")
                self._push_state_to_web({"ok": True, "message": start_msg, "tray_action": True})
                try:
                    payload = action()
                except Exception as exc:
                    message = f"「{label}」失败，请在日志中查看原因。"
                    self._bridge._append_log("error", f"托盘操作 {label} 失败：{exc}")
                    payload = {"ok": False, "message": message}
                if self._force_quit:
                    return
                message = payload.get("message") or f"「{label}」已结束。"
                self._notify_tray(APP_NAME, message, "error" if payload.get("ok") is False else "info")
                self._push_state_to_web({**payload, "message": message, "tray_action": True})
            finally:
                self._tray_action_lock.release()

        try:
            threading.Thread(target=_worker, name="GuardTrayAction", daemon=True).start()
        except RuntimeError as exc:
            self._tray_action_lock.release()
            self._bridge._append_log("error", f"无法启动托盘操作 {label}：{exc}")
            self._notify_tray(APP_NAME, f"无法启动「{label}」，请查看日志。", "error")

    def _tray_menu_items(
        self, admin: bool, update_version: str = ""
    ) -> list[tuple[str | None, Callable[[], None] | None]]:
        def action(label: str, callback: Callable[[], Dict[str, Any]], *, privileged: bool = False):
            if privileged and not admin:
                return label + "（需管理员权限）", None
            return label, lambda: self._tray_action_async(label, callback)

        items: list[tuple[str | None, Callable[[], None] | None]] = [
            ("打开主界面", self.show_window),
            action("立即运行防泄漏自检", self._bridge.run_doctor),
            (None, None),
            action("开启严格防泄漏保护", self._bridge.enable_all_protection, privileged=True),
            action("关闭防火墙断网锁", lambda: self._bridge.toggle_killswitch(False), privileged=True),
            action("紧急恢复网络 (Rescue)", self._bridge.run_rescue, privileged=True),
            (None, None),
        ]
        if update_version:
            clean_ver = update_version.lstrip("vV")
            items.append((f"发现新版本 v{clean_ver}（点击更新）", self._open_update_modal_from_tray))
        items.append(action("检查更新", self._bridge.check_update))
        if not admin:
            items.append(action("以管理员身份重启", self._bridge.elevate))
        items.append(("退出程序", lambda: threading.Thread(target=self.quit_app).start()))
        return items

    def show_window(self) -> None:
        if not self._window:
            return
        try:
            native = getattr(self._window, "native", None)
            hwnd = wintypes.HWND(native.Handle.ToInt64()) if native is not None else None
            if hwnd and _user32.IsIconic(hwnd):
                self._window.restore()
            self._window.show()
            if hwnd:
                _user32.BringWindowToTop(hwnd)
                _user32.SetForegroundWindow(hwnd)
        except Exception:
            pass

    def _on_closing(self) -> bool:
        if self._force_quit:
            return True
        if self._window:
            try:
                self._window.hide()
            except Exception:
                pass
        if not self._hide_notified and self._tray:
            self._hide_notified = True
            self._tray.notify(APP_NAME, "已最小化到系统托盘持续监控；右键托盘图标可退出。")
        return False

    def _apply_dwm_theme(self, dark: bool) -> None:
        if not self._window or not getattr(self._window, "native", None):
            return
        try:
            hwnd = ctypes.c_void_p(self._window.native.Handle.ToInt64())
            set_attribute = ctypes.windll.dwmapi.DwmSetWindowAttribute
            for attribute, value in (
                (DWMWA_USE_IMMERSIVE_DARK_MODE, 1 if dark else 0),
                (DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND),
                (DWMWA_BORDER_COLOR, FRAME_COLOR_DARK if dark else FRAME_COLOR_LIGHT),
            ):
                data = ctypes.c_uint32(value)
                set_attribute(hwnd, attribute, ctypes.byref(data), ctypes.sizeof(data))
        except Exception:
            pass

    def set_theme_frame(self, dark: bool) -> bool:
        """供前端切换日间/夜间主题时同步 Win11 原生窗口边框与暗色属性。"""
        self._apply_dwm_theme(bool(dark))
        return True

    def _prepare_frame(self) -> None:
        hwnd = wintypes.HWND(self._window.native.Handle.ToInt64())
        _comctl32.SetWindowSubclass(hwnd, _FRAMELESS_PROC_REF, 1, 0)
        style = _user32.GetWindowLongW(hwnd, GWL_STYLE)
        _user32.SetWindowLongW(hwnd, GWL_STYLE, style | WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX)
        _user32.SetWindowPos(hwnd, None, 0, 0, 0, 0, SWP_REFRESH_FRAME)
        self._window_icons = _apply_window_icon(hwnd, self._window.native)
        self._apply_dwm_theme(False)

    def window_command(self, action: str) -> bool:
        """Dispatch only the system commands available on the caption."""
        hwnd = ctypes.c_void_p(self._window.native.Handle.ToInt64())
        maximized = bool(ctypes.windll.user32.IsZoomed(hwnd))
        if action == "maximize":
            if maximized:
                self._window.restore()
            else:
                self._window.maximize()
        elif action == "minimize":
            self._window.minimize()
        elif action == "close":
            self._on_closing()
        return bool(ctypes.windll.user32.IsZoomed(hwnd))

    def _on_window_state(self) -> None:
        if self._window and self._window.events.loaded.is_set() and not self._force_quit:
            self._window.evaluate_js("window.syncCaption?.()")

    def _on_loaded(self) -> None:
        if self._start_minimized and self._window:
            self._window.hide()
        self._bridge._start_watchdog()

    def quit_app(self) -> None:
        if self._force_quit:
            return
        self._force_quit = True
        self._bridge._stop_watchdog()
        self._bridge._wait_for_operations()
        if self._tray:
            self._tray.stop()
        if self._window:
            try:
                self._window.destroy()
            except Exception:
                pass

    def run(self) -> None:
        if not INDEX_HTML.exists():
            raise FileNotFoundError(f"未找到前端入口文件: {INDEX_HTML}")

        _set_app_user_model_id()
        admin = is_admin()
        self._tray = SystemTrayIcon(
            tooltip=f"{APP_NAME} — 初始化自检中...",
            on_open=self.show_window,
            menu_items=self._tray_menu_items(admin),
        )
        self._tray.start()

        STATE_DIR.mkdir(parents=True, exist_ok=True)
        self._window = webview.create_window(
            title=f"{APP_NAME}  v{__version__}",
            url=INDEX_HTML.as_uri(),
            js_api=self._bridge,
            width=1100,
            height=800,
            min_size=(660, 460),
            frameless=True,
            easy_drag=False,
            background_color=SHELL_COLOR,
        )
        self._window.events.closing += self._on_closing
        self._window.expose(self.window_command, self.set_theme_frame)
        self._window.events.before_show += self._prepare_frame
        self._window.events.maximized += self._on_window_state
        self._window.events.restored += self._on_window_state
        self._window.events.loaded += self._on_loaded

        try:
            wv_dir = STATE_DIR / ("webview2-admin" if admin else "webview2-user")
            webview.start(
                gui="edgechromium",
                private_mode=False,
                storage_path=str(wv_dir),
                debug=False,
                icon=str(ICON_FILE) if ICON_FILE.exists() else None,
            )
        finally:
            self._bridge._stop_watchdog()
            if self._tray:
                self._tray.stop()
