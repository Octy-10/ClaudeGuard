"""macOS 的 WKWebView 窗口与 AppKit 菜单栏。"""

from __future__ import annotations

import threading

import AppKit
import webview
from objc import IBAction
from PyObjCTools import AppHelper

from . import __version__
from .bridge import PROJECT_ROOT, GuardBridge, encode_js_push
from .config import APP_NAME


class GuardMenuActions(AppKit.NSObject):
    @IBAction
    def showGuard_(self, sender):
        self.window.restore()
        self.window.show()

    @IBAction
    def scanGuard_(self, sender):
        self.showGuard_(sender)
        threading.Thread(target=self.scan, name="MacMenuScan", daemon=True).start()

    @IBAction
    def hideGuard_(self, sender):
        self.window.hide()

    @IBAction
    def quitGuard_(self, sender):
        self.quit()


def run_app(start_minimized: bool = False) -> None:
    AppKit.NSApplication.sharedApplication()
    status_bar = AppKit.NSStatusBar.systemStatusBar()
    status_item = status_bar.statusItemWithLength_(AppKit.NSVariableStatusItemLength)
    button = status_item.button()
    button.setTitle_("Guard")
    button.setToolTip_(APP_NAME)
    quitting = threading.Event()

    def update_status(color: str, tooltip: str) -> None:
        def update() -> None:
            if quitting.is_set():
                return
            button.setTitle_({"red": "Guard !", "yellow": "Guard ·", "green": "Guard ✓"}.get(color, "Guard"))
            button.setToolTip_(tooltip)

        AppHelper.callAfter(update)

    def push_state(payload: dict) -> None:
        if not quitting.is_set() and window.events.loaded.is_set():
            try:
                window.evaluate_js(encode_js_push(payload))
            except Exception:
                pass

    def quit_app() -> None:
        quitting.set()
        bridge._stop_watchdog()
        window.destroy()

    def notify(title: str, message: str, level: str) -> None:
        threading.Thread(
            target=push_state, args=({"message": f"{title}：{message}", "ok": level != "error", "tray_action": True},),
            name="MacStatusNotice", daemon=True,
        ).start()

    bridge = GuardBridge(on_tray_update=update_status, on_tray_notify=notify, on_push_state=push_state,
                         on_request_quit=quit_app)
    window = webview.create_window(
        title=f"{APP_NAME}  v{__version__}",
        url=(PROJECT_ROOT / "web" / "index.html").as_uri(),
        js_api=bridge,
        width=1100,
        height=800,
        min_size=(660, 460),
        hidden=start_minimized,
    )
    def run_scan() -> None:
        try:
            payload = bridge.run_doctor()
        except Exception as exc:
            bridge._append_log("error", f"菜单栏巡检失败：{exc}")
            payload = bridge._build_payload(ok=False, message="巡检失败，请查看日志")
        push_state({**payload, "tray_action": True})

    actions = GuardMenuActions.alloc().init()
    actions.window = window
    actions.scan = run_scan
    actions.quit = quit_app
    menu = AppKit.NSMenu.alloc().init()
    for label, selector in (
        ("打开主界面", "showGuard:"), ("隐藏主界面", "hideGuard:"),
        ("立即自检", "scanGuard:"), ("退出 Claude Guard", "quitGuard:"),
    ):
        item = AppKit.NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(label, selector, "")
        item.setTarget_(actions)
        menu.addItem_(item)
    status_item.setMenu_(menu)

    try:
        webview.start(bridge._start_watchdog, private_mode=False)
    finally:
        quitting.set()
        bridge._stop_watchdog()
        status_bar.removeStatusItem_(status_item)
