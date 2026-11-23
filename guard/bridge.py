"""WebView2 前后端通信桥接层（GuardBridge）。

设计原则：
- 仅暴露以 JSON 可序列化字典为返回值的公开方法给 `window.pywebview.api`；
- 所有内部状态以下划线开头，避免 pywebview 自省暴露无关对象；
- 通过互斥锁保护系统变更操作，内置后台 60s 看门狗与原生系统托盘联动。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import webbrowser
from collections import deque
from dataclasses import asdict, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Optional

from . import __version__
from .clash_config import PROBE_PORT
from .config import (
    APP_NAME,
    CLASH_VERGE_DIR,
    GuardConfig,
    load_config,
    save_config,
)
from .doctor import PROBE_PATH, TUN_PATH, DoctorReport, check_probe_route, run_doctor
from .firewall import disable_killswitch, enable_killswitch
from .hardening import (
    align_timezone_to_iana,
    clear_webrtc_policies,
    disable_physical_ipv6,
    enable_webrtc_policies,
    get_autostart_enabled,
    kill_claude_desktop,
    lock_physical_dns,
    play_alert_beep,
    restore_physical_dns,
    restore_physical_ipv6,
    restore_timezone,
    run_rescue,
    run_steps,
    set_autostart_enabled,
    StepResult,
)
from .probe import _fast_check_tun_up, probe_fast_local_health
from .purity import PurityReport, run_purity_check
from .sysutil import get_bundle_root, is_admin, relaunch_as_admin, system_change_lock
from .updater import (
    RELEASES_LATEST_URL,
    UpdateInfo,
    apply_update_and_restart,
    check_for_update,
    download_update,
    is_allowed_update_url,
)

PROJECT_ROOT = get_bundle_root()
OVERRIDE_SCRIPT_PATH = PROJECT_ROOT / "clash-verge-override.js"
AUTHOR_DOUYIN_URL = (
    "https://www.douyin.com/user/"
    "MS4wLjABAAAA1Rwt_jH2HH7M3Ra_FcozWkNv5UYuZQtTjJuzCGvIlJQ?from_tab_name=main"
)


class GuardBridge:
    """暴露给前端 WebView 的安全 API 控制器（无开放 TCP 端口，进程内直连）。"""

    def __init__(
        self,
        on_tray_update: Optional[Callable[[str, str], None]] = None,
        on_tray_notify: Optional[Callable[[str, str, str], None]] = None,
        on_push_state: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_request_quit: Optional[Callable[[], None]] = None,
        on_update_badge: Optional[Callable[[bool, str], None]] = None,
    ) -> None:
        self._cfg: GuardConfig = load_config()
        self._admin: bool = is_admin()
        self._last_report: Optional[DoctorReport] = None
        self._last_purity: Optional[PurityReport] = None
        self._last_alert_sig: str = ""
        self._last_fast_fault: str = ""
        self._op_lock = threading.Lock()
        self._purity_lock = threading.Lock()
        self._update_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._logs: Deque[Dict[str, str]] = deque(maxlen=50)
        self._on_tray_update = on_tray_update
        self._on_tray_notify = on_tray_notify
        self._on_push_state = on_push_state
        self._on_request_quit = on_request_quit
        self._on_update_badge = on_update_badge
        self._watchdog_thread: Optional[threading.Thread] = None
        self._update_thread: Optional[threading.Thread] = None
        self._update_info: Optional[UpdateInfo] = None
        self._update_progress: Optional[Dict[str, Any]] = None
        self._update_notified_version: str = ""

        self._append_log("info", f"{APP_NAME} v{__version__} 启动完成（{'管理员模式' if self._admin else '只读普通权限'}）")

    # ------------------------------------------------------------------
    # 内部生命周期与状态构建
    # ------------------------------------------------------------------
    def _append_log(self, level: str, message: str) -> None:
        self._logs.appendleft(
            {
                "time": datetime.now().strftime("%H:%M:%S"),
                "level": level,
                "message": message,
            }
        )

    def _build_payload(self, ok: bool = True, message: str = "") -> Dict[str, Any]:
        return {
            "ok": ok,
            "message": message,
            "app_name": APP_NAME,
            "version": __version__,
            "is_admin": self._admin,
            "config": asdict(self._cfg),
            "report": self._last_report.to_dict() if self._last_report else None,
            "purity": self._last_purity.to_dict() if self._last_purity else None,
            "logs": list(self._logs),
            "clash_dir_exists": CLASH_VERGE_DIR.exists(),
            "autostart_enabled": get_autostart_enabled(),
            "update": self._update_info.to_dict() if self._update_info else None,
            "update_progress": dict(self._update_progress) if self._update_progress else None,
        }

    def _handle_critical_alert(self, title: str, summary: str, sig: str) -> None:
        """去重触发系统通知、可选告警提示音与高危自动关闭 Claude 客户端。"""
        if sig == self._last_alert_sig:
            return
        self._last_alert_sig = sig
        if self._on_tray_notify:
            self._on_tray_notify(title, summary, "error")
        if self._cfg.alert_sound:
            play_alert_beep()
        if self._cfg.auto_kill_claude_on_critical:
            ok, msg = kill_claude_desktop()
            if ok and "安全结束" in msg:
                self._append_log("warn", f"高危联动已触发：{msg}")
                if self._on_tray_notify:
                    self._on_tray_notify(f"{APP_NAME} 已自动熔断 Claude", msg, "warn")

    def _sync_tray(self, report: DoctorReport) -> None:
        tip_ip = report.exit_info.ip or "出口未知"
        tip = f"{APP_NAME} ({report.overall.upper()}) - {tip_ip}"
        if self._on_tray_update:
            self._on_tray_update(report.overall, tip)

        if report.overall == "red":
            fails = [f"{i.name}: {i.summary}" for i in report.items if i.level == "FAIL"]
            sig = "|".join(fails)
            self._handle_critical_alert(f"{APP_NAME} 防泄漏告警", "\n".join(fails[:2]), sig)
        else:
            self._last_alert_sig = ""

    def _run_doctor_unlocked(self) -> DoctorReport:
        self._cfg = load_config()
        report = run_doctor(self._cfg)
        self._last_report = report
        self._sync_tray(report)
        return report

    def _push_to_ui(self) -> None:
        if self._on_push_state:
            self._on_push_state(self._build_payload())

    def _start_watchdog(self) -> None:
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            return
        self._stop_event.clear()

        def _loop() -> None:
            last_full_ts = time.monotonic()
            while not self._stop_event.is_set():
                settings = load_config()
                fast_interval = settings.fast_watch_interval_sec
                full_interval = settings.poll_interval_sec
                if self._stop_event.wait(timeout=fast_interval):
                    break

                # 1. 每 3 秒执行一次纯 Win32 本地快检（~5ms，零 PowerShell，零外网）
                urgent_reason = ""
                fast_fault_detected = False
                try:
                    fast = probe_fast_local_health()
                    faults = []
                    if not fast["tun_up"]:
                        faults.append("TUN 虚拟网卡已断开")
                    fast_fault_detected = bool(faults)
                    if settings.protection_enabled and fast["fw_disabled_hint"]:
                        faults.append("重新核对防火墙档位：" + "、".join(fast["fw_disabled_hint"]))
                    fault_sig = "|".join(faults)
                    if fault_sig and fault_sig != self._last_fast_fault:
                        urgent_reason = "；".join(faults)
                        self._last_fast_fault = fault_sig
                    elif not fault_sig:
                        self._last_fast_fault = ""
                except Exception:
                    urgent_reason = ""

                now = time.monotonic()
                due_full = (now - last_full_ts) >= full_interval
                if not urgent_reason and not due_full:
                    continue

                if self._op_lock.acquire(blocking=False):
                    try:
                        if urgent_reason:
                            self._append_log("error" if fast_fault_detected else "info", f"实时哨兵复核：{urgent_reason}")
                        self._run_doctor_unlocked()
                        last_full_ts = time.monotonic()
                    except Exception as exc:
                        self._append_log("error", f"后台巡检异常: {exc}")
                    finally:
                        self._op_lock.release()
                    self._push_to_ui()

        self._watchdog_thread = threading.Thread(target=_loop, name="GuardWatchdog", daemon=True)
        self._watchdog_thread.start()

        if not (self._update_thread and self._update_thread.is_alive()):
            def _startup_update_check() -> None:
                if self._stop_event.wait(timeout=3.0):
                    return
                self._check_update_internal(silent=True)

            self._update_thread = threading.Thread(target=_startup_update_check, name="GuardUpdateCheck", daemon=True)
            self._update_thread.start()

    def _stop_watchdog(self) -> None:
        self._stop_event.set()

    def _wait_for_operations(self) -> None:
        with self._op_lock:
            pass

    def _require_admin(self, action_name: str) -> Optional[Dict[str, Any]]:
        if not self._admin:
            msg = f"{action_name}需要管理员权限，请点击窗口右下角「以管理员重启」"
            self._append_log("warn", msg)
            return self._build_payload(ok=False, message=msg)
        return None

    # ------------------------------------------------------------------
    # 暴露给前端 JS（window.pywebview.api.*）的公开方法
    # ------------------------------------------------------------------
    def get_initial_state(self) -> Dict[str, Any]:
        """首屏加载立即返回静态状态，避免阻塞窗口首次渲染。"""
        return self._build_payload()

    def run_doctor(self) -> Dict[str, Any]:
        """执行一次完整并发 8 项防泄漏自检。"""
        with self._op_lock:
            if self._stop_event.is_set():
                return self._build_payload(ok=False, message="程序正在退出")
            report = self._run_doctor_unlocked()
            self._append_log(
                "info" if report.overall != "red" else "error",
                f"完成防泄漏自检（耗时 {report.elapsed_ms} ms，状态 {report.overall.upper()}）",
            )
            return self._build_payload(ok=True, message=f"自检完成（{report.elapsed_ms} ms）")

    def _apply_system(
        self, action_name: str, action: Callable[[], list[StepResult]], *, protection_enabled: bool | None = None
    ) -> Dict[str, Any]:
        denied = self._require_admin(action_name)
        if denied:
            return denied
        with self._op_lock:
            with system_change_lock() as acquired:
                if self._stop_event.is_set() or not acquired:
                    return self._build_payload(ok=False, message="系统变更暂不可用，请稍后重试")
                try:
                    self._cfg = load_config()
                    steps = action()
                    if not steps or not all(isinstance(step, StepResult) for step in steps):
                        raise ValueError("未返回系统变更结果")
                except Exception as exc:
                    steps = [StepResult(action_name, False, f"{type(exc).__name__}: {exc}")]
                ok = all(step.ok for step in steps)
                if protection_enabled is not None and (ok or protection_enabled):
                    self._cfg.protection_enabled = protection_enabled and ok
                    try:
                        save_config(self._cfg)
                    except Exception as exc:
                        steps.append(StepResult("保存防护状态", False, f"{type(exc).__name__}: {exc}"))
                failures = [step.label for step in steps if not step.ok]
                for step in steps:
                    self._append_log("ok" if step.ok else "error", step.log())
                ok = not failures
            try:
                self._run_doctor_unlocked()
            except Exception as exc:
                self._last_report = None
                self._append_log("error", f"系统变更后巡检失败：{exc}")
            message = steps[0].message if len(steps) == 1 else (
                f"{action_name}部分失败：{'、'.join(failures)}" if failures else f"{action_name}完成"
            )
            return self._build_payload(ok=ok, message=message)

    def _apply_setting(
        self, label: str, action: Callable[[], tuple[bool, str]], *, protection_enabled: bool | None = None
    ) -> Dict[str, Any]:
        return self._apply_system(label, lambda: run_steps([(label, action)]),
                                  protection_enabled=protection_enabled)

    def enable_all_protection(self) -> Dict[str, Any]:
        return self._apply_system("一键配置防护", lambda: run_steps([
            ("Kill Switch", lambda: enable_killswitch(self._cfg.extra_claude_exes)),
            ("物理网卡 DNS", lock_physical_dns),
            ("物理网卡 IPv6", disable_physical_ipv6),
            ("WebRTC 策略", enable_webrtc_policies),
        ]), protection_enabled=True)

    def toggle_dns_lock(self, enable: bool) -> Dict[str, Any]:
        return self._apply_setting("调整物理网卡 DNS", lock_physical_dns if enable else restore_physical_dns)

    def kill_claude_app(self) -> Dict[str, Any]:
        with self._op_lock:
            ok, msg = kill_claude_desktop()
            self._append_log("ok" if ok else "error", msg)
            self._run_doctor_unlocked()
            return self._build_payload(ok=ok, message=msg)

    def toggle_killswitch(self, enable: bool) -> Dict[str, Any]:
        action = (lambda: enable_killswitch(self._cfg.extra_claude_exes)) if enable else disable_killswitch
        return self._apply_setting("调整 Kill Switch 防火墙", action, protection_enabled=enable)

    def toggle_webrtc(self, enable: bool) -> Dict[str, Any]:
        return self._apply_setting("调整浏览器 WebRTC 策略", enable_webrtc_policies if enable else clear_webrtc_policies)

    def toggle_ipv6(self, disable: bool) -> Dict[str, Any]:
        return self._apply_setting("调整物理网卡 IPv6", disable_physical_ipv6 if disable else restore_physical_ipv6)

    def toggle_ip_monitor(self, enable: bool | None = None) -> Dict[str, Any]:
        """设置 Guard-Probe 测试出口的漂移监控。"""
        with self._op_lock:
            if self._stop_event.is_set():
                return self._build_payload(ok=False, message="程序正在退出")
            self._cfg = load_config()
            if enable is None:
                enable = not self._cfg.monitored_probe_ip
            unchanged_message = "出口漂移监控已开启" if enable else "出口漂移监控已停止"
            if enable == bool(self._cfg.monitored_probe_ip):
                return self._build_payload(message=unchanged_message)

            exit_info = None
            if enable:
                try:
                    exit_info = self._run_doctor_unlocked().exit_info
                except Exception as exc:
                    self._append_log("error", f"开启监控前巡检失败：{exc}")
                    return self._build_payload(ok=False, message="未能核实 Clash 出口 IP，请重新巡检")
                if not exit_info.ip or exit_info.path not in (PROBE_PATH, TUN_PATH):
                    return self._build_payload(ok=False, message="请先完成一次自检并取得有效出口 IP")
            with system_change_lock() as acquired:
                if not acquired or self._stop_event.is_set():
                    return self._build_payload(ok=False, message="系统变更暂不可用，请稍后重试")
                current = load_config()
                self._cfg = current
                if enable == bool(current.monitored_probe_ip):
                    return self._build_payload(message=unchanged_message)
                updated = replace(current, monitored_probe_ip=exit_info.ip if exit_info else "")
                try:
                    save_config(updated)
                except OSError as exc:
                    self._append_log("error", f"保存出口漂移监控失败：{exc}")
                    return self._build_payload(ok=False, message="无法保存出口漂移监控设置，请查看日志")
                self._cfg = updated
                msg = f"已开始监控出口 IP {exit_info.ip}" if exit_info else unchanged_message
                self._append_log("ok", msg)
            try:
                self._run_doctor_unlocked()
            except Exception as exc:
                self._last_report = None
                self._append_log("error", f"更新出口漂移监控后巡检失败：{exc}")
                msg += "。巡检未完成，可点击「立即自检」重试"
            return self._build_payload(message=msg)

    def align_timezone(self) -> Dict[str, Any]:
        def align():
            report = self._last_report
            if not report or report.exit_info.path not in (PROBE_PATH, TUN_PATH) or not report.exit_info.timezone:
                return False, "尚未获取出口 IP 时区，请先执行自检"
            return align_timezone_to_iana(report.exit_info.timezone)

        return self._apply_setting("对齐系统时区", align)

    def restore_timezone(self) -> Dict[str, Any]:
        return self._apply_setting("恢复原系统时区", restore_timezone)

    def run_rescue(self) -> Dict[str, Any]:
        return self._apply_system("紧急恢复", run_rescue, protection_enabled=False)

    def toggle_alert_sound(self, enable: bool) -> Dict[str, Any]:
        """开关红灯突发告警时的 Windows 系统提示音。"""
        with self._op_lock, system_change_lock() as acquired:
            if not acquired or self._stop_event.is_set():
                return self._build_payload(ok=False, message="系统变更暂不可用，请稍后重试")
            self._cfg = load_config()
            self._cfg.alert_sound = bool(enable)
            save_config(self._cfg)
            msg = "已开启突发告警系统提示音" if enable else "已关闭突发告警提示音（仅保留通知弹窗）"
            self._append_log("info", msg)
            return self._build_payload(ok=True, message=msg)

    def toggle_auto_kill_claude(self, enable: bool) -> Dict[str, Any]:
        """开关高危红灯告警时自动安全关闭 Claude 桌面端的联动策略。"""
        with self._op_lock, system_change_lock() as acquired:
            if not acquired or self._stop_event.is_set():
                return self._build_payload(ok=False, message="系统变更暂不可用，请稍后重试")
            self._cfg = load_config()
            self._cfg.auto_kill_claude_on_critical = bool(enable)
            save_config(self._cfg)
            msg = (
                "已开启高危联动：TUN 掉线或出口漂移时自动安全关闭 Claude 桌面端"
                if enable
                else "已关闭高危自动关闭 Claude 联动"
            )
            self._append_log("info", msg)
            return self._build_payload(ok=True, message=msg)

    def toggle_autostart(self, enable: bool) -> Dict[str, Any]:
        """开关当前用户开机静默最小化到托盘守护（仅写 HKCU\\Run，无系统服务）。"""
        with self._op_lock, system_change_lock() as acquired:
            if not acquired or self._stop_event.is_set():
                return self._build_payload(ok=False, message="系统变更暂不可用，请稍后重试")
            ok, msg = set_autostart_enabled(bool(enable))
            self._append_log("ok" if ok else "error", msg)
            return self._build_payload(ok=ok, message=msg)

    def check_ip_purity(self) -> Dict[str, Any]:
        """按已核实回环入口或通用 TUN 通道执行 HTTPS 体检。"""
        with self._purity_lock:
            error = check_probe_route()
            if not error:
                purity = run_purity_check(PROBE_PORT)
            else:
                tun_up, _ = _fast_check_tun_up()
                if not tun_up:
                    self._last_purity = None
                    return self._build_payload(
                        ok=False,
                        message="请先在代理软件中开启 TUN 虚拟网卡后再进行 IP 体检",
                    )
                purity = run_purity_check(None)
            self._last_purity = purity
            if not purity.ip:
                message = "未能获取当前出口 IP，请检查代理节点连通性"
                self._append_log("warn", message)
                return self._build_payload(ok=False, message=message)
            score_txt = f"{purity.fraud_score}/100" if purity.fraud_score is not None else "未知"
            self._append_log(
                {"low": "ok", "high": "error"}.get(purity.risk_level, "warn"),
                f"IP 纯净度体检完成（评级 {purity.grade} · IPPure 风险分 {score_txt} · {purity.elapsed_ms}ms）",
            )
            return self._build_payload(
                ok=True,
                message=f"IP 纯净度评级 {purity.grade}（风险分 {score_txt}，耗时 {purity.elapsed_ms}ms）",
            )

    def get_override_script(self) -> Dict[str, Any]:
        """读取订阅分流体检脚本。"""
        path = OVERRIDE_SCRIPT_PATH
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return {"ok": False, "path": str(path), "content": "", "message": f"无法读取 {path.name}"}
        return {
            "ok": True,
            "path": str(path),
            "content": content,
            "message": "读取成功",
        }

    def open_clash_dir(self) -> Dict[str, Any]:
        """在文件资源管理器中打开 Clash Verge 配置目录（或项目目录）。"""
        target = CLASH_VERGE_DIR if CLASH_VERGE_DIR.exists() else PROJECT_ROOT
        try:
            os.startfile(str(target))  # type: ignore[attr-defined]
            return {"ok": True, "message": f"已打开目录：{target}"}
        except Exception:
            subprocess.Popen(["explorer", str(target)])
            return {"ok": True, "message": f"已打开目录：{target}"}

    def open_author_page(self) -> Dict[str, Any]:
        """在系统默认浏览器中打开作者抖音主页（仅允许内置白名单地址）。"""
        try:
            if not webbrowser.open(AUTHOR_DOUYIN_URL, new=2):
                os.startfile(AUTHOR_DOUYIN_URL)  # type: ignore[attr-defined]
            return {"ok": True, "message": "已在浏览器中打开作者抖音主页"}
        except Exception as exc:
            return {"ok": False, "message": f"无法打开抖音主页：{exc}"}

    def _check_update_internal(self, *, silent: bool) -> UpdateInfo:
        with self._update_lock:
            info = check_for_update(__version__)
            self._update_info = info
            if info.available:
                if self._on_update_badge:
                    self._on_update_badge(True, info.latest_version)
                if info.latest_version != self._update_notified_version:
                    self._update_notified_version = info.latest_version
                    self._append_log("info", f"发现新版本 v{info.latest_version}（当前 v{__version__}）")
                    if self._on_tray_notify:
                        self._on_tray_notify(
                            f"{APP_NAME} 发现新版本 v{info.latest_version}",
                            "点击主界面右上角红点或托盘菜单可一键自动更新。",
                            "info",
                        )
            else:
                if not info.error and self._on_update_badge:
                    self._on_update_badge(False, "")
                if not silent:
                    if info.error:
                        self._append_log("warn", f"检查更新失败：{info.error}")
                    else:
                        self._append_log("info", f"当前已是最新版本 v{__version__}")
        if silent and info.available and not self._stop_event.is_set():
            self._push_to_ui()
        return info

    def check_update(self) -> Dict[str, Any]:
        """检查 GitHub Releases 是否有新版本。"""
        if self._stop_event.is_set():
            return self._build_payload(ok=False, message="程序正在退出")
        info = self._check_update_internal(silent=False)
        if info.error:
            return self._build_payload(ok=False, message=f"检查更新失败：{info.error}")
        if info.available:
            return self._build_payload(ok=True, message=f"发现新版本 v{info.latest_version}")
        return self._build_payload(ok=True, message=f"当前已是最新版本 v{__version__}")

    def install_update(self) -> Dict[str, Any]:
        """流式下载新版本、校验 SHA-256 并触发覆盖重启。"""
        if not self._update_lock.acquire(blocking=False):
            return self._build_payload(ok=False, message="更新任务正在进行中，请稍候")
        try:
            if self._stop_event.is_set():
                return self._build_payload(ok=False, message="程序正在退出")
            info = self._update_info
            if not info or not info.available:
                info = check_for_update(__version__)
                self._update_info = info
                if info.error:
                    return self._build_payload(ok=False, message=f"检查更新失败：{info.error}")
                if not info.available:
                    if self._on_update_badge:
                        self._on_update_badge(False, "")
                    return self._build_payload(ok=True, message=f"当前已是最新版本 v{__version__}")
            if not info.can_self_update:
                return self._build_payload(ok=False, message="当前为源码运行模式，请前往 GitHub Release 手动更新")

            dest_dir = Path(sys.executable).resolve().parent
            self._update_progress = {"stage": "downloading", "downloaded": 0, "total": 0, "percent": 0}
            self._push_to_ui()
            last_push = [0.0]

            def _on_progress(downloaded: int, total: int) -> None:
                now = time.monotonic()
                pct = int(downloaded * 100 / total) if total > 0 else 0
                self._update_progress = {
                    "stage": "downloading",
                    "downloaded": downloaded,
                    "total": total,
                    "percent": min(100, pct),
                }
                if (now - last_push[0]) >= 0.25 or (total > 0 and downloaded >= total):
                    last_push[0] = now
                    self._push_to_ui()

            staged = download_update(info, dest_dir, progress_cb=_on_progress)
            self._update_progress = {"stage": "verifying", "downloaded": 1, "total": 1, "percent": 100}
            self._push_to_ui()

            ok, msg = apply_update_and_restart(staged)
            if not ok:
                staged.unlink(missing_ok=True)
                self._update_progress = None
                self._append_log("error", f"自动更新失败：{msg}")
                self._push_to_ui()
                return self._build_payload(ok=False, message=msg)

            self._update_progress = {"stage": "restarting", "downloaded": 1, "total": 1, "percent": 100}
            self._append_log("ok", f"已校验 v{info.latest_version} 更新包，正在自动覆盖并重启")
            self._push_to_ui()
            if self._on_request_quit:
                threading.Timer(0.2, self._on_request_quit).start()
            return self._build_payload(ok=True, message=msg)
        except Exception as exc:
            self._update_progress = None
            self._append_log("error", f"自动更新失败：{exc}")
            self._push_to_ui()
            return self._build_payload(ok=False, message=f"自动更新失败：{exc}")
        finally:
            self._update_lock.release()

    def open_release_page(self) -> Dict[str, Any]:
        """在浏览器中打开允许的 GitHub Release 下载页。"""
        candidate = (
            self._update_info.release_url
            if self._update_info and self._update_info.release_url
            else RELEASES_LATEST_URL
        )
        url = candidate if is_allowed_update_url(candidate) else RELEASES_LATEST_URL
        try:
            if not webbrowser.open(url, new=2):
                os.startfile(url)  # type: ignore[attr-defined]
            return {"ok": True, "message": "已在浏览器中打开 GitHub Release 页面"}
        except Exception as exc:
            return {"ok": False, "message": f"无法打开下载页：{exc}"}

    def elevate(self) -> Dict[str, Any]:
        """触发 UAC 以管理员身份重启当前应用（带 --handoff 参数平滑交接单实例锁）。"""
        if relaunch_as_admin(str(PROJECT_ROOT / "app.py"), extra_args=["--handoff"]):
            if self._on_request_quit:
                threading.Timer(0.15, self._on_request_quit).start()
            return {"ok": True, "message": "正在以管理员身份重启..."}
        return {"ok": False, "message": "未完成 UAC 管理员提权"}

    def quit_app(self) -> Dict[str, Any]:
        """彻底退出桌面程序与托盘图标。"""
        if self._on_request_quit:
            threading.Timer(0.05, self._on_request_quit).start()
        return {"ok": True, "message": "正在退出"}


def encode_js_push(payload: Dict[str, Any]) -> str:
    """安全序列化状态推送脚本，确保传入 evaluate_js 的数据不会破坏语法。"""
    encoded = json.dumps(payload, ensure_ascii=False)
    return f"window.__onGuardPush && window.__onGuardPush({encoded});"
