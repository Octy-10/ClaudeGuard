"""Claude Guard 主入口。

用法：
  pythonw app.py              启动托盘桌面程序
  pythonw app.py --minimized  静默最小化到系统托盘启动
  python  app.py --rescue     命令行紧急恢复（清除防火墙/WebRTC/IPv6/时区改动）
  python  app.py --doctor     命令行输出一次完整防泄漏自检报告
"""

from __future__ import annotations

import argparse
import sys

from guard.config import APP_NAME, load_config, save_config
from guard.doctor import run_doctor
from guard.hardening import run_rescue
from guard.sysutil import SingleInstanceLock, is_admin, relaunch_as_admin, show_info_dialog, system_change_lock
from guard.updater import cleanup_update_artifacts


def _cli_doctor() -> int:
    cfg = load_config()
    report = run_doctor(cfg)
    print(f"=== Claude Guard 防泄漏自检 ({report.checked_at} · {report.elapsed_ms}ms) | 状态: {report.overall.upper()} ===")
    if report.exit_info.ip:
        ex = report.exit_info
        print(f"出口 IP: {ex.ip} ({ex.country_code} {ex.country} {ex.city} | {ex.isp} | TZ={ex.timezone})")
    else:
        print(f"出口 IP: 获取失败 ({report.exit_info.error})")
    print("-" * 72)
    for item in report.items:
        print(f"[{item.level:4s}] {item.name}: {item.summary}")
        if item.detail:
            print(f"       -> {item.detail}")
    return 0 if report.overall != "red" else 2


def _cli_rescue() -> int:
    if not is_admin():
        print("紧急恢复需要管理员权限，正在请求 UAC 提权...")
        if relaunch_as_admin():
            return 0
        print("未能获得管理员权限，请右键以管理员身份运行 rescue.bat。")
        return 1
    with system_change_lock() as acquired:
        if not acquired:
            print("系统配置正在变更，请稍后重试。")
            return 1
        steps = run_rescue()
        for step in steps:
            print(step.log())
        if not all(step.ok for step in steps):
            return 1
        cfg = load_config()
        cfg.protection_enabled = False
        save_config(cfg)
        return 0


def main() -> int:
    cleanup_update_artifacts()
    parser = argparse.ArgumentParser(description="Claude Guard 轻量透明防泄漏托盘工具")
    parser.add_argument("--minimized", action="store_true", help="启动后直接隐藏到右下角托盘")
    parser.add_argument("--doctor", action="store_true", help="仅在命令行执行一次防泄漏自检")
    parser.add_argument("--rescue", action="store_true", help="执行紧急网络恢复并退出")
    parser.add_argument("--handoff", action="store_true", help="内部参数：UAC 提权交接时短暂等待旧实例释放单实例锁")
    args = parser.parse_args()

    if args.doctor:
        return _cli_doctor()
    if args.rescue:
        return _cli_rescue()

    lock = SingleInstanceLock()
    if not lock.acquire(wait_sec=3.0 if args.handoff else 0.0):
        show_info_dialog(APP_NAME, "Claude Guard 已在运行中。\n请查看右下角系统托盘图标并点击打开主界面。")
        return 0

    try:
        from guard.ui import GuardApp

        app = GuardApp(start_minimized=args.minimized)
        app.run()
        return 0
    finally:
        lock.release()


if __name__ == "__main__":
    sys.exit(main())
