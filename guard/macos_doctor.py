"""macOS 网络、系统设置及已注册的防护状态。"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from . import macos_protection as protection
from .clash_config import PROBE_PORT
from .config import GuardConfig
from .doctor import (
    PROBE_PATH, CheckItem, DoctorReport, ExitInfo, QuickStates,
    _audit_clash_verge_config, _check_exit_ip, query_exit_info,
)
from .macos import (
    MIHOMO_NAMES, default_dns_servers, default_route_interface, is_tunnel_interface, process_paths, timezone_name,
)


def run_macos_doctor(cfg: GuardConfig) -> DoctorReport:
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="MacDoctor") as pool:
        route = pool.submit(default_route_interface)
        dns = pool.submit(default_dns_servers)
        processes = pool.submit(process_paths)
        settings = pool.submit(protection.settings_command, "status")
        firewall_state = protection.filter_status()
        policies = protection.host_command("webrtc-status").get("browsers", {})
        clash = _audit_clash_verge_config(require_tun_dns=False)
        if clash.level == "PASS":
            exit_info = query_exit_info(PROBE_PORT, PROBE_PATH)
        else:
            exit_info = ExitInfo(error="请先配置并核实 Clash Guard-Probe 回环入口")
        interface = route.result()
        dns_servers = dns.result()
        paths = processes.result()
        network_settings = settings.result()

    tun_up = is_tunnel_interface(interface)
    if tun_up:
        tun = CheckItem("tun", "系统路由", "WARN", f"IPv4 样本路由经过 {interface}", "macOS 的 utun 可由多个系统服务使用，归属未核实。")
    elif interface:
        tun = CheckItem("tun", "系统路由", "WARN", f"IPv4 样本路由未经过 TUN（{interface}）", "通过 Guard 启动的 Claude Desktop 使用独立本机入口。")
    else:
        tun = CheckItem("tun", "系统路由", "UNKNOWN", "无法读取 IPv4 样本路由")

    current_tz = timezone_name()
    dns_summary = ", ".join(dns_servers) or "未取得系统默认解析器"
    firewall_on = firewall_state.get("active") is True and firewall_state.get("configured") is True
    if firewall_on:
        relay_error = protection.app_relay_issue()
        firewall_item = CheckItem("killswitch", "Claude Desktop 断网锁", "FAIL" if relay_error else "PASS",
                                  relay_error or "已核对网络扩展和 Claude 专用入口",
                                  "覆盖 Claude Desktop 套接字和已知地址段的物理出站。")
    elif firewall_state.get("ok") is not True or firewall_state.get("active") is None:
        firewall_item = CheckItem("killswitch", "Claude Desktop 断网锁", "UNKNOWN", "无法核实网络扩展", firewall_state.get("message", ""))
    elif firewall_state.get("configured") or cfg.protection_enabled:
        firewall_item = CheckItem("killswitch", "Claude Desktop 断网锁", "FAIL", "未核实当前版本的网络扩展已启用", "安装新版本后，可重新开启断网锁以更新系统扩展。")
    else:
        firewall_item = CheckItem("killswitch", "Claude Desktop 断网锁", "WARN", "断网锁未配置")

    services = network_settings.get("services", [])
    known_network_settings = bool(network_settings.get("ok") and services)
    dns_locked = bool(network_settings.get("dns")) if known_network_settings else None
    ipv6_disabled = bool(network_settings.get("ipv6")) if known_network_settings else None
    webrtc_ok = bool(policies) and all(policies.values())
    matched_timezone = bool(current_tz and exit_info.timezone and current_tz == exit_info.timezone)
    items = [
        tun,
        _check_exit_ip(exit_info, cfg),
        clash,
        firewall_item,
        CheckItem("dns_lock", "物理网络服务 DNS", "PASS" if dns_locked else "WARN" if dns_locked is False else "UNKNOWN",
                  "当前网络位置已保存指定的 DNS" if dns_locked else f"系统默认 DNS · {dns_summary}",
                  "实际解析可能受多个网络服务、加密 DNS 和应用自身策略影响。"),
        CheckItem("ipv6", "物理网络服务 IPv6", "PASS" if ipv6_disabled else "WARN" if ipv6_disabled is False else "UNKNOWN",
                  "当前网络位置的受管服务已停用 IPv6" if ipv6_disabled else "IPv6 停用状态尚未满足"),
        CheckItem("webrtc", "浏览器 WebRTC 策略", "PASS" if webrtc_ok else "WARN" if policies else "UNKNOWN",
                  "已核实已发现的浏览器使用受管策略" if webrtc_ok else "检查 Chrome、Edge 或 Firefox 的受管策略",
                  "、".join(f"{browser} {'已核实' if active else '待配置'}" for browser, active in policies.items())),
        CheckItem("timezone", "系统时区", "PASS" if matched_timezone else "WARN" if current_tz else "UNKNOWN",
                  current_tz or "无法读取系统时区", f"测试出口时区 {exit_info.timezone}" if exit_info.timezone else ""),
    ]
    mihomo = any(path.rsplit("/", 1)[-1] in MIHOMO_NAMES for path in paths or [])
    claude_count = sum(path.endswith("/Claude.app/Contents/MacOS/Claude") for path in paths or [])
    if paths is None:
        processes_item = CheckItem("processes", "本机进程", "UNKNOWN", "无法读取本机进程列表")
    elif mihomo:
        processes_item = CheckItem("processes", "本机进程", "PASS", "已识别 Clash Verge Mihomo 进程")
    else:
        processes_item = CheckItem("processes", "本机进程", "WARN", "未识别到 Clash Verge Mihomo 进程")
    items.append(processes_item)

    return DoctorReport(
        checked_at=datetime.now().strftime("%H:%M:%S"),
        overall="red" if any(item.level == "FAIL" for item in items) else "yellow",
        exit_info=exit_info,
        tun_up=tun_up,
        mihomo_running=mihomo,
        elapsed_ms=int((time.perf_counter() - start) * 1000),
        states=QuickStates(
            firewall_active=firewall_on, firewall_known=bool(firewall_state.get("ok") and firewall_state.get("active") is not None),
            dns_summary=dns_summary, dns_locked=bool(dns_locked), ipv6_physical_disabled=ipv6_disabled,
            webrtc_ok=webrtc_ok, timezone_current=current_tz, timezone_expected=exit_info.timezone,
            timezone_matched=matched_timezone, claude_proc_count=claude_count, physical_adapters=services,
        ),
        items=items,
    )
