"""防泄漏深度自检（Doctor）规则引擎与并发调度器。

架构职责（SoC）：
- 底层系统采集 -> `guard/probe.py`（注册表 0ms + 单次 PowerShell 快照）
- 网络请求与代理回退 -> `guard/net.py`
- 本模块专职数据结构、9 项独立基线纯函数评估与并发调度。
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .clash_config import PROBE_PORT, read_config, subscription_probe_issues, tun_dns_issues
from .config import (
    CLASH_VERGE_RUNTIME_YAML,
    CONFLICT_PROCESSES,
    IANA_TO_WINDOWS_TZ,
    LOCKED_DNS_SERVERS,
    GuardConfig,
)
from .firewall import KillSwitchStatus, get_status as get_firewall_status
from .hardening import (
    WebRtcPolicyState,
    get_current_windows_timezone,
    get_webrtc_policy_state,
)
from .net import canonical_ip, fetch_ip_info, fetch_json, verify_proxy_listener
from .probe import check_old_hklm_run, normalize_list, probe_system_snapshot

# 保留内部别名以便单测直接 mock
_probe_system_snapshot = probe_system_snapshot
_check_old_hklm_run = check_old_hklm_run


@dataclass
class CheckItem:
    id: str
    name: str
    level: str  # "PASS" | "WARN" | "FAIL" | "UNKNOWN"
    summary: str
    detail: str = ""


PROBE_PATH = "clash-probe-listener"


@dataclass
class ExitInfo:
    ip: str = ""
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    asn: str = ""
    timezone: str = ""
    is_proxy: Optional[bool] = None
    is_hosting: Optional[bool] = None
    is_mobile: Optional[bool] = None
    error: str = ""
    path: str = ""


@dataclass
class QuickStates:
    """供前端快捷开关卡片直接绑定的结构化状态。"""

    firewall_active: bool = False
    firewall_rule_count: int = 0
    firewall_known: bool = False
    dns_locked: bool = False
    dns_summary: str = ""
    webrtc_ok: bool = False
    ipv6_physical_disabled: Optional[bool] = None
    ipv6_leaked_ip: str = ""
    timezone_current: str = ""
    timezone_expected: str = ""
    timezone_matched: bool = False
    claude_proc_count: int = 0
    physical_adapters: List[str] = field(default_factory=list)


@dataclass
class DoctorReport:
    checked_at: str
    overall: str  # "green" | "yellow" | "red"
    exit_info: ExitInfo
    tun_up: bool
    mihomo_running: bool
    elapsed_ms: int = 0
    states: QuickStates = field(default_factory=QuickStates)
    items: List[CheckItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def query_exit_info(proxy_port: int = PROBE_PORT) -> ExitInfo:
    data, error = fetch_ip_info(proxy_port)
    if not data:
        return ExitInfo(error=error)
    return ExitInfo(
        ip=canonical_ip(data.get("ip")),
        country=str(data.get("country_name") or ""),
        country_code=str(data.get("country_code") or "").upper(),
        region=str(data.get("region") or ""),
        city=str(data.get("city") or ""),
        isp=str(data.get("org") or ""),
        asn=str(data.get("asn") or ""),
        timezone=str(data.get("timezone") or ""),
        path=PROBE_PATH,
    )


_IPV6_PROBE_URLS = (
    "https://api64.ipify.org?format=json",
    "https://api.ip.sb/jsonip",
)


def _probe_ipv6_egress(proxy_port: int) -> Optional[str]:
    """Return IPv6, an empty string for observed IPv4, or None for unknown."""
    for url in _IPV6_PROBE_URLS:
        data, _ = fetch_json(url, timeout=5.0, proxy_port=proxy_port)
        if not data:
            continue
        if canonical_ip(data.get("ip"), version=4):
            return ""
        v6 = canonical_ip(data.get("ip"), version=6)
        if v6:
            return v6
    return None


def _check_tun(procs_lower: set[str], tuns_raw: List[Dict[str, Any]]) -> Tuple[CheckItem, bool, bool]:
    mihomo_running = "verge-mihomo.exe" in procs_lower or "verge-mihomo-alpha.exe" in procs_lower
    up_tuns = [t for t in tuns_raw if str(t.get("status", "")).lower() == "up"]
    tun_up = len(up_tuns) > 0

    if mihomo_running and tun_up:
        tun_names = ", ".join(str(t.get("name")) for t in up_tuns)
        return (
            CheckItem("tun", "Clash Verge 与 TUN 网卡", "PASS", f"verge-mihomo 运行中，TUN 网卡在线（{tun_names}）"),
            mihomo_running,
            tun_up,
        )

    reason = []
    if not mihomo_running:
        reason.append("verge-mihomo 未运行")
    if not tun_up:
        reason.append("Mihomo TUN 虚拟网卡未启用")
    return (
        CheckItem(
            "tun",
            "Clash Verge 与 TUN 网卡",
            "FAIL",
            "；".join(reason),
            "请确保 Clash Verge 已启动并打开 TUN（虚拟网卡）模式。",
        ),
        mihomo_running,
        tun_up,
    )


def _check_exit_ip(exit_info: ExitInfo, cfg: GuardConfig) -> CheckItem:
    name = "测试出口 IP"
    if exit_info.error or not exit_info.ip:
        return CheckItem(
            "exit_ip", name, "UNKNOWN", "未获得 Guard-Probe 出口 IP",
            exit_info.error or "请检查所选节点能否连通",
        )

    detail = "本次结果覆盖 Guard-Probe 所选节点。Claude 的实际分流可在 Clash「连接」页核对。"
    if cfg.monitored_probe_ip and exit_info.ip != cfg.monitored_probe_ip:
        return CheckItem(
            "exit_ip", name, "WARN",
            f"测试出口发生漂移：当前 {exit_info.ip}，监控基准 {cfg.monitored_probe_ip}",
            detail,
        )
    location = " ".join(part for part in (exit_info.country_code, exit_info.country) if part)
    summary = f"Guard-Probe 出口为 {exit_info.ip}" + (f"（{location}）" if location else "")
    return CheckItem("exit_ip", name, "PASS", summary, detail)


def _check_killswitch(fw: KillSwitchStatus) -> CheckItem:
    name = "严格模式 Kill Switch"
    if fw.error:
        return CheckItem("killswitch", name, "UNKNOWN", "无法核对实际生效的规则", fw.error)
    if fw.active:
        if not fw.claude_apps:
            return CheckItem(
                "killswitch", name, "WARN", "已验证地址段拦截，尚无 Claude 程序规则",
                "安装客户端或补充程序路径后，重新应用断网锁以覆盖其他目标地址。",
            )
        return CheckItem(
            "killswitch", name, "PASS", f"已验证 {fw.rule_count} 条防火墙规则",
            f"覆盖物理网卡：{', '.join(fw.physical_adapters)}",
        )
    if fw.rule_count or fw.disabled_profiles or fw.local_rules_blocked_profiles:
        details = [f"{name} 防火墙未启用" for name in fw.disabled_profiles]
        details.extend(f"{name} 档位策略禁止本地规则" for name in fw.local_rules_blocked_profiles)
        details.extend(fw.missing_scopes)
        if fw.diagnostic:
            details.append(fw.diagnostic)
        return CheckItem("killswitch", name, "FAIL", "断网锁覆盖不完整", "；".join(details))
    return CheckItem("killswitch", name, "WARN", "尚未开启防直连防火墙规则")


def _evaluate_physical_dns(dns_states: List[Dict[str, Any]]) -> Tuple[CheckItem, bool, str]:
    safe_set = set(LOCKED_DNS_SERVERS) | {"1.0.0.1", "8.8.4.4"}
    active_nics = [d for d in dns_states if str(d.get("status", "")).lower() == "up"] or dns_states
    if not active_nics:
        return CheckItem("dns_lock", "物理网卡 DNS 锁定", "WARN", "未检测到活跃物理网卡 DNS 信息"), False, "未检测到网卡"

    unlocked: List[str] = []
    shown_servers: List[str] = []
    for nic in active_nics:
        name = str(nic.get("name", ""))
        srvs = [str(s) for s in normalize_list(nic.get("servers")) if s]
        shown_servers.extend(srvs)
        if not srvs or not all(s in safe_set for s in srvs):
            unlocked.append(f"{name}({', '.join(srvs) or 'DHCP'})")

    uniq_srvs = list(dict.fromkeys(shown_servers))
    summary_text = ", ".join(uniq_srvs[:2]) if uniq_srvs else "DHCP 自动"

    if not unlocked:
        return CheckItem("dns_lock", "物理网卡 DNS 锁定", "PASS", f"物理网卡已锁定安全境外 DNS（{summary_text}）"), True, summary_text
    return (
        CheckItem(
            "dns_lock",
            "物理网卡 DNS 锁定",
            "WARN",
            f"物理网卡仍使用本地/未锁定 DNS：{'; '.join(unlocked)}",
            "点击「物理 DNS 锁定」开关可将物理网卡 DNS 锁定为 1.1.1.1 / 8.8.8.8（自动备份原 DHCP/静态配置，一键可精确还原），避免 Windows 多宿解析回落本地运营商 DNS。",
        ),
        False,
        summary_text,
    )


def _evaluate_ipv6(ipv6_states: List[Dict[str, Any]], leaked_ip: Optional[str]) -> Tuple[CheckItem, Optional[bool]]:
    name = "IPv6 防泄漏"
    enabled = [str(adapter.get("name", "")) for adapter in ipv6_states if adapter.get("ipv6") is True]
    known = bool(ipv6_states) and all(type(adapter.get("ipv6")) is bool for adapter in ipv6_states)
    disabled = False if enabled else (True if known else None)
    if enabled:
        detail = f"仍启用 IPv6 的物理网卡：{', '.join(enabled)}"
        if leaked_ip:
            return CheckItem("ipv6", name, "FAIL", f"检测到 IPv6 出站：{leaked_ip}", detail), disabled
        return CheckItem("ipv6", name, "WARN", "物理网卡仍有 IPv6 绑定", detail), disabled
    if disabled is None:
        return CheckItem("ipv6", name, "UNKNOWN", "无法确认物理网卡 IPv6 绑定状态"), disabled
    if leaked_ip:
        return CheckItem("ipv6", name, "WARN", f"代理检测到 IPv6 出站：{leaked_ip}"), disabled
    if leaked_ip is None:
        return CheckItem("ipv6", name, "UNKNOWN", "物理网卡 IPv6 已关闭，未取得代理出站结果"), disabled
    return CheckItem("ipv6", name, "PASS", "物理网卡 IPv6 已关闭，本次代理探测使用 IPv4"), disabled


def _check_webrtc(rtc: WebRtcPolicyState) -> Tuple[CheckItem, bool]:
    installed = {
        name: enabled for name, enabled, required in (
            ("Chrome", rtc.chrome_ok, rtc.chrome_required),
            ("Edge", rtc.edge_ok, rtc.edge_required),
            ("Firefox", rtc.firefox_ok, rtc.firefox_required),
        ) if required
    }
    if not installed:
        return CheckItem("webrtc", "浏览器 WebRTC 策略", "UNKNOWN", "未发现支持核对的浏览器"), False
    detail = " | ".join(f"{name}={rtc.details.get(name, '未获取')}" for name in installed)
    if all(installed.values()):
        return CheckItem("webrtc", "浏览器 WebRTC 策略", "PASS", "已核对已安装浏览器的 WebRTC 策略", detail), True
    return CheckItem("webrtc", "浏览器 WebRTC 策略", "WARN", "浏览器 WebRTC 防泄漏策略未完全开启", detail), False


def _check_timezone(cur_tz: str, exit_tz: str) -> Tuple[CheckItem, str, bool]:
    expected_tz = IANA_TO_WINDOWS_TZ.get(exit_tz, "") if exit_tz else ""
    matched = bool(expected_tz and cur_tz == expected_tz)
    if not exit_tz:
        return CheckItem("timezone", "系统时区一致性", "WARN", f"当前系统时区：{cur_tz}（未能获取出口时区）"), expected_tz, False
    if matched:
        return CheckItem("timezone", "系统时区一致性", "PASS", f"系统时区（{cur_tz}）与出口时区（{exit_tz}）一致"), expected_tz, True
    return (
        CheckItem(
            "timezone",
            "系统时区一致性",
            "WARN",
            f"时区不匹配：本机 {cur_tz} ≠ 出口 {exit_tz}",
            f"建议切换为 {expected_tz or exit_tz}（点击「对齐」可一键切换并在需要时恢复）。",
        ),
        expected_tz,
        False,
    )


def _audit_clash_verge_config() -> CheckItem:
    name = "Clash Verge 配置审计"
    try:
        config = read_config(CLASH_VERGE_RUNTIME_YAML)
    except (OSError, ValueError) as exc:
        return CheckItem("clash_config", name, "UNKNOWN", "无法读取 Clash 运行配置", str(exc))

    issues = [*subscription_probe_issues(config), *tun_dns_issues(config)]
    if issues:
        return CheckItem("clash_config", name, "WARN", issues[0], "\n".join(issues))
    if not verify_proxy_listener(PROBE_PORT):
        return CheckItem(
            "clash_config", name, "WARN", f"无法核实 Mihomo 回环端口 {PROBE_PORT}",
            "请重新应用订阅，确认体检入口只监听 127.0.0.1。",
        )
    return CheckItem("clash_config", name, "PASS", "Guard-Probe 本机体检入口已核实")


def check_probe_route() -> str:
    item = _audit_clash_verge_config()
    return "" if item.level == "PASS" else item.summary


def _check_conflicts(procs_lower: set[str], old_svc: str, old_run: bool) -> CheckItem:
    found_conflicts = [f"{label} ({proc})" for proc, label in CONFLICT_PROCESSES.items() if proc in procs_lower]
    residuals = []
    if old_svc:
        residuals.append(f"残留系统服务 cc-hahaeasy ({old_svc})")
    if old_run:
        residuals.append("残留开机自启项 HKLM\\Run\\cc-hahaeasy")

    all_warn = found_conflicts + residuals
    if all_warn:
        return CheckItem("conflicts", "冲突代理与旧软件残留", "WARN", f"检测到 {len(all_warn)} 项冲突或残留", "；".join(all_warn))
    return CheckItem("conflicts", "冲突代理与旧软件残留", "PASS", "无冲突代理/VPN，cc-hahaeasy 已清理干净")


# ----------------------------------------------------------------------
# 并发自检主入口
# ----------------------------------------------------------------------
def run_doctor(cfg: GuardConfig) -> DoctorReport:
    """并发执行完整 9 项防泄漏深度自检并返回结构化报告。"""
    t0 = time.perf_counter()

    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="DoctorProbe") as pool:
        fut_snapshot = pool.submit(_probe_system_snapshot)
        fut_firewall = pool.submit(get_firewall_status, cfg.extra_claude_exes)

        rtc = get_webrtc_policy_state()
        cur_tz = get_current_windows_timezone()
        clash_item = _audit_clash_verge_config()
        old_run = _check_old_hklm_run()

        if clash_item.level == "PASS":
            fut_exit = pool.submit(query_exit_info, PROBE_PORT)
            fut_ipv6 = pool.submit(_probe_ipv6_egress, PROBE_PORT)
            exit_info = fut_exit.result()
            if not exit_info.ip:
                reason = f"（{exit_info.error}）" if exit_info.error else ""
                exit_info.error = f"Guard-Probe 查询失败{reason}，请确认已在 Clash 选择可用节点"
            leaked_v6 = fut_ipv6.result()
        else:
            exit_info = ExitInfo(error=clash_item.summary)
            leaked_v6 = None
        snapshot = fut_snapshot.result()
        fw = fut_firewall.result()

    procs_lower = {str(p).lower() for p in normalize_list(snapshot.get("procs"))}
    claude_proc_count = int(snapshot.get("claude_procs") or 0)
    tuns_raw = [t for t in normalize_list(snapshot.get("tuns")) if isinstance(t, dict)]
    ipv6_states = [s for s in normalize_list(snapshot.get("ipv6")) if isinstance(s, dict)]
    dns_states = [d for d in normalize_list(snapshot.get("dns")) if isinstance(d, dict)]

    tun_item, mihomo_running, tun_up = _check_tun(procs_lower, tuns_raw)
    if snapshot.get("error"):
        tun_item = CheckItem("tun", "Clash Verge 与 TUN 网卡", "UNKNOWN", "无法获取系统网络快照", snapshot["error"])
    exit_item = _check_exit_ip(exit_info, cfg)
    fw_item = _check_killswitch(fw)
    dns_item, dns_locked, dns_summary = _evaluate_physical_dns(dns_states)
    ipv6_item, ipv6_physical_disabled = _evaluate_ipv6(ipv6_states, leaked_v6)
    webrtc_item, webrtc_ok = _check_webrtc(rtc)
    tz_item, expected_tz, tz_matched = _check_timezone(cur_tz, exit_info.timezone)
    if clash_item.level == "PASS":
        ipv6_item.detail = "\n".join(filter(None, (ipv6_item.detail, "代理侧探测只覆盖 Guard-Probe 所选节点。")))
    conflict_item = _check_conflicts(procs_lower, str(snapshot.get("old_svc") or ""), old_run)

    items = [tun_item, exit_item, fw_item, dns_item, ipv6_item, webrtc_item, tz_item, clash_item, conflict_item]
    levels = {i.level for i in items}
    overall = "red" if "FAIL" in levels else ("yellow" if levels & {"WARN", "UNKNOWN"} else "green")

    return DoctorReport(
        checked_at=datetime.now().strftime("%H:%M:%S"),
        overall=overall,
        exit_info=exit_info,
        tun_up=tun_up,
        mihomo_running=mihomo_running,
        elapsed_ms=int((time.perf_counter() - t0) * 1000),
        states=QuickStates(
            firewall_active=fw.active and bool(fw.claude_apps),
            firewall_rule_count=fw.rule_count,
            firewall_known=not fw.error,
            dns_locked=dns_locked,
            dns_summary=dns_summary,
            webrtc_ok=webrtc_ok,
            ipv6_physical_disabled=ipv6_physical_disabled,
            ipv6_leaked_ip=leaked_v6 or "",
            timezone_current=cur_tz,
            timezone_expected=expected_tz,
            timezone_matched=tz_matched,
            claude_proc_count=claude_proc_count,
            physical_adapters=fw.physical_adapters,
        ),
        items=items,
    )
