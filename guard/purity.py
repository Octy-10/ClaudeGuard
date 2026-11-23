"""Evaluate the independently selected Guard-Probe test node."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime

from .clash_config import PROBE_PORT
from .net import canonical_ip, fetch_ip_info, fetch_json


@dataclass
class PuritySignal:
    label: str
    value: str
    level: str
    note: str = ""


@dataclass
class PurityReport:
    checked_at: str
    elapsed_ms: int
    ip: str = ""
    asn: str = ""
    as_org: str = ""
    country: str = ""
    country_code: str = ""
    city: str = ""
    fraud_score: int | None = None
    is_residential: bool | None = None
    is_broadcast: bool | None = None
    is_proxy: bool | None = None
    is_hosting: bool | None = None
    grade: str = "—"
    risk_level: str = "unknown"
    verdict_title: str = ""
    verdict_detail: str = ""
    signals: list[PuritySignal] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _fetch_ippure(proxy_port: int) -> tuple[dict | None, str]:
    data, error = fetch_json("https://my.ippure.com/v1/info", proxy_port=proxy_port)
    if data and canonical_ip(data.get("ip")):
        return data, ""
    return None, f"IPPure 探测失败：{error or '缺少有效 IP'}"


def _flag(data: dict, key: str) -> bool | None:
    value = data.get(key)
    return value if isinstance(value, bool) else None


def evaluate_purity(
    ippure: dict | None,
    ipapi: dict | None,
    errors: list[str],
    elapsed_ms: int,
) -> PurityReport:
    primary = ippure or {}
    secondary = ipapi or {}
    primary_ip = canonical_ip(primary.get("ip"))
    secondary_ip = canonical_ip(secondary.get("ip") or secondary.get("query"))
    if not primary_ip:
        primary = {}
    if not secondary_ip or (primary_ip and secondary_ip != primary_ip):
        secondary = {}

    try:
        fraud_score = max(0, min(100, int(primary["fraudScore"])))
    except (KeyError, TypeError, ValueError, OverflowError):
        fraud_score = None
    asn = str(primary.get("asn") or secondary.get("asn") or secondary.get("as") or "").split(" ", 1)[0]
    if asn.isdigit():
        asn = "AS" + asn

    report = PurityReport(
        checked_at=datetime.now().strftime("%H:%M:%S"), elapsed_ms=elapsed_ms,
        ip=primary_ip or secondary_ip, asn=asn,
        as_org=str(primary.get("asOrganization") or secondary.get("org") or secondary.get("isp") or ""),
        country=str(primary.get("country") or secondary.get("country_name") or secondary.get("country") or ""),
        country_code=str(primary.get("countryCode") or secondary.get("country_code") or secondary.get("countryCode") or "").upper(),
        city=str(primary.get("city") or secondary.get("city") or ""),
        fraud_score=fraud_score, is_residential=_flag(primary, "isResidential"),
        is_broadcast=_flag(primary, "isBroadcast"), is_proxy=_flag(secondary, "proxy"),
        is_hosting=_flag(secondary, "hosting"), errors=errors.copy(),
    )
    risk_points = 0
    if fraud_score is None:
        report.signals.append(PuritySignal("IPPure 风险分", "未获取", "warn"))
    else:
        risk_points += 50 if fraud_score > 75 else 30 if fraud_score > 50 else 12 if fraud_score > 25 else 0
        level = "fail" if fraud_score > 75 else "warn" if fraud_score > 50 else "info"
        report.signals.append(PuritySignal("IPPure 风险分", f"{fraud_score} / 100", level))
    if report.is_residential is False or report.is_hosting is True:
        risk_points += 22
        report.signals.append(PuritySignal("网络类型", "机房 / 数据中心", "warn"))
    elif report.is_residential is True:
        report.signals.append(PuritySignal("网络类型", "住宅 / 家宽", "pass"))
    if report.is_broadcast is True:
        risk_points += 15
        report.signals.append(PuritySignal("IP 属性", "广播 IP", "warn"))
    if report.is_proxy is True:
        risk_points += 28
        report.signals.append(PuritySignal("匿名代理库", "命中代理标记", "warn"))

    if primary_ip and secondary_ip and primary_ip != secondary_ip:
        report.errors.append("两个数据源观察到不同出口，请确认测试节点后重试")
    if not primary_ip or primary_ip != secondary_ip or fraud_score is None:
        report.verdict_title = "证据不足，暂无法评级"
        report.verdict_detail = "评级需要两处探测确认同一出口和有效的 IPPure 风险分。"
    elif fraud_score > 75 or risk_points >= 55:
        report.grade, report.risk_level = "D", "high"
        report.verdict_title = "测试节点网络风险较高"
    elif risk_points >= 18:
        report.grade, report.risk_level = ("C" if risk_points >= 35 else "B"), "medium"
        report.verdict_title = "测试节点有风险标记"
    else:
        report.grade = "A+" if risk_points == 0 and report.is_residential is True and report.is_broadcast is False else "A"
        report.risk_level = "low"
        report.verdict_title = "测试节点网络风险较低"
    if report.risk_level != "unknown":
        report.verdict_detail = "评级来自 IPPure 和 ipapi.co。Claude 实际出口未核实。"
    return report


def run_purity_check() -> PurityReport:
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="PurityProbe") as pool:
        ippure = pool.submit(_fetch_ippure, PROBE_PORT)
        ipapi = pool.submit(fetch_ip_info, PROBE_PORT)
        primary, primary_error = ippure.result()
        secondary, secondary_error = ipapi.result()
    errors = [error for error in (primary_error, secondary_error) if error]
    return evaluate_purity(primary, secondary, errors, int((time.perf_counter() - start) * 1000))
