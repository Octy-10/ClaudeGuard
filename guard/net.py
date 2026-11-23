"""HTTPS probes through the configured local Clash mixed port."""

from __future__ import annotations

import http.client
import json
import time
from ipaddress import ip_address
from urllib.parse import urlsplit

from .sysutil import run_ps_json

USER_AGENT = "ClaudeGuard/2.0"
IP_INFO_URL = "https://ipapi.co/json/"
IP_INFO_URLS = (
    IP_INFO_URL,
    "https://ipwho.is/",
    "https://api.ip.sb/geoip",
)
_RATE_LIMITED_UNTIL: dict[str, float] = {}


def verify_proxy_listener(port: int) -> bool:
    if type(port) is not int or not 1 <= port <= 65535:
        return False
    ok, data, _ = run_ps_json(
        "$ErrorActionPreference='Stop';"
        f"$listeners = @(Get-NetTCPConnection -State Listen -LocalPort {port});"
        "$local = @($listeners | Where-Object LocalAddress -eq '127.0.0.1');"
        "$owners = @($local | ForEach-Object { (Get-Process -Id $_.OwningProcess).ProcessName });"
        "$exposed = @($listeners | Where-Object { "
        "$_.LocalAddress -notin @('127.0.0.1','::1') -and "
        "($_.LocalAddress -in @('0.0.0.0','::') -or $_.OwningProcess -in $local.OwningProcess) });"
        "[pscustomobject]@{verified=($owners.Count -gt 0 -and "
        "@($owners | Where-Object { $_ -notin @('verge-mihomo','verge-mihomo-alpha') }).Count -eq 0 "
        "-and $exposed.Count -eq 0)} "
        "| ConvertTo-Json -Compress",
        timeout=8,
    )
    return ok and isinstance(data, dict) and data.get("verified") is True


def canonical_ip(value: object, version: int | None = None) -> str:
    try:
        address = ip_address(str(value))
    except ValueError:
        return ""
    return str(address) if version is None or address.version == version else ""


def fetch_text(url: str, *, proxy_port: int, timeout: float = 6.0) -> tuple[str | None, str]:
    endpoint = urlsplit(url)
    if endpoint.scheme != "https" or not endpoint.hostname:
        return None, "探测需要 HTTPS 地址"
    if type(proxy_port) is not int or not 1 <= proxy_port <= 65535:
        return None, "Clash mixed-port 无效"
    conn = http.client.HTTPSConnection("127.0.0.1", proxy_port, timeout=timeout)
    try:
        conn.set_tunnel(endpoint.hostname, endpoint.port or 443)
        resource = endpoint.path or "/"
        if endpoint.query:
            resource += "?" + endpoint.query
        conn.request("GET", resource, headers={"Host": endpoint.netloc, "User-Agent": USER_AGENT})
        with conn.getresponse() as response:
            if not 200 <= response.status < 300:
                return None, f"HTTPS 探测返回 {response.status}"
            data = response.read(131073)
            if len(data) > 131072:
                return None, "探测响应过大"
            return data.decode("utf-8"), ""
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return None, str(exc)
    finally:
        conn.close()


def fetch_json(url: str, *, proxy_port: int, timeout: float = 6.0) -> tuple[dict | None, str]:
    raw, error = fetch_text(url, proxy_port=proxy_port, timeout=timeout)
    if raw is None:
        return None, error
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data, ""
        return None, "响应不是 JSON 对象"
    except (ValueError, RecursionError) as exc:
        return None, f"JSON 解析失败：{exc}"


def _normalize_ip_info(data: dict) -> dict | None:
    if data.get("success") is False:
        return None
    ip = canonical_ip(data.get("ip"))
    if not ip:
        return None
    conn = data.get("connection") if isinstance(data.get("connection"), dict) else {}
    tz_raw = data.get("timezone")
    tz = str(tz_raw.get("id") or "") if isinstance(tz_raw, dict) else str(tz_raw or "")
    asn_raw = data.get("asn") or conn.get("asn") or ""
    asn = f"AS{asn_raw}" if str(asn_raw).isdigit() else str(asn_raw)
    org = str(
        data.get("org")
        or conn.get("isp")
        or conn.get("org")
        or data.get("isp")
        or data.get("organization")
        or ""
    )
    return {
        **data,
        "ip": ip,
        "country_name": str(data.get("country_name") or data.get("country") or ""),
        "country_code": str(data.get("country_code") or "").upper(),
        "region": str(data.get("region") or ""),
        "city": str(data.get("city") or ""),
        "org": org,
        "asn": asn,
        "timezone": tz,
    }


def fetch_ip_info(mixed_port: int) -> tuple[dict | None, str]:
    now = time.monotonic()
    ordered = [u for u in IP_INFO_URLS if _RATE_LIMITED_UNTIL.get(u, 0.0) <= now]
    ordered.extend(u for u in IP_INFO_URLS if u not in ordered)
    last_error = ""
    for url in ordered:
        data, error = fetch_json(url, proxy_port=mixed_port)
        if data:
            normalized = _normalize_ip_info(data)
            if normalized:
                _RATE_LIMITED_UNTIL.pop(url, None)
                return normalized, ""
            last_error = "出口查询缺少有效 IP"
            continue
        if "429" in error:
            _RATE_LIMITED_UNTIL[url] = time.monotonic() + 600.0
        last_error = error or last_error
    return None, last_error or "出口查询缺少有效 IP"

