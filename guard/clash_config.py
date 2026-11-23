"""Audit the generated Clash Verge YAML and the route used by HTTPS probes."""

from __future__ import annotations

from pathlib import Path

PROBE_GROUP = "Guard-Probe"
PROBE_INBOUND = "claude-guard-probe"
PROBE_PORT = 17897
NON_REMOTE_TYPES = {"direct", "compatible", "pass", "reject", "rejectdrop", "dns", "rematch"}
PROBE_NODE_TYPES = {
    "anytls", "http", "hysteria", "hysteria2", "mieru", "shadowquic", "snell", "socks5",
    "ss", "ssr", "ssh", "trojan", "trusttunnel", "tuic", "vless", "vmess", "wireguard",
}


def read_config(path: Path) -> dict:
    try:
        import yaml
    except ImportError as exc:
        raise ValueError("缺少 PyYAML，请安装 requirements.txt 中的依赖") from exc
    try:
        with path.open(encoding="utf-8-sig") as file:
            data = yaml.safe_load(file)
    except yaml.YAMLError as exc:
        raise ValueError("Clash 运行配置 YAML 格式无效") from exc
    if not isinstance(data, dict):
        raise ValueError("Clash 配置根节点需要是映射")
    return data


def subscription_probe_issues(config: dict, *, group: str = PROBE_GROUP, inbound: str = PROBE_INBOUND, port: int = PROBE_PORT) -> list[str]:
    group_name = group
    issues = []
    if str(config.get("mode", "")).casefold() != "rule":
        issues.append("请在 Clash 使用规则模式")
    if any(str(config.get(key)) == str(port) for key in ("mixed-port", "port", "socks-port", "redir-port", "tproxy-port")):
        issues.append(f"Guard 专用端口 {port} 与现有端口冲突")

    listeners = config.get("listeners")
    probe_listeners = [
        entry for entry in listeners if isinstance(entry, dict) and (
            entry.get("name") == inbound or str(entry.get("port")) == str(port)
        )
    ] if isinstance(listeners, list) else []
    if not probe_listeners:
        return [*issues, "请在总览点击「配置出口检测」，保存并重新应用新版全局扩展脚本"]
    if probe_listeners != [{
        "name": inbound, "type": "http", "listen": "127.0.0.1", "port": port,
        "proxy": group_name, "users": [],
    }]:
        issues.append(f"未找到绑定到 127.0.0.1:{port} 的 Guard 专用入口")

    groups = config.get("proxy-groups")
    groups = [entry for entry in groups if isinstance(entry, dict)] if isinstance(groups, list) else []
    probes = [entry for entry in groups if entry.get("name") == group_name]
    if len(probes) != 1:
        return [*issues, f"缺少唯一的 {group_name} 策略组"]
    group = probes[0]
    choices = group.get("proxies")
    if (
        group.get("type") != "select" or group.get("empty-fallback") != "REJECT"
        or group.get("default-selected") != "REJECT" or not isinstance(choices, list)
        or not choices or choices[0] != "REJECT" or not all(isinstance(name, str) and name.strip() for name in choices)
        or any(group.get(key) for key in ("include-all", "include-all-proxies", "include-all-providers", "use"))
        or len(set(choices)) != len(choices)
    ):
        return [*issues, f"{group_name} 需要显式节点列表和 REJECT 兜底"]
    if len(choices) < 2:
        return [*issues, f"{group_name} 没有可用节点。请使用含有内联节点的订阅"]

    reserved = NON_REMOTE_TYPES | {"global", "guardprobe", "guardclaude"}
    candidates = set(choices[1:])
    group_names = {entry.get("name") for entry in groups if isinstance(entry.get("name"), str)}
    proxies = config.get("proxies")
    entries = [
        entry for entry in proxies if isinstance(entry, dict)
        and isinstance(entry.get("name"), str) and entry["name"] in candidates | {group_name, "REJECT"}
    ] if isinstance(proxies, list) else []
    safe = {
        entry["name"] for entry in entries if str(entry.get("type", "")).strip().casefold() in PROBE_NODE_TYPES
        and entry["name"].strip().casefold().replace("-", "") not in reserved
    }
    if safe != candidates or len(entries) != len(candidates) or candidates & group_names or "REJECT" in group_names:
        issues.append(f"{group_name} 只能包含明确的代理节点及内置 REJECT")
    return issues


def tun_dns_issues(config: dict) -> list[str]:
    issues = []
    tun = config.get("tun")
    if not isinstance(tun, dict) or not all(tun.get(key) is True for key in ("enable", "auto-route", "strict-route")):
        issues.append("TUN、自动路由和严格路由需要启用")
    if config.get("ipv6") is not False:
        issues.append("Clash 顶层 IPv6 需要关闭")
    dns = config.get("dns")
    if not isinstance(dns, dict) or dns.get("enable") is not True or dns.get("ipv6") is not False:
        return [*issues, "Clash DNS 需要启用并关闭 IPv6 解析"]
    return issues
