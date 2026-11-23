"""Create and verify Windows Firewall rules scoped to physical adapters."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from ipaddress import ip_network
from pathlib import PureWindowsPath
from uuid import uuid4

from .config import ANTHROPIC_CIDRS_V4, ANTHROPIC_CIDRS_V6, FIREWALL_GROUP, FIREWALL_PROFILE_KEYS
from .sysutil import discover_claude_executables, get_physical_adapters, is_admin, ps_quote, run_ps, run_ps_json

_ps_quote = ps_quote
_ENFORCED = 1
_FIREWALL_OFF = 2
_PROFILE_INACTIVE = 5


@dataclass
class KillSwitchStatus:
    active: bool
    rule_count: int
    firewall_profiles_enabled: bool
    disabled_profiles: list[str]
    physical_adapters: list[str]
    rule_names: list[str]
    missing_scopes: list[str] = field(default_factory=list)
    error: str = ""
    claude_apps: list[str] = field(default_factory=list)
    local_rules_blocked_profiles: list[str] = field(default_factory=list)
    diagnostic: str = ""
    verified_rule_ids: list[str] = field(default_factory=list)
    missing_rule_specs: list[tuple[str, list[str], str]] = field(default_factory=list)


def _expected_scopes(apps: list[str]) -> list[tuple[str, list[str], str]]:
    scopes = [
        ("Anthropic IPv4", ANTHROPIC_CIDRS_V4, "Any"),
        ("Anthropic IPv6", ANTHROPIC_CIDRS_V6, "Any"),
    ]
    scopes.extend((f"应用 {PureWindowsPath(app).name}", ["Any"], app) for app in apps)
    return scopes


def _as_list(value: object) -> list:
    """PowerShell 单元素数组会被 ConvertTo-Json 折叠成标量，统一还原为列表。"""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _addresses(items: list[str]) -> set[str]:
    normalized = set()
    for item in items:
        text = str(item)
        try:
            normalized.add(str(ip_network(text, strict=False)))
        except ValueError:
            normalized.add(text.lower())
    return normalized


def _rule_rejection_reasons(
    rule: dict,
    expected_interfaces: set[str],
    inactive_profiles: int,
    inactive_firewalls_off: int,
) -> list[str]:
    reasons: list[str] = []
    if not isinstance(rule.get("id"), str) or not rule["id"]:
        reasons.append("缺少规则 ID")
    if str(rule.get("enabled", "")).strip().lower() != "true":
        reasons.append(f"enabled={rule.get('enabled')!r}")
    if str(rule.get("direction", "")) != "Outbound":
        reasons.append(f"direction={rule.get('direction')!r}")
    if str(rule.get("action", "")) != "Block":
        reasons.append(f"action={rule.get('action')!r}")
    if str(rule.get("profile", "")) != "Any":
        reasons.append(f"profile={rule.get('profile')!r}")
    if str(rule.get("primary_status", "")).casefold() != "ok":
        reasons.append(f"primary_status={rule.get('primary_status')!r}")
    if not _has_effective_enforcement(rule.get("enforcement"), inactive_profiles, inactive_firewalls_off):
        reasons.append(f"enforcement={rule.get('enforcement')!r}")
    if str(rule.get("protocol", "")) not in ("Any", "256"):
        reasons.append(f"protocol={rule.get('protocol')!r}")
    if not (isinstance(rule.get("program"), str) and bool(rule["program"])):
        reasons.append(f"program={rule.get('program')!r}")
    got_ifaces = {str(name).casefold() for name in _as_list(rule.get("interfaces"))}
    if got_ifaces != expected_interfaces:
        reasons.append(f"interfaces={sorted(got_ifaces)}!=expected={sorted(expected_interfaces)}")
    if _addresses(_as_list(rule.get("local"))) != {"any"}:
        reasons.append(f"local={rule.get('local')!r}")
    return reasons


def _has_effective_enforcement(
    value: object, inactive_profiles: int, inactive_firewalls_off: int
) -> bool:
    states = _as_list(value)
    allowed = {_ENFORCED, _FIREWALL_OFF, _PROFILE_INACTIVE}
    # ActiveStore can report both enforcement and inactive profile statuses for an Any-profile rule.
    return (
        all(type(state) is int and state in allowed for state in states)
        and _ENFORCED in states
        and states.count(_FIREWALL_OFF) <= inactive_firewalls_off
        and states.count(_FIREWALL_OFF) + states.count(_PROFILE_INACTIVE) <= inactive_profiles
    )


def _scope_key(program: str, addresses: list[str]) -> tuple[str, frozenset[str]]:
    return str(PureWindowsPath(program)).casefold(), frozenset(_addresses(addresses))


def _evaluate_rules(data: dict, adapters: list[str], apps: list[str]) -> KillSwitchStatus:
    if "rules" not in data or "profiles" not in data:
        raise ValueError("缺少规则或防火墙档位")
    rules = _as_list(data["rules"])
    if any(not isinstance(rule, dict) for rule in rules):
        raise ValueError("规则列表包含无效的记录")
    profiles = {
        profile["name"]: profile for profile in _as_list(data.get("profiles"))
        if isinstance(profile, dict) and profile.get("name") in FIREWALL_PROFILE_KEYS
    }
    categories = {str(category) for category in _as_list(data.get("network_categories"))}
    if "DomainAuthenticated" in categories:
        categories.discard("DomainAuthenticated")
        categories.add("Domain")
    required_profiles = categories or set(FIREWALL_PROFILE_KEYS)
    disabled = sorted(name for name in required_profiles if profiles.get(name, {}).get("enabled") is not True)
    blocked = sorted(name for name in required_profiles if profiles.get(name, {}).get("local_rules_allowed") is False)
    inactive = profiles.keys() - required_profiles
    inactive_firewalls_off = sum(profiles[name].get("enabled") is False for name in inactive)
    expected_interfaces = {name.casefold() for name in adapters}
    effective_by_scope: dict[tuple[str, frozenset[str]], str] = {}
    first_rejection = ""
    for rule in rules:
        reasons = _rule_rejection_reasons(rule, expected_interfaces, len(inactive), inactive_firewalls_off)
        if not reasons:
            key = _scope_key(rule["program"], _as_list(rule.get("remote")))
            effective_by_scope.setdefault(key, rule["id"])
        elif not first_rejection:
            first_rejection = f"{rule.get('name') or rule.get('id')}: {', '.join(reasons)}"
    verified_ids: list[str] = []
    missing: list[tuple[str, list[str], str]] = []
    for scope in _expected_scopes(apps):
        _, addresses, program = scope
        verified_id = effective_by_scope.get(_scope_key(program, addresses))
        if verified_id:
            verified_ids.append(verified_id)
        else:
            missing.append(scope)
    return KillSwitchStatus(
        active=bool(adapters) and not missing and not disabled and not blocked,
        rule_count=len(rules), firewall_profiles_enabled=not disabled, disabled_profiles=disabled,
        physical_adapters=adapters, rule_names=[str(rule.get("name", "")) for rule in rules],
        missing_scopes=[label for label, _, _ in missing], claude_apps=list(apps), local_rules_blocked_profiles=blocked,
        diagnostic=f"规则被拒({first_rejection})" if missing and first_rejection else "",
        verified_rule_ids=verified_ids, missing_rule_specs=missing,
    )


def get_status(extra_claude_exes: list[str] | None = None) -> KillSwitchStatus:
    adapters = get_physical_adapters()
    profiles_and_rules = (
        "$ErrorActionPreference='Stop';"
        "$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {"
        " [pscustomobject]@{name=[string]$_.Name;enabled=([string]$_.Enabled -eq 'True');"
        " local_rules_allowed=([string]$_.AllowLocalFirewallRules -ne 'False')} });"
        "$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { "
        f" $_.Group -eq {ps_quote(FIREWALL_GROUP)} }} | ForEach-Object {{ "
        " $a = $_ | Get-NetFirewallAddressFilter;"
        " $i = $_ | Get-NetFirewallInterfaceFilter;"
        " $p = $_ | Get-NetFirewallApplicationFilter;"
        " $t = $_ | Get-NetFirewallPortFilter;"
        " [pscustomobject]@{id=[string]$_.Name;name=[string]$_.DisplayName;enabled=[string]$_.Enabled;"
        " direction=[string]$_.Direction;action=[string]$_.Action;profile=[string]$_.Profile;"
        " primary_status=[string]$_.PrimaryStatus;enforcement=@($_.CimInstanceProperties['EnforcementStatus'].Value);"
        " local=@($a.LocalAddress);remote=@($a.RemoteAddress);interfaces=@($i.InterfaceAlias);"
        " program=[string]$p.Program;protocol=[string]$t.Protocol} });"
        "$categories = @(Get-NetConnectionProfile | ForEach-Object { [string]$_.NetworkCategory });"
        "[pscustomobject]@{rules=$rules;profiles=$profiles;network_categories=$categories} | ConvertTo-Json -Depth 5 -Compress"
    )
    ok, data, error = run_ps_json(profiles_and_rules, timeout=18)
    if not ok or not isinstance(data, dict) or not adapters:
        return KillSwitchStatus(False, 0, False, [], adapters, [], error=error or "无法完整读取防火墙或物理网卡")
    try:
        return _evaluate_rules(data, adapters, discover_claude_executables(extra_claude_exes))
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return KillSwitchStatus(
            False, 0, False, [], adapters, [],
            error=f"防火墙规则解析失败：{type(exc).__name__}: {exc}",
        )


def _remove_rules(condition: str = "$true") -> tuple[int, str, str]:
    group = ps_quote(FIREWALL_GROUP)
    return run_ps(
        "$ErrorActionPreference='Stop';"
        "$targets = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { "
        + f"$_.Group -eq {group} -and ({condition}) }});"
        "if ($targets.Count) { $targets | Remove-NetFirewallRule };"
        "$remaining = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { "
        + f"$_.Group -eq {group} -and ({condition}) }});"
        "if ($remaining.Count) { throw 'Firewall rules still present' };"
    )


def disable_killswitch() -> tuple[bool, str]:
    if not is_admin():
        return False, "移除防火墙规则需要管理员权限"
    rc, out, error = _remove_rules()
    return (False, error or out) if rc else (True, "已核对本程序的防火墙规则均已移除")


def _poll_status(extra_claude_exes: list[str] | None) -> KillSwitchStatus:
    """等待 ActiveStore 回读新规则，期间使用原有规则核对整体覆盖。"""
    status = get_status(extra_claude_exes)
    for _ in range(2):
        if status.active or status.error or status.disabled_profiles or status.local_rules_blocked_profiles:
            break
        time.sleep(0.25)
        status = get_status(extra_claude_exes)
    return status


def _coverage_error(status: KillSwitchStatus) -> str:
    issues = [f"{name} 防火墙未启用" for name in status.disabled_profiles]
    issues.extend(f"{name} 档位策略禁止本地规则" for name in status.local_rules_blocked_profiles)
    issues.extend(status.missing_scopes)
    if status.diagnostic:
        issues.append(status.diagnostic)
    return status.error or "；".join(issues) or "规则生效状态未通过验证"


def enable_killswitch(extra_claude_exes: list[str] | None = None) -> tuple[bool, str]:
    if not is_admin():
        return False, "写入防火墙规则需要管理员权限"

    status = get_status(extra_claude_exes)
    if status.error or status.disabled_profiles or status.local_rules_blocked_profiles:
        return False, _coverage_error(status)
    if status.active and status.rule_count == len(status.verified_rule_ids):
        return True, f"现有 {status.rule_count} 条规则已通过验证"

    if status.missing_rule_specs:
        generation = f"ClaudeGuard-{uuid4().hex}-"
        interfaces = "@(" + ",".join(map(ps_quote, status.physical_adapters)) + ")"
        commands = ["$ErrorActionPreference='Stop'"]
        for index, (label, addresses, program) in enumerate(status.missing_rule_specs, start=1):
            cmd = (
                f"New-NetFirewallRule -Name {ps_quote(generation + str(index))} "
                f"-DisplayName {ps_quote('ClaudeGuard - Block ' + label)} -Group {ps_quote(FIREWALL_GROUP)} "
                f"-Direction Outbound -Action Block -Profile Any -Enabled True -InterfaceAlias {interfaces} "
            )
            if program != "Any":
                cmd += f"-Program {ps_quote(program)} "
            else:
                cmd += "-RemoteAddress @(" + ",".join(map(ps_quote, addresses)) + ") "
            commands.append(cmd + "| Out-Null")

        rc, out, error = run_ps("; ".join(commands), timeout=30)
        if rc == 0:
            status = _poll_status(extra_claude_exes)
        if rc or not status.active:
            cleanup, cleanup_out, cleanup_error = _remove_rules(f"$_.Name -like {ps_quote(generation + '*')}")
            suffix = f"；新规则清理失败：{cleanup_error or cleanup_out}" if cleanup else ""
            reason = (error or out or "Windows 未能创建规则") if rc else _coverage_error(status)
            return False, f"防火墙规则更新失败，已保留旧规则：{reason}{suffix}"

    if not status.active or not status.verified_rule_ids:
        return False, _coverage_error(status)

    # Windows may keep the older rule effective when a later rule has the same scope.
    # Keep the IDs actually verified in ActiveStore before removing anything redundant.
    if status.rule_count > len(status.verified_rule_ids):
        keep = "@(" + ",".join(map(ps_quote, status.verified_rule_ids)) + ")"
        cleanup, cleanup_out, cleanup_error = _remove_rules(f"$_.Name -notin {keep}")
        if cleanup:
            return False, f"规则覆盖已验证，冗余规则清理失败：{cleanup_error or cleanup_out}"
        status = _poll_status(extra_claude_exes)
        if not status.active:
            return False, f"已完成冗余规则清理，最终状态尚未通过验证：{_coverage_error(status)}"

    scope = "" if status.claude_apps else "；尚未发现 Claude 程序，当前仅覆盖地址段"
    return True, f"已验证 {len(status.verified_rule_ids)} 条规则，覆盖 {', '.join(status.physical_adapters)}{scope}"
