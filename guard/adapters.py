"""Apply and restore IPv4 DNS and IPv6 bindings on physical Windows adapters."""

from __future__ import annotations

import re
from uuid import UUID

from .config import LOCKED_DNS_SERVERS, load_backup, save_backup
from .sysutil import PHYSICAL_ADAPTER_FILTER, is_admin, ps_quote, run_ps, run_ps_json

_ADAPTERS = (
    "$ErrorActionPreference='Stop';"
    f"$adapters = @(Get-NetAdapter | Where-Object {{ {PHYSICAL_ADAPTER_FILTER} }});"
)
_DNS_DATA = (
    "$guid = ([guid]$n.InterfaceGuid).ToString('B');"
    "$reg = Get-ItemProperty -LiteralPath ('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\' + $guid);"
    "$manual = [string]$reg.NameServer;"
)
_BINDING = (
    "$binding = @(Get-NetAdapterBinding -Name ([WildcardPattern]::Escape($n.Name)) -ComponentID ms_tcpip6);"
    "if ($binding.Count -ne 1 -or $null -eq $binding[0].Enabled) { throw 'IPv6 binding unavailable' };"
    "$binding = $binding[0];"
)


def _read_adapters(setting: str) -> list[dict]:
    detail = _DNS_DATA + "$value = $manual;" if setting == "DNS" else _BINDING + "$value = [bool]$binding.Enabled;"
    ok, records, error = run_ps_json(
        _ADAPTERS + "@($adapters | ForEach-Object { $n = $_;"
        + detail + "[pscustomobject]@{ name=$n.Name; guid=([guid]$n.InterfaceGuid).ToString(); value=$value }"
        "}) | ConvertTo-Json -Compress"
    )
    if not ok:
        raise OSError(error)
    return [records] if isinstance(records, dict) else records or []


def _select_adapter(identity: str) -> str:
    try:
        guid = str(UUID(identity))
        predicate = f"([guid]$_.InterfaceGuid).ToString() -eq {ps_quote(guid)}"
    except ValueError:
        predicate = f"$_.Name -eq {ps_quote(identity)}"  # Legacy backup
    return (
        _ADAPTERS + f"$n = @($adapters | Where-Object {{ {predicate} }});"
        "if ($n.Count -ne 1) { throw 'Physical adapter unavailable' }; $n = $n[0];"
    )


def _dns_servers(value: str) -> list[str]:
    return [server for server in re.split(r"[\s,;]+", value.strip()) if server]


def _ps_array(values: list[str]) -> str:
    return "@(" + ",".join(ps_quote(value) for value in values) + ")"


def _write_dns(identity: str, expected: list[str], servers: list[str]) -> None:
    target = _ps_array(servers)
    before = _ps_array(expected)
    change = f"-ServerAddresses {target}" if servers else "-ResetServerAddresses"
    readback = "@($manual -split '[\\s,;]+' | Where-Object { $_ }) -join ','"
    rc, out, error = run_ps(
        _select_adapter(identity) + _DNS_DATA
        + f"$current = {readback};"
        + f"if ($current -ne ({target} -join ',')) {{"
        + f"if ($current -ne ({before} -join ',')) {{ throw 'DNS configuration changed outside Claude Guard' }};"
        "$dns = Get-DnsClientServerAddress -InterfaceIndex $n.ifIndex -AddressFamily IPv4;"
        + f"Set-DnsClientServerAddress -InputObject $dns {change};"
        + _DNS_DATA
        + f"if (({readback}) -ne ({target} -join ',')) {{ throw 'DNS verification failed' }};"
        "}"
    )
    if rc != 0:
        raise OSError(error or out)


def _write_ipv6(identity: str, enabled: bool) -> None:
    target = "$true" if enabled else "$false"
    rc, out, error = run_ps(
        _select_adapter(identity) + _BINDING
        + f"if ([bool]$binding.Enabled -ne {target}) {{"
        + f"Set-NetAdapterBinding -InputObject $binding -Enabled {target};"
        + _BINDING
        + f"if ([bool]$binding.Enabled -ne {target}) {{ throw 'IPv6 verification failed' }}"
        "}"
    )
    if rc != 0:
        raise OSError(error or out)


def lock_physical_dns() -> tuple[bool, str]:
    if not is_admin():
        return False, "锁定物理网卡 DNS 需要管理员权限"
    backup = load_backup()
    errors = []
    adapters = _read_adapters("DNS")
    if not adapters:
        return False, "未读到物理网卡 DNS 配置"
    for adapter in adapters:
        guid, name = adapter["guid"], adapter["name"]
        original = _dns_servers(adapter["value"])
        if original == LOCKED_DNS_SERVERS:
            continue
        if guid not in backup.dns_backup and name not in backup.dns_backup:
            backup.dns_backup[guid] = original
            save_backup(backup)
        try:
            _write_dns(guid, original, LOCKED_DNS_SERVERS)
        except OSError as exc:
            errors.append(f"{name}：{exc}")
    return (False, "；".join(errors)) if errors else (True, "已核对物理网卡静态 IPv4 DNS")


def restore_physical_dns() -> tuple[bool, str]:
    if not is_admin():
        return False, "恢复物理网卡 DNS 需要管理员权限"
    backup = load_backup()
    errors = []
    for adapter, servers in list(backup.dns_backup.items()):
        try:
            _write_dns(adapter, LOCKED_DNS_SERVERS, servers)
        except OSError as exc:
            errors.append(f"{adapter}：{exc}")
            continue
        del backup.dns_backup[adapter]
        save_backup(backup)
    return (False, "；".join(errors)) if errors else (True, "已核对所有已备份的物理网卡 DNS")


def disable_physical_ipv6() -> tuple[bool, str]:
    if not is_admin():
        return False, "关闭物理网卡 IPv6 需要管理员权限"
    backup = load_backup()
    errors = []
    adapters = _read_adapters("IPv6")
    if not adapters:
        return False, "未读到物理网卡 IPv6 配置"
    unconfirmed = set()
    for adapter in adapters:
        if not adapter["value"]:
            continue
        guid, name = adapter["guid"], adapter["name"]
        added = guid not in backup.ipv6_disabled_adapters and name not in backup.ipv6_disabled_adapters
        if added:
            backup.ipv6_disabled_adapters.append(guid)
            save_backup(backup)
        try:
            _write_ipv6(guid, False)
        except OSError as exc:
            errors.append(f"{name}：{exc}")
            if added:
                unconfirmed.add(guid)
    if unconfirmed:
        try:
            current = _read_adapters("IPv6")
        except OSError:
            current = []
        unchanged = {adapter["guid"] for adapter in current if adapter["value"] is True} & unconfirmed
        if unchanged:
            backup.ipv6_disabled_adapters = [guid for guid in backup.ipv6_disabled_adapters if guid not in unchanged]
            save_backup(backup)
    return (False, "；".join(errors)) if errors else (True, "已核对物理网卡 IPv6 绑定已关闭")


def restore_physical_ipv6() -> tuple[bool, str]:
    if not is_admin():
        return False, "恢复物理网卡 IPv6 需要管理员权限"
    backup = load_backup()
    errors = []
    for adapter in list(backup.ipv6_disabled_adapters):
        try:
            _write_ipv6(adapter, True)
        except OSError as exc:
            errors.append(f"{adapter}：{exc}")
            continue
        backup.ipv6_disabled_adapters.remove(adapter)
        save_backup(backup)
    return (False, "；".join(errors)) if errors else (True, "已核对所有已备份网卡的 IPv6 绑定")
