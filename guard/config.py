"""配置持久化与静态安全规则定义。"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

APP_NAME = "Claude Guard"
FIREWALL_GROUP = "ClaudeGuard_KillSwitch"
FIREWALL_PROFILE_KEYS = {"Domain": "DomainProfile", "Private": "StandardProfile", "Public": "PublicProfile"}
STATE_DIR = Path.home() / ".claude-guard"
CONFIG_FILE = STATE_DIR / "config.json"
BACKUP_FILE = STATE_DIR / "backup.json"

# Clash Verge Rev 默认配置路径
CLASH_VERGE_DIR = (
    Path.home() / "Library" / "Application Support" if sys.platform == "darwin"
    else Path(os.environ.get("APPDATA", ""))
) / "io.github.clash-verge-rev.clash-verge-rev"
CLASH_VERGE_RUNTIME_YAML = CLASH_VERGE_DIR / "clash-verge.yaml"

# 断网锁使用的 Anthropic 已知 IP 段。
ANTHROPIC_CIDRS_V4: List[str] = [
    "160.79.104.0/21",
    "34.36.57.103/32",
    "34.120.108.227/32",
    "35.190.46.17/32",
]

ANTHROPIC_CIDRS_V6: List[str] = [
    "2607:6bc0::/48",
]

# 物理网卡锁 DNS 时写入的安全境外 DNS（防止回落至本地运营商 DNS）
LOCKED_DNS_SERVERS: List[str] = ["1.1.1.1", "8.8.8.8"]

# 主流代理客户端进程与其所属客户端家族（同家族的壳与内核同时运行不视为冲突）
KNOWN_PROXY_CLIENTS: Dict[str, str] = {
    "verge-mihomo.exe": "Clash Verge (Mihomo)",
    "verge-mihomo-alpha.exe": "Clash Verge (Mihomo Alpha)",
    "clash-verge.exe": "Clash Verge",
    "mihomo.exe": "Mihomo 内核",
    "flclash.exe": "FlClash",
    "mihomo-party.exe": "Mihomo Party",
    "clash-nyanpasu.exe": "Clash Nyanpasu",
    "clash for windows.exe": "Clash for Windows",
    "v2rayn.exe": "v2rayN",
    "v2ray.exe": "V2Ray 内核",
    "xray.exe": "Xray 内核",
    "sing-box.exe": "sing-box",
    "hiddify.exe": "Hiddify",
    "nekoray.exe": "Nekoray",
    "nekobox.exe": "NekoBox",
    "warp-svc.exe": "Cloudflare WARP",
    "tailscaled.exe": "Tailscale",
    "mullvad-daemon.exe": "Mullvad VPN",
    "nordvpn-service.exe": "NordVPN",
    "protonvpnservice.exe": "ProtonVPN",
}

PROXY_CLIENT_FAMILIES: Dict[str, str] = {
    "verge-mihomo.exe": "clash-verge",
    "verge-mihomo-alpha.exe": "clash-verge",
    "clash-verge.exe": "clash-verge",
    "flclash.exe": "flclash",
    "mihomo-party.exe": "mihomo-party",
    "clash-nyanpasu.exe": "clash-nyanpasu",
    "clash for windows.exe": "cfw",
    "v2rayn.exe": "v2rayn",
    "hiddify.exe": "hiddify",
    "nekoray.exe": "nekobox",
    "nekobox.exe": "nekobox",
    "warp-svc.exe": "warp",
    "tailscaled.exe": "tailscale",
    "mullvad-daemon.exe": "mullvad",
    "nordvpn-service.exe": "nordvpn",
    "protonvpnservice.exe": "protonvpn",
}

PROXY_CORE_EXECUTABLES: Dict[str, str] = {
    "mihomo.exe": "core:mihomo",
    "v2ray.exe": "core:v2ray",
    "xray.exe": "core:xray",
    "sing-box.exe": "core:sing-box",
}

# 游戏加速器与已知旧版残留（始终视为路由/规则冲突风险）
ACCELERATOR_PROCESSES: Dict[str, str] = {
    "cc-hahaeasy-daemon.exe": "cc-hahaeasy 守护服务（残留）",
    "uu.exe": "网易 UU 加速器",
    "leigod.exe": "雷神加速器",
    "xunyou.exe": "迅游加速器",
    "qiyou.exe": "奇游加速器",
}

# 保留历史导出字典名以兼容旧引用
CONFLICT_PROCESSES: Dict[str, str] = {
    **ACCELERATOR_PROCESSES,
    **{k: v for k, v in KNOWN_PROXY_CLIENTS.items() if k not in ("verge-mihomo.exe", "verge-mihomo-alpha.exe", "clash-verge.exe")},
}

# 常用 IANA 时区 -> Windows tzutil 时区 ID 映射
IANA_TO_WINDOWS_TZ: Dict[str, str] = {
    "America/Los_Angeles": "Pacific Standard Time",
    "America/Vancouver": "Pacific Standard Time",
    "America/Denver": "Mountain Standard Time",
    "America/Phoenix": "US Mountain Standard Time",
    "America/Chicago": "Central Standard Time",
    "America/New_York": "Eastern Standard Time",
    "America/Toronto": "Eastern Standard Time",
    "America/Detroit": "Eastern Standard Time",
    "America/Anchorage": "Alaskan Standard Time",
    "Pacific/Honolulu": "Hawaiian Standard Time",
    "Europe/London": "GMT Standard Time",
    "Europe/Dublin": "GMT Standard Time",
    "Europe/Paris": "Romance Standard Time",
    "Europe/Berlin": "W. Europe Standard Time",
    "Europe/Amsterdam": "W. Europe Standard Time",
    "Europe/Zurich": "W. Europe Standard Time",
    "Europe/Stockholm": "W. Europe Standard Time",
    "Europe/Warsaw": "Central European Standard Time",
    "Asia/Tokyo": "Tokyo Standard Time",
    "Asia/Seoul": "Korea Standard Time",
    "Asia/Singapore": "Singapore Standard Time",
    "Asia/Kuala_Lumpur": "Singapore Standard Time",
    "Asia/Taipei": "Taipei Standard Time",
    "Asia/Shanghai": "China Standard Time",
    "Asia/Hong_Kong": "China Standard Time",
    "Asia/Ho_Chi_Minh": "SE Asia Standard Time",
    "Asia/Bangkok": "SE Asia Standard Time",
    "Australia/Sydney": "AUS Eastern Standard Time",
    "Australia/Melbourne": "AUS Eastern Standard Time",
    "UTC": "UTC",
    "Etc/UTC": "UTC",
}


@dataclass
class GuardConfig:
    monitored_probe_ip: str = ""
    poll_interval_sec: int = 60
    fast_watch_interval_sec: int = 3
    alert_sound: bool = True
    auto_kill_claude_on_critical: bool = False
    protection_enabled: bool = False
    extra_claude_exes: List[str] = field(default_factory=list)


@dataclass
class SystemBackup:
    original_timezone: Optional[str] = None
    ipv6_disabled_adapters: List[str] = field(default_factory=list)
    dns_backup: Dict[str, List[str]] = field(default_factory=dict)
    webrtc_modified: bool = False
    webrtc_previous: Dict[str, Optional[List[Any]]] = field(default_factory=dict)


def _ensure_state_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> GuardConfig:
    _ensure_state_dir()
    if not CONFIG_FILE.exists():
        return GuardConfig()
    try:
        raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        valid_keys = {f.name for f in GuardConfig.__dataclass_fields__.values()}
        filtered = {k: v for k, v in raw.items() if k in valid_keys}
        cfg = GuardConfig(**filtered)
        if not isinstance(cfg.monitored_probe_ip, str):
            cfg.monitored_probe_ip = ""
        if type(cfg.poll_interval_sec) is not int or cfg.poll_interval_sec < 15:
            cfg.poll_interval_sec = GuardConfig.poll_interval_sec
        if type(cfg.fast_watch_interval_sec) is not int or not 2 <= cfg.fast_watch_interval_sec <= 15:
            cfg.fast_watch_interval_sec = GuardConfig.fast_watch_interval_sec
        if type(cfg.auto_kill_claude_on_critical) is not bool:
            cfg.auto_kill_claude_on_critical = False
        if not isinstance(cfg.extra_claude_exes, list) or not all(isinstance(p, str) for p in cfg.extra_claude_exes):
            cfg.extra_claude_exes = []
        return cfg
    except Exception:
        return GuardConfig()


def save_config(cfg: GuardConfig) -> None:
    _save_json(CONFIG_FILE, asdict(cfg))


def load_backup() -> SystemBackup:
    _ensure_state_dir()
    if not BACKUP_FILE.exists():
        return SystemBackup()
    try:
        raw = json.loads(BACKUP_FILE.read_text(encoding="utf-8"))
        valid_keys = {f.name for f in SystemBackup.__dataclass_fields__.values()}
        filtered = {k: v for k, v in raw.items() if k in valid_keys}
        backup = SystemBackup(**filtered)
        if not isinstance(backup.dns_backup, dict) or not all(
            isinstance(servers, list) and all(isinstance(server, str) for server in servers)
            for servers in backup.dns_backup.values()
        ):
            raise ValueError("DNS 备份格式无效")
        if not isinstance(backup.ipv6_disabled_adapters, list) or not all(
            isinstance(adapter, str) for adapter in backup.ipv6_disabled_adapters
        ):
            raise ValueError("IPv6 备份格式无效")
        if not isinstance(backup.webrtc_previous, dict):
            raise ValueError("WebRTC 备份格式无效")
        if not all(
            value is None or (isinstance(value, list) and len(value) == 2 and type(value[0]) is int)
            for value in backup.webrtc_previous.values()
        ):
            raise ValueError("WebRTC 备份值类型无效")
        if backup.original_timezone is not None and not isinstance(backup.original_timezone, str):
            raise ValueError("时区备份格式无效")
        return backup
    except (OSError, ValueError, AttributeError, TypeError) as exc:
        raise ValueError(f"无法读取系统备份 {BACKUP_FILE.name}：{exc}") from exc


def save_backup(backup: SystemBackup) -> None:
    _save_json(BACKUP_FILE, asdict(backup))


def _save_json(path: Path, data: Dict[str, Any]) -> None:
    _ensure_state_dir()
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.stem}.", suffix=".tmp", delete=False
    ) as file:
        temporary = Path(file.name)
        try:
            json.dump(data, file, ensure_ascii=False, indent=2)
            file.flush()
            os.fsync(file.fileno())
            file.close()
            for attempt in range(5):
                try:
                    temporary.replace(path)
                    break
                except PermissionError:
                    if attempt == 4:
                        raise
                    # Windows readers may briefly hold the destination without share-delete.
                    time.sleep(0.02 * (attempt + 1))
        finally:
            file.close()
            temporary.unlink(missing_ok=True)
