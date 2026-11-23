"""macOS 本机只读探测与进程互斥。"""

from __future__ import annotations

import os
import re
import subprocess
import time
from contextlib import contextmanager
from ipaddress import ip_address
from pathlib import Path

from .config import STATE_DIR

MIHOMO_NAMES = {"verge-mihomo", "verge-mihomo-alpha"}


class MacInstanceLock:
    def __init__(self, name: str = "instance.lock") -> None:
        self._path = STATE_DIR / name
        self._file = None

    def acquire(self, wait_sec: float = 0.0) -> bool:
        import fcntl

        self._path.parent.mkdir(parents=True, exist_ok=True)
        handle = self._path.open("ab")
        deadline = time.monotonic() + wait_sec
        try:
            while True:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        return False
                    time.sleep(0.05)
                else:
                    self._file = handle
                    return True
        finally:
            if self._file is not handle:
                handle.close()

    def release(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None


@contextmanager
def settings_lock():
    lock = MacInstanceLock("settings.lock")
    acquired = lock.acquire()
    try:
        yield acquired
    finally:
        lock.release()


def run_command(*args: str) -> str | None:
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=4, env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def default_route_interface() -> str:
    # 查路由表，route get 不向该地址发送数据包。
    result = run_command("/sbin/route", "-n", "get", "-inet", "1.1.1.1")
    match = re.search(r"^\s*interface:\s+(\S+)", result or "", re.MULTILINE)
    return match[1] if match else ""


def is_tunnel_interface(interface: str) -> bool:
    return re.fullmatch(r"utun\d+", interface) is not None


def default_dns_servers() -> list[str]:
    output = run_command("/usr/sbin/scutil", "--dns") or ""
    unscoped = output.partition("DNS configuration (for scoped queries)")[0]
    default_resolver = re.split(r"(?m)^\s*resolver #\d+\s*$", unscoped, maxsplit=2)
    if len(default_resolver) < 2:
        return []
    return re.findall(r"(?m)^\s*nameserver\[\d+\]\s*:\s*(\S+)", default_resolver[1])


def timezone_name() -> str:
    try:
        return os.readlink("/etc/localtime").partition("/zoneinfo/")[2]
    except OSError:
        return ""


def play_alert_beep() -> None:
    from AppKit import NSBeep
    from PyObjCTools import AppHelper

    AppHelper.callAfter(NSBeep)


def process_paths() -> list[str] | None:
    result = run_command("/bin/ps", "-axo", "comm=")
    return None if result is None else [line.strip() for line in result.splitlines() if line.strip()]


def parse_tcp_listeners(output: str, port: int) -> list[tuple[str, int]]:
    """兼容 netstat 的独立 pid 列与较新版本的 process:pid 列。"""
    listeners = []
    pid_column = None
    named_pid = False
    for line in output.splitlines():
        columns = line.strip().replace("Local Address", "LocalAddress").replace("Foreign Address", "ForeignAddress").split()
        if not columns:
            continue
        if columns[0] == "Proto":
            pid_column = next((i for i, column in enumerate(columns) if column in {"pid", "process:pid"}), None)
            named_pid = "process:pid" in columns
            continue
        if not columns[0].startswith("tcp") or len(columns) <= 5 or columns[5] != "LISTEN":
            continue
        address, _, local_port = columns[3].rpartition(".")
        if local_port != str(port):
            continue
        owner = ""
        if pid_column is not None and pid_column < len(columns):
            if named_pid:
                pid_field = line.split(maxsplit=pid_column)[pid_column]
                match = re.match(r"[^:\n]{0,16}:([0-9]+)(?:\s|$)", pid_field)
                owner = match[1] if match else ""
            else:
                owner = columns[pid_column]
        listeners.append((address, int(owner) if owner.isascii() and owner.isdecimal() else 0))
    return listeners


def verify_proxy_listener(port: int) -> bool:
    # netstat 从内核读取监听地址与 PID，可覆盖 Clash 服务模式的 root 进程。
    output = run_command("/usr/sbin/netstat", "-anv", "-p", "tcp") or ""
    listeners = parse_tcp_listeners(output, port)
    if not any(address == "127.0.0.1" for address, _ in listeners):
        return False
    for address, pid in listeners:
        try:
            loopback = ip_address(address).is_loopback
        except ValueError:
            return False
        if not loopback or pid <= 0:
            return False

    for pid in {pid for _, pid in listeners}:
        owner = run_command("/bin/ps", "-p", str(pid), "-o", "comm=") or ""
        if Path(owner.strip()).name not in MIHOMO_NAMES:
            return False
    return True
