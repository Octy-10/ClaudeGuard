"""GitHub Releases 自动更新检查、SHA-256 校验下载与 Windows 自替换重启。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from . import __version__
from .clash_config import PROBE_PORT, read_config
from .config import CLASH_VERGE_RUNTIME_YAML
from .net import build_ssl_context
from .sysutil import CREATE_NO_WINDOW, ps_quote

GITHUB_REPO = "Octy-10/ClaudeGuard"
MANIFEST_URL = f"https://github.com/{GITHUB_REPO}/releases/latest/download/latest.json"
RELEASES_LATEST_URL = f"https://github.com/{GITHUB_REPO}/releases/latest"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ASSET_BYTES = 128 * 1024 * 1024
UPDATE_USER_AGENT = "ClaudeGuard-Updater/1.0"
STAGED_FILENAME = "ClaudeGuard.update.tmp"
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


@dataclass
class UpdateInfo:
    """远程更新清单与当前安装状态快照。"""

    current_version: str
    latest_version: str = ""
    available: bool = False
    asset: str = ""
    sha256: str = ""
    download_url: str = ""
    release_url: str = RELEASES_LATEST_URL
    notes: str = ""
    can_self_update: bool = False
    checked_at: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_version(version: str) -> tuple[int, ...]:
    """提取版本号中的主数字段用于语义化比较，忽略前导 v 与预发布后缀。"""
    cleaned = str(version or "").strip().lstrip("vV")
    base = cleaned.split("-", 1)[0].split("+", 1)[0]
    parts: list[int] = []
    for seg in base.split("."):
        match = re.match(r"^\d+", seg.strip())
        if not match:
            break
        parts.append(int(match.group(0)))
    return tuple(parts) if parts else (0,)


def is_newer_version(remote: str, current: str) -> bool:
    """比较远程版本号是否严格高于本地版本号。"""
    remote_parts = parse_version(remote)
    current_parts = parse_version(current)
    width = max(len(remote_parts), len(current_parts))
    r_pad = remote_parts + (0,) * (width - len(remote_parts))
    c_pad = current_parts + (0,) * (width - len(current_parts))
    return r_pad > c_pad


def is_allowed_update_url(url: str) -> bool:
    """仅允许 HTTPS 协议的 github.com 或 *.githubusercontent.com 地址。"""
    if not isinstance(url, str) or not url.strip():
        return False
    try:
        parsed = urlsplit(url.strip())
    except ValueError:
        return False
    if parsed.scheme.lower() != "https" or parsed.username or parsed.password:
        return False
    if parsed.port not in (None, 443):
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    return host == "github.com" or (host.endswith(".githubusercontent.com") and len(host) > len(".githubusercontent.com"))


def _valid_port(value: Any) -> Optional[int]:
    if type(value) is int and 1 <= value <= 65535:
        return value
    return None


def detect_local_proxy_port() -> Optional[int]:
    """从 Clash Verge 运行时配置探测可用的本地 HTTP/Mixed 代理端口。"""
    try:
        cfg = read_config(CLASH_VERGE_RUNTIME_YAML)
    except Exception:
        return None
    for key in ("mixed-port", "port"):
        port = _valid_port(cfg.get(key))
        if port and port != PROBE_PORT:
            return port
    listeners = cfg.get("listeners")
    if isinstance(listeners, list):
        for entry in listeners:
            if isinstance(entry, dict) and _valid_port(entry.get("port")) == PROBE_PORT:
                return PROBE_PORT
    return None


_build_ssl_context = build_ssl_context


def _open_https(
    url: str,
    *,
    proxy_port: Optional[int],
    timeout: float,
    max_redirects: int = 5,
) -> Tuple[http.client.HTTPSConnection, http.client.HTTPResponse]:
    """发起 HTTPS GET 请求并按白名单跟随重定向。"""
    ctx = _build_ssl_context()
    current_url = url
    for _ in range(max_redirects + 1):
        if not is_allowed_update_url(current_url):
            raise ValueError(f"更新地址不在安全白名单内：{current_url}")
        endpoint = urlsplit(current_url)
        host = endpoint.hostname or ""
        port = endpoint.port or 443
        if proxy_port is not None:
            conn = http.client.HTTPSConnection("127.0.0.1", proxy_port, timeout=timeout, context=ctx)
            conn.set_tunnel(host, port)
        else:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)

        resource = endpoint.path or "/"
        if endpoint.query:
            resource += "?" + endpoint.query

        closed = False
        try:
            conn.request(
                "GET",
                resource,
                headers={
                    "Host": endpoint.netloc,
                    "User-Agent": UPDATE_USER_AGENT,
                    "Accept": "application/json, application/octet-stream, */*",
                },
            )
            resp = conn.getresponse()
            if resp.status in _REDIRECT_STATUSES:
                location = resp.getheader("Location")
                resp.close()
                conn.close()
                closed = True
                if not location:
                    raise http.client.HTTPException(f"重定向缺少 Location（HTTP {resp.status}）")
                current_url = urljoin(current_url, location.strip())
                continue
            if not (200 <= resp.status < 300):
                status = resp.status
                resp.close()
                conn.close()
                closed = True
                raise http.client.HTTPException(f"HTTP {status}")
            return conn, resp
        except Exception:
            if not closed:
                conn.close()
            raise

    raise ValueError("更新重定向次数过多")


def _fetch_with_fallback(
    url: str,
    *,
    timeout: float,
    reader: Callable[[http.client.HTTPSConnection, http.client.HTTPResponse], Any],
) -> Any:
    """优先经由 Clash 本地代理通道访问 GitHub，失败时回退直连。"""
    proxy_port = detect_local_proxy_port()
    candidates = [proxy_port, None] if proxy_port is not None else [None]
    last_exc: Optional[Exception] = None
    for port in candidates:
        conn: Optional[http.client.HTTPSConnection] = None
        resp: Optional[http.client.HTTPResponse] = None
        try:
            conn, resp = _open_https(url, proxy_port=port, timeout=timeout)
            return reader(conn, resp)
        except (OSError, http.client.HTTPException) as exc:
            last_exc = exc
        finally:
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
    assert last_exc is not None
    raise last_exc


def check_for_update(current_version: str = __version__, timeout: float = 10.0) -> UpdateInfo:
    """请求 GitHub Releases 的 latest.json 清单并校验版本与签名元数据。"""
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    can_self = bool(getattr(sys, "frozen", False))

    def _read_manifest(_conn: http.client.HTTPSConnection, resp: http.client.HTTPResponse) -> dict[str, Any]:
        raw = resp.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ValueError("更新清单体积超出限制")
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("更新清单格式无效")
        return data

    try:
        data = _fetch_with_fallback(MANIFEST_URL, timeout=timeout, reader=_read_manifest)
        latest = str(data.get("version") or "").strip().lstrip("vV")
        if not latest or not re.search(r"\d", latest):
            raise ValueError("更新清单缺少有效版本号")
        sha256 = str(data.get("sha256") or "").strip().lower()
        if not _SHA256_RE.fullmatch(sha256):
            raise ValueError("更新清单缺少合法 SHA-256 校验值")
        download_url = str(data.get("url") or "").strip()
        if not is_allowed_update_url(download_url):
            raise ValueError("更新包下载地址不在 GitHub 白名单内")
        release_url = str(data.get("release_url") or "").strip()
        if not is_allowed_update_url(release_url):
            release_url = RELEASES_LATEST_URL
        asset = str(data.get("asset") or "ClaudeGuard.exe").strip() or "ClaudeGuard.exe"
        notes = str(data.get("notes") or "").strip()
        return UpdateInfo(
            current_version=current_version,
            latest_version=latest,
            available=is_newer_version(latest, current_version),
            asset=asset,
            sha256=sha256,
            download_url=download_url,
            release_url=release_url,
            notes=notes,
            can_self_update=can_self,
            checked_at=checked_at,
        )
    except Exception as exc:
        return UpdateInfo(
            current_version=current_version,
            available=False,
            can_self_update=can_self,
            checked_at=checked_at,
            error=str(exc),
        )


def download_update(
    info: UpdateInfo,
    dest_dir: Path,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    timeout: float = 60.0,
) -> Path:
    """流式下载更新包至同目录临时文件，并强校验 PE 魔数与 SHA-256。"""
    if not is_allowed_update_url(info.download_url):
        raise ValueError("更新包下载地址不在安全白名单内")
    expected_sha = str(info.sha256 or "").strip().lower()
    if not _SHA256_RE.fullmatch(expected_sha):
        raise ValueError("更新包缺少合法的 SHA-256 校验值")

    dest_dir.mkdir(parents=True, exist_ok=True)
    staged = dest_dir / STAGED_FILENAME

    def _stream(_conn: http.client.HTTPSConnection, resp: http.client.HTTPResponse) -> Path:
        raw_len = (resp.getheader("Content-Length") or "").strip()
        total = int(raw_len) if raw_len.isdigit() else 0
        if total > MAX_ASSET_BYTES:
            raise ValueError("更新包体积超出安全上限")

        hasher = hashlib.sha256()
        downloaded = 0
        header = b""
        try:
            with staged.open("wb") as handle:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > MAX_ASSET_BYTES:
                        raise ValueError("更新包下载体积超出安全上限")
                    if len(header) < 2:
                        header += chunk[: 2 - len(header)]
                    hasher.update(chunk)
                    handle.write(chunk)
                    if progress_cb:
                        progress_cb(downloaded, total)
            if downloaded == 0 or header != b"MZ":
                raise ValueError("下载的文件不是有效的 Windows 可执行程序")
            actual_sha = hasher.hexdigest().lower()
            if not hmac.compare_digest(actual_sha, expected_sha):
                raise ValueError("SHA-256 校验失败，已自动清理损坏文件")
        except Exception:
            staged.unlink(missing_ok=True)
            raise
        if progress_cb:
            progress_cb(downloaded, total or downloaded)
        return staged

    try:
        return _fetch_with_fallback(info.download_url, timeout=timeout, reader=_stream)
    except Exception:
        staged.unlink(missing_ok=True)
        raise


def cleanup_update_artifacts(exe_path: Optional[Path] = None) -> None:
    """清理上一次自更新残留的 .old 备份与临时下载文件。"""
    target = exe_path
    if target is None:
        if not getattr(sys, "frozen", False):
            return
        target = Path(sys.executable)
    try:
        resolved = target.resolve()
        for leftover in (Path(f"{resolved}.old"), resolved.parent / STAGED_FILENAME):
            leftover.unlink(missing_ok=True)
    except OSError:
        pass


def build_replace_ps_script(staged_exe: Path, target_exe: Path, pid: int) -> str:
    """生成等待旧进程退出、备份覆盖并带 --handoff 重启新版的 PowerShell 脚本。"""
    staged_q = ps_quote(str(staged_exe))
    target_q = ps_quote(str(target_exe))
    backup_q = ps_quote(f"{target_exe}.old")
    work_dir_q = ps_quote(str(target_exe.parent))
    return (
        "$ErrorActionPreference = 'Stop'\n"
        f"$targetPid = {int(pid)}\n"
        f"$staged = {staged_q}\n"
        f"$target = {target_q}\n"
        f"$backup = {backup_q}\n"
        f"$workDir = {work_dir_q}\n"
        "for ($i = 0; $i -lt 60; $i++) {\n"
        "    if (-not (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) { break }\n"
        "    Start-Sleep -Milliseconds 500\n"
        "}\n"
        "$replaced = $false\n"
        "for ($j = 0; $j -lt 30; $j++) {\n"
        "    try {\n"
        "        if (Test-Path -LiteralPath $backup) {\n"
        "            Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue\n"
        "        }\n"
        "        if (Test-Path -LiteralPath $target) {\n"
        "            Move-Item -LiteralPath $target -Destination $backup -Force\n"
        "        }\n"
        "        Move-Item -LiteralPath $staged -Destination $target -Force\n"
        "        if (Test-Path -LiteralPath $backup) {\n"
        "            Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue\n"
        "        }\n"
        "        $replaced = $true\n"
        "        break\n"
        "    } catch {\n"
        "        if ((-not (Test-Path -LiteralPath $target)) -and (Test-Path -LiteralPath $backup)) {\n"
        "            Move-Item -LiteralPath $backup -Destination $target -Force -ErrorAction SilentlyContinue\n"
        "        }\n"
        "        Start-Sleep -Milliseconds 500\n"
        "    }\n"
        "}\n"
        "if ($replaced -and (Test-Path -LiteralPath $target)) {\n"
        "    Start-Process -FilePath $target -ArgumentList '--handoff' -WorkingDirectory $workDir\n"
        "}\n"
    )


def apply_update_and_restart(
    staged_exe: Path,
    target_exe: Optional[Path] = None,
    pid: Optional[int] = None,
) -> tuple[bool, str]:
    """启动隐藏独立 PowerShell 进程，在当前进程退出后覆盖 exe 并重启。"""
    if target_exe is None and not getattr(sys, "frozen", False):
        return False, "源码运行模式不支持自动覆盖可执行文件，请手动更新"

    target = (target_exe or Path(sys.executable)).resolve()
    staged = staged_exe.resolve()
    if not staged.is_file():
        return False, "更新包临时文件不存在，请重新下载"

    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".cg_perm_", suffix=".tmp", delete=True):
            pass
    except OSError:
        return False, "当前目录无写入权限，请以管理员身份运行或前往 GitHub 手动下载"

    script = build_replace_ps_script(staged, target, os.getpid() if pid is None else pid)
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    ps_exe = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        r"System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    clean_env = {k: v for k, v in os.environ.items() if not k.startswith(("_MEI", "_PYI_"))}
    try:
        subprocess.Popen(
            [ps_exe, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=clean_env,
            creationflags=CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )
    except OSError as exc:
        return False, f"无法启动更新替换进程：{exc}"

    return True, "正在覆盖旧版本并自动重启…"
