# -*- mode: python ; coding: utf-8 -*-
"""在 macOS 上打包 ClaudeGuard.app。"""

from runpy import run_path
from os import environ

version = run_path("guard/__init__.py")["__version__"]

a = Analysis(
    ["app.py"],
    pathex=["."],
    datas=[("web", "web"), ("assets", "assets"), ("clash-macos-probe.js", ".")],
    hiddenimports=["yaml", "webview.platforms.cocoa"],
    excludes=["pythonnet", "clr_loader", "tkinter"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [], exclude_binaries=True, name="ClaudeGuard", console=False, upx=False,
    codesign_identity=environ.get("MACOS_APPLICATION_IDENTITY"),
)
distribution = COLLECT(exe, a.binaries, a.datas, name="ClaudeGuard", upx=False)
app = BUNDLE(
    distribution,
    name="ClaudeGuard.app",
    bundle_identifier="io.github.octy-10.claudeguard",
    icon="assets/icon-256.png",
    version=version,
)
