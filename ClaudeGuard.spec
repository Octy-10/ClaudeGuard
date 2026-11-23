# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包规格：生成单文件无黑框 Windows 桌面程序 ClaudeGuard.exe。"""

from PyInstaller.utils.hooks import collect_all

datas = [
    ("web", "web"),
    ("assets", "assets"),
    ("clash-verge-override.js", "."),
]
binaries = []
hiddenimports = ["yaml", "guard.ui"]

for pkg in ("webview", "pythonnet", "clr_loader", "certifi"):
    pkg_datas, pkg_bins, pkg_hidden = collect_all(pkg)
    datas += pkg_datas
    binaries += pkg_bins
    hiddenimports += pkg_hidden

a = Analysis(
    ["app.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "unittest", "PIL", "pytest", "pydoc", "doctest"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ClaudeGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="assets/icon.ico",
)
