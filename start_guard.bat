@echo off
setlocal

set "CG_DIR=%~dp0"
set "CG_PY=%LOCALAPPDATA%\Programs\Python\Python310\pythonw.exe"
if not exist "%CG_PY%" (
    for /f "delims=" %%i in ('where pythonw 2^>nul ^| findstr /I /V "WindowsApps"') do (
        set "CG_PY=%%i"
        goto :found_pyw
    )
)

:found_pyw
if not exist "%CG_PY%" (
    echo [ERROR] pythonw.exe not found. Please install Python 3.10+.
    pause
    exit /b 1
)

rem Launch Claude Guard GUI elevated via env vars (100%% safe for Unicode paths)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$q=[char]34; $app=Join-Path $env:CG_DIR 'app.py'; Start-Process -FilePath $env:CG_PY -ArgumentList ($q+$app+$q) -WorkingDirectory $env:CG_DIR -Verb RunAs"
