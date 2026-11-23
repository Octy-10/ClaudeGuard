@echo off
chcp 65001 >nul
setlocal

set "CG_DIR=%~dp0"
set "CG_PY=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
if not exist "%CG_PY%" (
    for /f "delims=" %%i in ('where python 2^>nul ^| findstr /I /V "WindowsApps"') do (
        set "CG_PY=%%i"
        goto :found_py
    )
)

:found_py
if not exist "%CG_PY%" (
    echo [错误] 未找到 python.exe，请确认已安装 Python 3.10+。
    pause
    exit /b 1
)

echo 正在请求管理员权限并执行 Claude Guard 紧急网络恢复 (Rescue)...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$q=[char]34; $app=Join-Path $env:CG_DIR 'app.py'; Start-Process -FilePath $env:CG_PY -ArgumentList ($q+$app+$q+' --rescue') -WorkingDirectory $env:CG_DIR -Verb RunAs -Wait -PassThru -ErrorAction Stop | ForEach-Object { exit $_.ExitCode }"
set "CG_RESCUE_EXIT=%ERRORLEVEL%"
echo.
if not "%CG_RESCUE_EXIT%"=="0" echo 部分恢复失败，请保留备份并查看恢复日志。
echo 恢复流程已结束。如未看到窗口输出，可右键以管理员身份打开终端执行：python "%CG_DIR%app.py" --rescue
pause
exit /b %CG_RESCUE_EXIT%
