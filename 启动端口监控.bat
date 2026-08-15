@echo off
chcp 65001 >nul
cd /d "%~dp0"

where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw "%~dp0port_monitor.py"
    goto :eof
)
where pyw >nul 2>nul
if %errorlevel%==0 (
    start "" pyw "%~dp0port_monitor.py"
    goto :eof
)
echo 未找到 Python，请先安装 Python 3.8+ 并勾选 "Add Python to PATH"。
pause
