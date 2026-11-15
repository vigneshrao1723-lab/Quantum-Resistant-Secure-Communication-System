@echo off
rem Fallback Desktop launcher: runs main.py from source through the repo venv's pythonw.exe.
rem pythonw.exe is signed by the Python Software Foundation, so this works even where the unsigned
rem QRSCS-Desktop.exe is blocked by Windows application control (e.g. Smart App Control).
rem The Desktop app connects to the server set in .env (SERVER_HOST / SERVER_PORT, 127.0.0.1:5000),
rem so start the demo stack first: scripts\start_demo.cmd
setlocal
cd /d "%~dp0.."
if not exist "%~dp0..\venv\Scripts\pythonw.exe" (
    echo The repository virtual environment is missing: venv\Scripts\pythonw.exe
    pause
    exit /b 2
)
start "" "%~dp0..\venv\Scripts\pythonw.exe" main.py
exit /b 0
