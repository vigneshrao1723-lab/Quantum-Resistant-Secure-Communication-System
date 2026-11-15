@echo off
rem Stop the demo stack that start_demo.py started (and nothing else).
setlocal
cd /d "%~dp0.."
"%~dp0..\venv\Scripts\python.exe" scripts\stop_demo.py %*
set CODE=%ERRORLEVEL%
pause
exit /b %CODE%
