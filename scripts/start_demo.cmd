@echo off
rem Start the local demo stack (server, web gateway, Website on 8010) with the repo venv.
rem See scripts\start_demo.py for what it checks. Extra arguments are passed through.
setlocal
cd /d "%~dp0.."
"%~dp0..\venv\Scripts\python.exe" scripts\start_demo.py %*
set CODE=%ERRORLEVEL%
if not "%CODE%"=="0" echo. & echo Start-up did not complete ^(exit code %CODE%^).
pause
exit /b %CODE%
