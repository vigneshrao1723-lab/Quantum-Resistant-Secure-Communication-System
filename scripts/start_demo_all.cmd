@echo off
rem Start the demo stack, then open the Desktop application and demo_bob's Website.
rem   1. scripts\start_demo.py  (checks, then server + gateway + Website on the demo database)
rem   2. only if that succeeded: QRSCS-Desktop.exe, then scripts\open_demo_website.cmd
rem If the executable is missing, the venv-pythonw fallback launcher is used instead.
setlocal
cd /d "%~dp0.."

echo Starting the QRSCS demo stack...
"%~dp0..\venv\Scripts\python.exe" scripts\start_demo.py
if errorlevel 1 (
    echo.
    echo The demo stack did not start, so no application was opened.
    pause
    exit /b 1
)

echo.
echo Opening the Desktop application and the Website...
if exist "%~dp0..\dist\desktop\QRSCS-Desktop\QRSCS-Desktop.exe" (
    start "" "%~dp0..\dist\desktop\QRSCS-Desktop\QRSCS-Desktop.exe"
) else (
    echo QRSCS-Desktop.exe not found; using the fallback launcher.
    call "%~dp0launch_desktop_fallback.cmd"
)
call "%~dp0open_demo_website.cmd"

echo.
echo Done. To stop everything later, use the "Stop QRSCS demo" shortcut.
timeout /t 8 >nul
exit /b 0
