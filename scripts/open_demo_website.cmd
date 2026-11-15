@echo off
rem Open the Website in the dedicated Chrome profile that holds demo_bob's identity keys.
rem (A different browser or profile would be a NEW device for that account.)
rem Start the demo stack first: scripts\start_demo.cmd
start "" chrome --user-data-dir="%USERPROFILE%\.qrscs\demo-chrome-bob" --no-first-run "http://127.0.0.1:8010/"
exit /b 0
