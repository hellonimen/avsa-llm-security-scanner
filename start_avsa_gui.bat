@echo off
setlocal
cd /d "%~dp0"

echo === AVSA GUI launcher ===
echo.

curl -s -o nul --max-time 2 http://127.0.0.1:5000/login
if %errorlevel%==0 (
    echo DVAI already running on port 5000 - reusing it.
) else (
    echo Starting DVAI...
    start "DVAI (port 5000)" cmd /k "cd /d "%~dp0dvai" && .venv\Scripts\python.exe app.py"
    timeout /t 3 /nobreak >nul
)

curl -s -o nul --max-time 2 http://127.0.0.1:5050/
if %errorlevel%==0 (
    echo AVSA GUI already running on port 5050 - reusing it.
) else (
    echo Installing/checking Flask...
    pip install --quiet flask
    echo Starting AVSA GUI...
    start "AVSA GUI (port 5050)" cmd /k "cd /d "%~dp0" && python -m avsa_gui.app"
    timeout /t 3 /nobreak >nul
)

echo Opening browser...
start http://127.0.0.1:5050/

echo.
echo Two windows should now be open: DVAI (port 5000) and AVSA GUI (port 5050).
echo Leave both open while you use the scanner. This launcher window can be closed.
echo.
pause
