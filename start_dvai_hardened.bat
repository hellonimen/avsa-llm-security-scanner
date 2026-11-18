@echo off
setlocal
cd /d "%~dp0"

echo === DVAI-hardened (Defend-phase / token spotlighting) launcher ===
echo.

set "VENV_PY=%~dp0dvai\.venv\Scripts\python.exe"

if not exist "%VENV_PY%" (
    echo ERROR: could not find the DVAI virtual environment's python.exe at:
    echo   %VENV_PY%
    echo This script reuses dvai's own venv rather than creating a second one.
    echo Make sure dvai\.venv exists and try again.
    echo.
    pause
    exit /b 1
)
echo Using Python: %VENV_PY%
echo.

echo Checking if something is already listening on port 5001...
curl -s -o nul --max-time 2 http://127.0.0.1:5001/login
if %errorlevel%==0 (
    echo Something is already answering on port 5001 - reusing it, not starting a second copy.
    goto :done
)
echo Nothing answered on port 5001 - will seed and start DVAI-hardened now.
echo.

echo Seeding dvai_hardened's own database - idempotent, safe to re-run...
pushd "%~dp0dvai_hardened"
"%VENV_PY%" seed.py
set SEED_RESULT=%errorlevel%
popd
if not %SEED_RESULT%==0 (
    echo.
    echo ERROR: seeding dvai_hardened failed - see the Python output above for the real error.
    echo.
    pause
    exit /b 1
)
echo Seeding done.
echo.

echo Starting DVAI-hardened in its own window now...
start "DVAI-hardened (port 5001)" /D "%~dp0dvai_hardened" cmd /k "%VENV_PY%" app.py

echo Waiting a few seconds for it to come up...
timeout /t 3 /nobreak >nul

:done
echo.
echo DVAI-hardened should now be on port 5001. The real DVAI on port 5000 is completely untouched.
echo In the AVSA GUI, set Target to http://127.0.0.1:5001 (User stays alice) and Run Full Scan.
echo Only Prompt Injection is expected to flip to absent - IDOR/SQLi/XSS are deliberately still there.
echo.
echo This window is just the launcher and can be closed. The actual server runs in the
echo OTHER window titled "DVAI-hardened (port 5001)". Close THAT one to stop the server.
echo.
pause
