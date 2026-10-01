@echo off
rem Starts Secure Login and opens it in the browser. Needs Python 3.10 or newer.
rem The first run sets up a virtual environment and installs the dependencies.
cd /d "%~dp0"
if not exist .venv\Scripts\flask.exe (
    echo Setting up. This takes a minute the first time...
    python -m venv .venv || goto :failed
    .venv\Scripts\python.exe -m pip install --quiet -e . || goto :failed
)
.venv\Scripts\python.exe -m secure_login --open
goto :eof

:failed
echo.
echo Setup failed. Check that Python 3.10 or newer is installed and that you are online.
pause
