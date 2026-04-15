@echo off
title AEC Local Dev Server

echo.
echo  Applied Economics Club - Local Dev Server
echo  ------------------------------------------
echo  Site will open at: http://localhost:8000
echo  Press Ctrl+C to stop the server.
echo.

REM Try Python 3 first
python --version >nul 2>&1
if %errorlevel% == 0 (
    echo  Starting with Python...
    start "" "http://localhost:8000"
    python -m http.server 8000
    goto :done
)

REM Try py launcher (alternate Python install)
py --version >nul 2>&1
if %errorlevel% == 0 (
    echo  Starting with Python (py launcher)...
    start "" "http://localhost:8000"
    py -m http.server 8000
    goto :done
)

REM Fall back to Node / npx serve
node --version >nul 2>&1
if %errorlevel% == 0 (
    echo  Starting with Node (npx serve)...
    start "" "http://localhost:8000"
    npx serve -p 8000 -s .
    goto :done
)

REM Nothing found
echo  ERROR: Neither Python nor Node was found on this machine.
echo  Install either from https://www.python.org or https://nodejs.org
echo  then re-run this file.
pause

:done
