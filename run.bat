@echo off
cd /d "%~dp0"
where py >nul 2>nul || (echo Python not found. Install from https://www.python.org/downloads/ and tick "Add python.exe to PATH". & pause & exit /b 1)
if not exist .venv ( py -3 -m venv .venv || (echo Could not create environment. & pause & exit /b 1) )
call .venv\Scripts\activate
python -m pip install -q -r requirements.txt || (echo Install failed - check internet connection. & pause & exit /b 1)
python timelock_app.py
if errorlevel 1 pause
