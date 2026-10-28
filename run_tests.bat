@echo off
cd /d "%~dp0"
if not exist .venv ( py -3 -m venv .venv )
call .venv\Scripts\activate
python -m pip install -q -r requirements.txt
python tests\test_core.py
pause
