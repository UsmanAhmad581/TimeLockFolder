@echo off
cd /d "%~dp0"
if not exist .venv ( py -3 -m venv .venv )
call .venv\Scripts\activate
python -m pip install -q -r requirements.txt pyinstaller
pyinstaller --onefile --windowed --name TimeLockFolder timelock_app.py
echo.
echo Done. Your program is: dist\TimeLockFolder.exe
pause
