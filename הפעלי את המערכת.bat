@echo off
chcp 65001 >nul
echo.
echo  ====================================
echo   מערכת מסכי הבניין מתחילה...
echo  ====================================
echo.
echo  המתיני כמה שניות...
echo.

cd /d "%~dp0"
start "" "http://localhost:3000/screen1"
start "" "http://localhost:3000/admin"
node server.js

pause
