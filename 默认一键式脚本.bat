@echo off
chcp 65001 > nul
echo.
set /p DOMAIN=[*] 请输入目标域名【默认】：
echo.
python3 Hakutaku.py -d %DOMAIN%
echo.
pause