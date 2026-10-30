@echo off
title Security Detective
echo.
echo  ==============================================
echo    Security Detective - collecting clues...
echo    (read-only: nothing on this PC is changed)
echo    This takes about 2 minutes. Please wait...
echo  ==============================================
echo.
echo  Tip: right-click this file and choose
echo       "Run as administrator" to also check login records.
echo.
powershell -NoProfile -File "%~dp0collect.ps1"
powershell -NoProfile -File "%~dp0server.ps1"
