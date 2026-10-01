@echo off
rem ============================================================
rem  GhostLock-MT6983T one-key root & fix (launcher)
rem  Edit the ADB path below if adb is not on your PATH,
rem  then just double-click this file. Phone must be connected
rem  with USB debugging enabled (see docs/使用指南.md).
rem ============================================================
chcp 65001 >nul
set "ADB=adb"
if exist "D:\Android\platform-tools\adb.exe" set "ADB=D:\Android\platform-tools\adb.exe"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0onekey_root.ps1" -Adb "%ADB%"
pause
