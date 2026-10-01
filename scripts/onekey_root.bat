@echo off
rem ============================================================
rem  GhostLock-MT6983T one-key root & fix (launcher)
rem  adb lookup order: the manual path below > adb on PATH.
rem  When editing the manual path KEEP the "ADB=" prefix, e.g.
rem     set "ADB=D:\tools\platform-tools\adb.exe"
rem ============================================================
chcp 65001 >nul
rem ==== edit this line if needed (keep the ADB= prefix) ====
set "ADB="
rem =========================================================
if not defined ADB where adb >nul 2>nul && set "ADB=adb"
if not defined ADB (
  echo [!] adb not found: edit this .bat and put the full adb.exe path in set "ADB=..."
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0onekey_root.ps1" -Adb "%ADB%"
pause
