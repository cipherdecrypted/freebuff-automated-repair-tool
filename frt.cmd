@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>nul
title Freebuff Repair Tool
cd /d "%~dp0"
set "HERE=%~dp0"
set "MODE=%~1"

if exist "%HERE%frt.mjs" goto findbun
echo.
echo  Freebuff Repair Tool can't start: frt.mjs is missing next to frt.cmd.
echo.
echo  If you opened frt.cmd from inside a .zip file, Windows only extracted frt.cmd.
echo  Right-click the .zip, choose "Extract All...", then open frt.cmd in the extracted folder.
echo.
echo  Looked in: %HERE%
goto fail

:findbun
set "BUN=%FRT_BUN%"
if defined BUN goto check
for %%D in ("%LOCALAPPDATA%\Programs\Freebuff" "%LOCALAPPDATA%\Programs\freebuff-desktop" "%LOCALAPPDATA%\Programs\@codebufffreebuff-desktop" "%ProgramFiles%\Freebuff") do if not defined BUN if exist "%%~D\resources\bun\bun.exe" set "BUN=%%~D\resources\bun\bun.exe"
if defined BUN goto check
for /f "usebackq delims=" %%P in (`powershell -NoProfile -NonInteractive -Command "$e = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Freebuff*' -and $_.InstallLocation } | Select-Object -First 1; if ($e) { Join-Path $e.InstallLocation 'resources\bun\bun.exe' }" 2^>nul`) do if exist "%%P" set "BUN=%%P"
if defined BUN goto check
where bun >nul 2>nul && set "BUN=bun"
if defined BUN goto run
echo.
echo  Freebuff Repair Tool could not find Freebuff on this computer.
echo  Install Freebuff from https://freebuff.com, or run from a terminal:
echo    "C:\path\to\Freebuff\resources\bun\bun.exe" "%HERE%frt.mjs" --install "C:\path\to\Freebuff"
goto fail

:check
"%BUN%" --version >nul 2>nul
if not errorlevel 1 goto run
for %%B in ("%BUN%") do if exist "%%~dpBbun-baseline.exe" set "BUN=%%~dpBbun-baseline.exe"

:run
if "%MODE%"=="" goto ui
"%BUN%" "%HERE%frt.mjs" %*
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" exit /b 0
if "%RC%"=="1" exit /b 1
goto crashed

:ui
"%BUN%" "%HERE%frt.mjs" --ui
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" exit /b 0

:crashed
echo.
echo  Freebuff Repair Tool stopped unexpectedly (exit code %RC%).
echo  Please send a screenshot of this window to support.

:fail
echo.
pause
exit /b 2
