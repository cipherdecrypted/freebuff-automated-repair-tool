@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>nul
cd /d "%~dp0"

set "BUN=%FRT_BUN%"
if defined BUN goto run

for %%D in ("%LOCALAPPDATA%\Programs\Freebuff" "%LOCALAPPDATA%\Programs\freebuff-desktop" "%LOCALAPPDATA%\Programs\@codebufffreebuff-desktop" "%ProgramFiles%\Freebuff") do (
  if not defined BUN if exist "%%~D\resources\bun\bun.exe" set "BUN=%%~D\resources\bun\bun.exe"
)
if defined BUN goto check

for /f "usebackq delims=" %%P in (`powershell -NoProfile -NonInteractive -Command "$e = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Freebuff*' -and $_.InstallLocation } | Select-Object -First 1; if ($e) { Join-Path $e.InstallLocation 'resources\bun\bun.exe' }" 2^>nul`) do (
  if exist "%%P" set "BUN=%%P"
)
if defined BUN goto check

where bun >nul 2>nul && set "BUN=bun"
if defined BUN goto run

echo.
echo Freebuff Repair Tool could not find Freebuff's installation.
echo Run it from a terminal with the folder, for example:
echo   "C:\path\to\Freebuff\resources\bun\bun.exe" "%~dp0frt.mjs" --install "C:\path\to\Freebuff"
echo.
pause
exit /b 2

:check
"%BUN%" --version >nul 2>nul
if errorlevel 1 (
  for %%B in ("%BUN%") do if exist "%%~dpBbun-baseline.exe" set "BUN=%%~dpBbun-baseline.exe"
)

:run
if "%~1"=="" (
  "%BUN%" "%~dp0frt.mjs" --ui
  exit /b %ERRORLEVEL%
)
"%BUN%" "%~dp0frt.mjs" %*
exit /b %ERRORLEVEL%
