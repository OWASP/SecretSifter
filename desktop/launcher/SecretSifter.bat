@echo off
:: SecretSifter Windows launcher — double-click to start SecretSifter.
:: Requires Java 17 or later on PATH or JAVA_HOME.

setlocal enabledelayedexpansion

echo ====================================
echo  SecretSifter - Starting...
echo ====================================
echo.

:: Find the JAR next to this .bat file
set "DIR=%~dp0"
set "JAR=%DIR%secretsifter-1.1.0.jar"

echo Launcher location: %DIR%
echo Looking for JAR:   %JAR%
echo.

:: Fall back to any secretsifter-*.jar in the same folder
if not exist "%JAR%" (
    for /f "delims=" %%f in ('dir /b /o-n "%DIR%secretsifter-*.jar" 2^>nul') do (
        set "JAR=%DIR%%%f"
        goto :found_jar
    )
    echo ERROR: No secretsifter-*.jar found in:
    echo        %DIR%
    echo.
    echo Make sure you EXTRACTED the ZIP before running this file.
    echo Do NOT run directly from inside the ZIP archive.
    echo.
    pause
    exit /b 1
)
:found_jar
echo Found JAR: %JAR%
echo.

:: Prefer JAVA_HOME if set
set "JAVA_EXE="
if defined JAVA_HOME (
    if exist "%JAVA_HOME%\bin\java.exe" (
        set "JAVA_EXE=%JAVA_HOME%\bin\java.exe"
    )
)

:: Fall back to java on PATH
if not defined JAVA_EXE (
    where java >nul 2>&1
    if !errorlevel! == 0 set "JAVA_EXE=java"
)

if not defined JAVA_EXE (
    echo ERROR: Java 17 or later is required but was not found.
    echo.
    echo Download and install Java from:
    echo   https://adoptium.net
    echo.
    echo After installing Java, re-open this file.
    echo.
    pause
    exit /b 1
)

echo Found Java: %JAVA_EXE%

:: Verify version is 17+
for /f "tokens=3 delims= " %%v in ('"%JAVA_EXE%" -version 2^>^&1 ^| findstr /i "version"') do (
    set "VER_STR=%%v"
    goto :check_ver
)
:check_ver
set "VER_STR=%VER_STR:"=%"
for /f "delims=." %%m in ("%VER_STR%") do set "MAJOR=%%m"
echo Java version: %VER_STR% (major: %MAJOR%)
echo.

if %MAJOR% LSS 17 (
    echo ERROR: Java 17+ required. You have version %VER_STR%.
    echo.
    echo Download Java 17 from: https://adoptium.net
    echo.
    pause
    exit /b 1
)

echo Launching SecretSifter...
echo (This window will close when the app opens)
echo.

"%JAVA_EXE%" -jar "%JAR%"
if %errorlevel% neq 0 (
    echo.
    echo ERROR: SecretSifter crashed with exit code %errorlevel%
    echo.
    pause
)
