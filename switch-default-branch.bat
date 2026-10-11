@echo off
setlocal enabledelayedexpansion
title PRIVEX - Switch Default GitHub Branch

echo =======================================================
echo          PRIVEX GITHUB DEFAULT BRANCH SWITCHER
echo =======================================================
echo.

:: Check GitHub CLI authentication
where gh >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] GitHub CLI ('gh') is not installed or not in PATH.
    echo Please install gh or ensure it is accessible.
    pause
    exit /b 1
)

:: Get current default branch
echo [*] Fetching current default branch from GitHub...
for /f "delims=" %%i in ('gh repo view --json defaultBranchRef -q .defaultBranchRef.name 2^>nul') do set CURRENT_BRANCH=%%i

if "%CURRENT_BRANCH%"=="" (
    echo [!] Could not automatically detect current branch.
    set CURRENT_BRANCH=unknown
)

echo [*] Current Default Branch is: [%CURRENT_BRANCH%]
echo.
echo Select an option:
echo   [1] Set 'main' as default branch (Full Source Code)
echo   [2] Set 'master' as default branch (Structure & MD Docs Only)
echo   [3] Toggle (Switch between main ^<--^> master)
echo   [4] Exit
echo.

set /p CHOICE="Enter choice (1/2/3/4): "

if "%CHOICE%"=="1" (
    set TARGET_BRANCH=main
) else if "%CHOICE%"=="2" (
    set TARGET_BRANCH=master
) else if "%CHOICE%"=="3" (
    if /i "%CURRENT_BRANCH%"=="main" (
        set TARGET_BRANCH=master
    ) else (
        set TARGET_BRANCH=main
    )
) else (
    echo [*] Exiting without changes.
    exit /b 0
)

echo.
echo [*] Changing default branch on GitHub to '%TARGET_BRANCH%'...
gh repo edit --default-branch %TARGET_BRANCH%

if %ERRORLEVEL% equ 0 (
    echo.
    echo =======================================================
    echo [SUCCESS] Default branch is now successfully set to: %TARGET_BRANCH%
    echo =======================================================
) else (
    echo.
    echo [ERROR] Failed to switch default branch. Please verify permissions.
)

echo.
pause
