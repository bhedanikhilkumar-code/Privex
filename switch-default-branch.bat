@echo off
setlocal EnableDelayedExpansion
title PRIVEX - Switch Default GitHub Branch

cls
echo =======================================================
echo          PRIVEX GITHUB DEFAULT BRANCH SWITCHER
echo =======================================================
echo.

:: Check GitHub CLI
where gh >nul 2>&1
if errorlevel 1 (
    echo [ERROR] GitHub CLI is not installed or not in PATH.
    echo Please ensure gh CLI is installed.
    echo.
    pause
    exit /b 1
)

:: Get current default branch
echo [*] Fetching current default branch from GitHub...
set CURRENT_BRANCH=unknown
for /f "tokens=*" %%i in ('gh repo view bhedanikhilkumar-code/Privex --json defaultBranchRef -q .defaultBranchRef.name') do (
    set CURRENT_BRANCH=%%i
)

echo [*] Current Default Branch is: [!CURRENT_BRANCH!]
echo.
echo =======================================================
echo  Select an option:
echo    1. Set 'main' as default (Full Source Code)
echo    2. Set 'master' as default (Structure and MD Docs Only)
echo    3. Toggle switch between main and master
echo    4. Exit
echo =======================================================
echo.

set CHOICE=
set /p CHOICE="Enter choice (1, 2, 3, or 4): "

if "!CHOICE!"=="1" goto SET_MAIN
if "!CHOICE!"=="2" goto SET_MASTER
if "!CHOICE!"=="3" goto DO_TOGGLE
if "!CHOICE!"=="4" goto DO_EXIT
goto INVALID_CHOICE

:SET_MAIN
set TARGET_BRANCH=main
goto EXECUTE_SWITCH

:SET_MASTER
set TARGET_BRANCH=master
goto EXECUTE_SWITCH

:DO_TOGGLE
if /i "!CURRENT_BRANCH!"=="main" (
    set TARGET_BRANCH=master
) else (
    set TARGET_BRANCH=main
)
goto EXECUTE_SWITCH

:INVALID_CHOICE
echo.
echo [!] Invalid option selected.
pause
exit /b 1

:EXECUTE_SWITCH
echo.
echo [*] Changing default branch on GitHub to: !TARGET_BRANCH! ...
gh repo edit bhedanikhilkumar-code/Privex --default-branch !TARGET_BRANCH!
if errorlevel 1 (
    echo.
    echo [ERROR] Failed to switch default branch. Please check GitHub permissions.
    echo.
    pause
    exit /b 1
)

echo.
echo =======================================================
echo [SUCCESS] Default branch is now: !TARGET_BRANCH!
echo =======================================================
echo.
pause
exit /b 0

:DO_EXIT
echo.
echo [*] Exited without changes.
exit /b 0
