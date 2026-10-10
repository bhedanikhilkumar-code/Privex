@echo off
setlocal enabledelayedexpansion
title PRIVEX - Deploy to Cloudflare Pages

echo ======================================================================
echo           PRIVEX - CLOUDFLARE PAGES AUTO DEPLOY SCRIPT
echo           Target: https://privex.io/ (https://privex.pages.dev/)
echo ======================================================================
echo.

:: Navigate to root directory
cd /d "%~dp0"

:: Step 1: Pre-build & Verification
echo [STEP 1/4] Building Web Application (@private-protection/web)...
echo ----------------------------------------------------------------------
call npm run build:web
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Build failed! Fix build errors before deploying.
    echo ----------------------------------------------------------------------
    pause
    exit /b %ERRORLEVEL%
)
echo [OK] Web build completed successfully!
echo.

:: Step 2: Git Status Check & Staging
echo [STEP 2/4] Checking Git Status and Staging changes...
echo ----------------------------------------------------------------------
git status --short
echo.
git add -A

:: Check if there are changes to commit
git diff --cached --quiet
if %ERRORLEVEL% EQU 0 (
    echo [INFO] No new local changes to commit.
    set /p FORCE_PUSH="Do you still want to push existing commits to git? (Y/N, default Y): "
    if /i "!FORCE_PUSH!"=="N" (
        echo [INFO] Deployment aborted by user.
        goto :END
    )
) else (
    :: Step 3: Commit
    echo.
    echo [STEP 3/4] Creating Git Commit...
    echo ----------------------------------------------------------------------
    set /p COMMIT_MSG="Enter commit message (Press ENTER for default message): "
    if "!COMMIT_MSG!"=="" (
        for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
        set "TIMESTAMP=!datetime:~0,4!-!datetime:~4,2!-!datetime:~6,2! !datetime:~8,2!:!datetime:~10,2!"
        set "COMMIT_MSG=deploy: update web build for pages.dev (!TIMESTAMP!)"
    )
    
    echo Committing with message: "!COMMIT_MSG!"
    git commit -m "!COMMIT_MSG!"
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Git commit failed!
        pause
        exit /b %ERRORLEVEL%
    )
    echo [OK] Commit created successfully!
)

:: Step 4: Push to Remote
echo.
echo [STEP 4/4] Pushing commits to GitHub (origin main)...
echo ----------------------------------------------------------------------
git push origin main
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Git push failed! Please check your internet connection or git permissions.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ======================================================================
echo  [SUCCESS] All latest commits have been pushed to 'main'!
echo  Cloudflare Pages / GitHub Actions will now automatically deploy:
echo  URL: https://privex.io/ (Fallback: https://privex.pages.dev/)
echo ======================================================================
echo.

:END
echo Press any key to exit...
pause >nul
