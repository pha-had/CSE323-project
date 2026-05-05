@echo off
setlocal enabledelayedexpansion
title File Encryption System
color 0A

set ENCRYPT_BIN=H:\file-encryption\encrypt.exe

if not exist "%ENCRYPT_BIN%" (
    echo.
    echo  [!] ERROR: encrypt.exe not found
    echo.
    pause
    exit /b 1
)

:main
cls
echo.
echo  +================================================+
echo  ^|       FILE ENCRYPTION SYSTEM                   ^|
echo  ^|       Secure Your Files - v1.0                ^|
echo  +================================================+
echo.
echo  [1] Encrypt a File
echo  [2] Encrypt a Folder
echo  [3] Encrypt with Duress Password (Real + Decoy)
echo  [4] Decrypt a File
echo  [5] Change Password on Encrypted File
echo  [6] Verify File Integrity
echo  [7] Shred a File Securely
echo  [8] View Audit Log
echo  [9] Exit
echo.
set /p choice="  Enter your choice (1-9): "

if "%choice%"=="1" goto encrypt_file
if "%choice%"=="2" goto encrypt_folder
if "%choice%"=="3" goto encrypt_duress
if "%choice%"=="4" goto decrypt_file
if "%choice%"=="5" goto change_password
if "%choice%"=="6" goto verify_file
if "%choice%"=="7" goto shred_file
if "%choice%"=="8" goto view_log
if "%choice%"=="9" goto exit_program

echo  [!] Invalid choice. Try again.
pause
goto main

:encrypt_file
cls
echo.
echo  +================================================+
echo  ^|            ENCRYPT FILE                        ^|
echo  +================================================+
echo.
set /p filepath="  Enter file path: "
for /f "tokens=* delims=" %%A in ("%filepath%") do set filepath=%%~A

if not exist "%filepath%" (
    echo  [!] ERROR: File not found
    pause
    goto main
)

echo.
set /p password="  Enter password: "

if "%password%"=="" (
    echo  [!] Operation cancelled
    pause
    goto main
)

echo.
"%ENCRYPT_BIN%" --encrypt "%filepath%" --password "%password%"
pause
goto main

:encrypt_folder
cls
echo.
echo  +================================================+
echo  ^|           ENCRYPT FOLDER                       ^|
echo  +================================================+
echo.
set /p folderpath="  Enter folder path: "
for /f "tokens=* delims=" %%A in ("%folderpath%") do set folderpath=%%~A

if not exist "%folderpath%" (
    echo  [!] ERROR: Folder not found
    pause
    goto main
)

echo.
set /p password="  Enter password: "

if "%password%"=="" (
    echo  [!] Operation cancelled
    pause
    goto main
)

echo.
"%ENCRYPT_BIN%" --encrypt "%folderpath%" --password "%password%"
pause
goto main

:encrypt_duress
cls
echo.
echo  +================================================+
echo  ^|      ENCRYPT WITH DURESS PASSWORD              ^|
echo  ^|      (Real File + Decoy File)                 ^|
echo  +================================================+
echo.
echo  This encrypts TWO files with TWO passwords.
echo  If coerced, use the decoy password.
echo.
set /p realfile="  Enter REAL file path: "
for /f "tokens=* delims=" %%A in ("%realfile%") do set realfile=%%~A

if not exist "%realfile%" (
    echo  [!] ERROR: Real file not found
    pause
    goto main
)

set /p decoyfile="  Enter DECOY file path: "
for /f "tokens=* delims=" %%A in ("%decoyfile%") do set decoyfile=%%~A

if not exist "%decoyfile%" (
    echo  [!] ERROR: Decoy file not found
    pause
    goto main
)

echo.
set /p realpass="  Enter REAL password: "

if "%realpass%"=="" (
    echo  [!] Operation cancelled
    pause
    goto main
)

echo.
set /p decoypass="  Enter DECOY password: "

if "%decoypass%"=="" (
    echo  [!] Operation cancelled
    pause
    goto main
)

echo.
"%ENCRYPT_BIN%" --encrypt "%realfile%" --password "%realpass%" --decoy "%decoyfile%" --decoy-password "%decoypass%"
pause
goto main

:decrypt_file
cls
echo.
echo  +================================================+
echo  ^|            DECRYPT FILE                        ^|
echo  +================================================+
echo.
set /p filepath="  Enter .enc file path: "
for /f "tokens=* delims=" %%A in ("%filepath%") do set filepath=%%~A

if not exist "%filepath%" (
    echo  [!] ERROR: File not found
    pause
    goto main
)

echo.
set /p password="  Enter password: "

if "%password%"=="" (
    echo  [!] Operation cancelled
    pause
    goto main
)

echo.
"%ENCRYPT_BIN%" --decrypt "%filepath%" --password "%password%"
pause
goto main

:change_password
cls
echo.
echo  +================================================+
echo  ^|         CHANGE PASSWORD                        ^|
echo  +================================================+
echo.
set /p filepath="  Enter .enc file path: "
for /f "tokens=* delims=" %%A in ("%filepath%") do set filepath=%%~A

if not exist "%filepath%" (
    echo  [!] ERROR: File not found
    pause
    goto main
)

echo.
set /p oldpass="  Enter OLD password: "

if "%oldpass%"=="" (
    echo  [!] Operation cancelled
    pause
    goto main
)

echo.
set /p newpass="  Enter NEW password: "

if "%newpass%"=="" (
    echo  [!] Operation cancelled
    pause
    goto main
)

echo.
set /p is_duress="  Is this a duress-mode file (yes/no): "

if /i "%is_duress%"=="yes" (
    echo.
    set /p olddecoy="  Enter OLD decoy password: "
    if "%olddecoy%"=="" (
        echo  [!] Operation cancelled
        pause
        goto main
    )
    
    echo.
    set /p newdecoy="  Enter NEW decoy password: "
    if "%newdecoy%"=="" (
        echo  [!] Operation cancelled
        pause
        goto main
    )
    
    echo.
    "%ENCRYPT_BIN%" --change-password "%filepath%" --password "%oldpass%" --new-password "%newpass%" --decoy-password "%olddecoy%" --new-decoy-password "%newdecoy%"
) else (
    echo.
    "%ENCRYPT_BIN%" --change-password "%filepath%" --password "%oldpass%" --new-password "%newpass%"
)
pause
goto main

:verify_file
cls
echo.
echo  +================================================+
echo  ^|         VERIFY FILE INTEGRITY                  ^|
echo  +================================================+
echo.
set /p filepath="  Enter .enc file path: "
for /f "tokens=* delims=" %%A in ("%filepath%") do set filepath=%%~A

if not exist "%filepath%" (
    echo  [!] ERROR: File not found
    pause
    goto main
)

echo.
set /p password="  Enter password: "

if "%password%"=="" (
    echo  [!] Operation cancelled
    pause
    goto main
)

echo.
"%ENCRYPT_BIN%" --verify "%filepath%" --password "%password%"
pause
goto main

:shred_file
cls
echo.
echo  +================================================+
echo  ^|          SECURE FILE SHREDDER                  ^|
echo  +================================================+
echo.
set /p filepath="  Enter file path to shred: "
for /f "tokens=* delims=" %%A in ("%filepath%") do set filepath=%%~A

if not exist "%filepath%" (
    echo  [!] ERROR: File not found
    pause
    goto main
)

echo.
echo  WARNING: This will PERMANENTLY delete the file!
echo.
set /p confirm="  Type 'yes' to confirm: "

if /i "%confirm%"=="yes" (
    echo.
    "%ENCRYPT_BIN%" --shred "%filepath%"
) else (
    echo  [!] Operation cancelled
)
pause
goto main

:view_log
cls
echo.
echo  +================================================+
echo  ^|            AUDIT LOG                           ^|
echo  +================================================+
echo.
"%ENCRYPT_BIN%" --log
echo.
pause
goto main

:exit_program
cls
echo.
echo  +================================================+
echo  ^|           Goodbye!                             ^|
echo  +================================================+
echo.
exit /b 0
