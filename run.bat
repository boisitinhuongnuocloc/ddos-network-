@echo off
title DDoS Network - Admin Terminal

:: Kiểm tra Python
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Khong tim thay Python. Vui long cai dat Python va them vao PATH.
    pause
    exit
)

:: Kiểm tra quyền Admin
net session >nul 2>&1
if %errorLevel% == 0 (
    cd /d "%~dp0"
    
    :: Kiem tra xem co Windows Terminal (wt.exe) khong
    where wt >nul 2>&1
    if not errorlevel 1 (
        :: Chạy qua Windows Terminal cho dep
        wt -d . cmd /c "title Admin Terminal & python attack.py"
    ) else (
        :: Chạy bang CMD binh thuong neu khong co Windows Terminal
        echo [!] Khong tim thay Windows Terminal, dung tam CMD...
        python attack.py
        pause
    )
) else (
    :: Chưa có quyền Admin, yêu cầu cấp quyền UAC
    echo Dang yeu cau quyen Administrator...
    powershell -Command "Start-Process '%~0' -Verb RunAs"
    exit
)

