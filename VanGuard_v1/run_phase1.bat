@echo off
title AgentNDR - Autonomous Network Threat Detection Dashboard
echo ======================================================================
echo   AgentNDR: Autonomous Network Threat Detection Platform
echo ======================================================================
echo.
echo [1/2] Checking Python environment...
python --version
if errorlevel 1 (
    echo Python is not installed or not in PATH!
    pause
    exit /b 1
)

echo [2/2] Launching AgentNDR Security Dashboard...
python -m streamlit run app.py
pause
