@echo off
chcp 65001 >nul
title TESTE UNINSTALL - Simula remocao completa
color 0C

echo.
echo ==============================================================
echo        TESTE DE DESINSTALACAO - MODO SIMULACAO
echo ==============================================================
echo.
echo Este script simula o que a funcao Uninstall() vai fazer.
echo NAO vai executar nada, apenas mostrar o que seria feito.
echo.
pause

echo.
echo [1/6] Matando processos...
echo       - taskkill /f /im CleanClean*.exe
echo       - taskkill /f /im focous*.exe
echo       - taskkill /f /im pacman.exe
echo.

echo [2/6] Pastas que seriam deletadas:
echo       - C:\Program Files (x86)\CleanClean
echo       - C:\Program Files\CleanClean
echo       - %USERPROFILE%\AppData\Local\CleanClean
echo       - %PROGRAMDATA%\CleanClean
echo       - %APPDATA%\CleanClean
echo       - %USERPROFILE%\AppData\Local\Calculator_App
echo.

echo [3/6] Verificando se CleanClean esta instalado via MSI...
wmic product where "name like '%%CleanClean%%'" get name,identifyingnumber 2>nul
echo.

echo [4/6] Desinstalando CleanClean via WMI (seria executado):
echo       - Get-WmiObject Win32_Product ^| Where Name -like '*CleanClean*' ^| Uninstall
echo.

echo [5/6] Removendo Calculadora customizada:
echo       - Remove-AppxPackage 'Calculator.Stealth'
powershell -Command "Get-AppxPackage -Name 'Calculator.Stealth' | Select-Object Name,PackageFullName"
echo.

echo [6/6] Reinstalando Calculadora original do Windows:
echo       - Add-AppxPackage Microsoft.WindowsCalculator
echo.

echo ==============================================================
echo                    VERIFICACAO DE ARQUIVOS
echo ==============================================================
echo.

echo Verificando se CleanClean existe:
if exist "C:\Program Files (x86)\CleanClean" (
    echo   [ENCONTRADO] C:\Program Files (x86)\CleanClean
    dir "C:\Program Files (x86)\CleanClean" /s /b 2>nul | head -20
) else (
    echo   [NAO EXISTE] C:\Program Files (x86)\CleanClean
)
echo.

if exist "%USERPROFILE%\AppData\Local\Calculator_App" (
    echo   [ENCONTRADO] Calculator_App
    dir "%USERPROFILE%\AppData\Local\Calculator_App" /b 2>nul
) else (
    echo   [NAO EXISTE] Calculator_App
)
echo.

echo ==============================================================
echo.
set /p EXECUTAR="Deseja REALMENTE executar a desinstalacao? (S/N): "
if /i "%EXECUTAR%"=="S" (
    echo.
    echo [!] EXECUTANDO DESINSTALACAO REAL...
    echo.
    
    echo [1] Matando processos...
    taskkill /f /im CleanClean.exe >nul 2>&1
    taskkill /f /im focous_clean.exe >nul 2>&1
    
    echo [2] Removendo pastas...
    rd /s /q "C:\Program Files (x86)\CleanClean" 2>nul
    rd /s /q "%USERPROFILE%\AppData\Local\CleanClean" 2>nul
    rd /s /q "%USERPROFILE%\AppData\Local\Calculator_App" 2>nul
    
    echo [3] Desinstalando CleanClean MSI...
    powershell -Command "Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like '*CleanClean*' } | ForEach-Object { $_.Uninstall() }" 2>nul
    
    echo [4] Removendo Calculadora customizada...
    powershell -Command "Get-AppxPackage -Name 'Calculator.Stealth' | Remove-AppxPackage -ErrorAction SilentlyContinue"
    
    echo [5] Reinstalando Calculadora do Windows...
    powershell -Command "Get-AppxPackage -AllUsers Microsoft.WindowsCalculator | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register \"$($_.InstallLocation)\AppXManifest.xml\" -ErrorAction SilentlyContinue}"
    
    echo.
    echo [OK] DESINSTALACAO CONCLUIDA!
) else (
    echo [*] Desinstalacao cancelada.
)

echo.
pause
