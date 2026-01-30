@echo off
chcp 65001 >nul 2>&1
title THE HAND OF GOD - Semantic Engine v7.0
cd /d "%~dp0"
color 0A

:check_python
python --version >nul 2>&1
if errorlevel 1 (
    py --version >nul 2>&1
    if errorlevel 1 (
        color 0C
        cls
        echo.
        echo   ============================================================
        echo                    [ERRO] PYTHON NAO ENCONTRADO
        echo   ============================================================
        echo.
        echo   O Python e necessario para executar esta ferramenta.
        echo.
        echo   Opcoes de instalacao:
        echo     1. Microsoft Store - https://aka.ms/python
        echo     2. Site oficial    - https://python.org/downloads
        echo.
        echo   Apos instalar, reinicie este programa.
        echo.
        echo   ============================================================
        echo.
        pause
        exit
    ) else (
        set PYTHON_CMD=py
    )
) else (
    set PYTHON_CMD=python
)

:menu
cls
echo.
echo   [96m============================================================[0m
echo   [96m||                                                        ||[0m
echo   [96m||[0m   [93m _____ _   _ _____   _   _  ___  _   _ ____         [0m[96m||[0m
echo   [96m||[0m   [93m|_   _| | | | ____| | | | |/ _ \| \ | |  _ \        [0m[96m||[0m
echo   [96m||[0m   [93m  | | | |_| |  _|   | |_| | |_| |  \| | | | |       [0m[96m||[0m
echo   [96m||[0m   [93m  | | |  _  | |___  |  _  |  _  | |\  | |_| |       [0m[96m||[0m
echo   [96m||[0m   [93m  |_| |_| |_|_____| |_| |_|_| |_|_| \_|____/        [0m[96m||[0m
echo   [96m||[0m                                                        [96m||[0m
echo   [96m||[0m   [93m  ___  _____    ____  ___  ____                     [0m[96m||[0m
echo   [96m||[0m   [93m / _ \|  ___|  / ___|/ _ \|  _ \                    [0m[96m||[0m
echo   [96m||[0m   [93m| | | | |_    | |  _| | | | | | |                   [0m[96m||[0m
echo   [96m||[0m   [93m| |_| |  _|   | |_| | |_| | |_| |                   [0m[96m||[0m
echo   [96m||[0m   [93m \___/|_|      \____|\___/|____/                    [0m[96m||[0m
echo   [96m||[0m                                                        [96m||[0m
echo   [96m||[0m        [97mSemantic Translation Engine v7.0[0m               [96m||[0m
echo   [96m||                                                        ||[0m
echo   [96m============================================================[0m
echo.
echo   [92m[1][0m ENCODE     [90m- Preparar codigo para IA[0m
echo   [92m[2][0m RESTORE    [90m- Restaurar termos originais[0m
echo   [92m[3][0m PREVIEW    [90m- Ver preview das alteracoes[0m
echo   [92m[4][0m STATS      [90m- Ver estatisticas completas[0m
echo   [92m[5][0m HISTORY    [90m- Ver historico de operacoes[0m
echo   [92m[6][0m UNDO       [90m- Desfazer ultima operacao[0m
echo   [92m[7][0m VALIDATE   [90m- Validar configuracao[0m
echo.
echo   [94m[E][0m EDIT       [90m- Abrir work.txt[0m
echo   [94m[C][0m CONFIG     [90m- Editar regras[0m
echo   [94m[B][0m BACKUPS    [90m- Ver backups[0m
echo   [94m[I][0m INTERACTIVE[90m- Modo interativo Python[0m
echo.
echo   [91m[0][0m EXIT       [90m- Sair[0m
echo.
echo   [96m============================================================[0m
echo.
set /p "opt=   [97mDigite a opcao:[0m "

if "%opt%"=="1" goto encode
if "%opt%"=="2" goto restore
if "%opt%"=="3" goto preview
if "%opt%"=="4" goto stats
if "%opt%"=="5" goto history
if "%opt%"=="6" goto undo
if "%opt%"=="7" goto validate
if /i "%opt%"=="e" goto edit
if /i "%opt%"=="c" goto config
if /i "%opt%"=="b" goto backup
if /i "%opt%"=="i" goto interactive
if "%opt%"=="0" goto exitapp
if /i "%opt%"=="q" goto exitapp
if /i "%opt%"=="exit" goto exitapp

echo.
echo   [91m[!] Opcao invalida. Tente novamente.[0m
timeout /t 2 >nul
goto menu

:encode
cls
echo.
echo   [96m============================================================[0m
echo   [96m         ENCODE MODE - Preparando para IA...[0m
echo   [96m============================================================[0m
echo.
%PYTHON_CMD% core/translator.py encode
echo.
echo   [96m============================================================[0m
pause
goto menu

:restore
cls
echo.
echo   [96m============================================================[0m
echo   [96m        RESTORE MODE - Restaurando termos...[0m
echo   [96m============================================================[0m
echo.
%PYTHON_CMD% core/translator.py restore
echo.
echo   [96m============================================================[0m
pause
goto menu

:preview
cls
echo.
echo   [96m============================================================[0m
echo   [96m              PREVIEW - Visualizacao[0m
echo   [96m============================================================[0m
echo.
%PYTHON_CMD% core/translator.py preview
echo.
echo   [96m============================================================[0m
pause
goto menu

:stats
cls
echo.
%PYTHON_CMD% core/translator.py stats
pause
goto menu

:history
cls
echo.
%PYTHON_CMD% core/translator.py history
pause
goto menu

:undo
cls
echo.
echo   [96m============================================================[0m
echo   [96m              UNDO - Desfazendo...[0m
echo   [96m============================================================[0m
echo.
%PYTHON_CMD% core/translator.py undo
echo.
pause
goto menu

:validate
cls
echo.
echo   [96m============================================================[0m
echo   [96m         VALIDATE - Verificando configuracao...[0m
echo   [96m============================================================[0m
echo.
%PYTHON_CMD% core/translator.py validate
echo.
pause
goto menu

:edit
if not exist work.txt (
    echo. > work.txt
    echo   [92m[+] Arquivo work.txt criado![0m
    timeout /t 1 >nul
)
start "" notepad work.txt
goto menu

:config
if not exist core/config.json (
    echo   [91m[!] core/config.json nao encontrado![0m
    pause
    goto menu
)
start "" notepad core/config.json
goto menu

:backup
cls
echo.
echo   [96m============================================================[0m
echo   [96m                   BACKUPS SALVOS[0m
echo   [96m============================================================[0m
echo.
if not exist backups (
    mkdir backups
    echo   [93m[!] Pasta de backups criada.[0m
    echo   [93m    Nenhum backup encontrado ainda.[0m
) else (
    echo   [97mArquivos mais recentes:[0m
    echo.
    dir /b /o-d backups\*.txt 2>nul | findstr /n "^" | findstr "^[1-9]:" | findstr "^[0-9]:" 2>nul
    if errorlevel 1 (
        echo   [93m[!] Nenhum backup encontrado.[0m
    )
)
echo.
echo   [96m============================================================[0m
echo.
echo   [92m[1][0m Abrir pasta de backups
echo   [91m[0][0m Voltar ao menu
echo.
set /p "bopt=   Opcao: "
if "%bopt%"=="1" (
    start "" explorer backups
)
goto menu

:interactive
cls
%PYTHON_CMD% core/translator.py interactive
goto menu

:exitapp
cls
echo.
echo   [96m============================================================[0m
echo   [96m||                                                        ||[0m
echo   [96m||[0m      [92mObrigado por usar THE HAND OF GOD![0m               [96m||[0m
echo   [96m||[0m                                                        [96m||[0m
echo   [96m||[0m           [93mSemantic Engine v7.0[0m                        [96m||[0m
echo   [96m||[0m                                                        [96m||[0m
echo   [96m||[0m               [97mAte a proxima![0m                          [96m||[0m
echo   [96m||                                                        ||[0m
echo   [96m============================================================[0m
echo.
timeout /t 3 >nul
exit

