@echo off
chcp 65001 >nul
title THE HAND OF GOD - Super Instalador v2.0
color 0A

echo.
echo ╔═══════════════════════════════════════════════════════════════════════════╗
echo ║                                                                           ║
echo ║   ████████╗██╗  ██╗███████╗    ██╗  ██╗ █████╗ ███╗   ██╗██████╗          ║
echo ║   ╚══██╔══╝██║  ██║██╔════╝    ██║  ██║██╔══██╗████╗  ██║██╔══██╗         ║
echo ║      ██║   ███████║█████╗      ███████║███████║██╔██╗ ██║██║  ██║         ║
echo ║      ██║   ██╔══██║██╔══╝      ██╔══██║██╔══██║██║╚██╗██║██║  ██║         ║
echo ║      ██║   ██║  ██║███████╗    ██║  ██║██║  ██║██║ ╚████║██████╔╝         ║
echo ║      ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝          ║
echo ║                                                                           ║
echo ║                    ██████╗ ███████╗     ██████╗  ██████╗ ██████╗          ║
echo ║                   ██╔═══██╗██╔════╝    ██╔════╝ ██╔═══██╗██╔══██╗         ║
echo ║                   ██║   ██║█████╗      ██║  ███╗██║   ██║██║  ██║         ║
echo ║                   ██║   ██║██╔══╝      ██║   ██║██║   ██║██║  ██║         ║
echo ║                   ╚██████╔╝██║         ╚██████╔╝╚██████╔╝██████╔╝         ║
echo ║                    ╚═════╝ ╚═╝          ╚═════╝  ╚═════╝ ╚═════╝          ║
echo ║                                                                           ║
echo ║           MEGAZORD-CODE: Sistema de Traducao Semantica + HTTP Toolkit     ║
echo ║                              Super Instalador v2.0                        ║
echo ╚═══════════════════════════════════════════════════════════════════════════╝
echo.

:: Verificar se está rodando como admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Executando com privilegios de administrador
) else (
    echo [!] Recomendado: Execute como Administrador para instalacao completa
)

echo.
echo [1/8] Verificando Python...
where python >nul 2>&1
if %errorLevel% neq 0 (
    echo [X] Python nao encontrado! Instalando via winget...
    winget install Python.Python.3.12 --silent --accept-package-agreements
    if %errorLevel% neq 0 (
        echo [ERRO] Falha ao instalar Python. Instale manualmente: https://python.org
        pause
        exit /b 1
    )
) else (
    for /f "tokens=*" %%i in ('python --version 2^>^&1') do echo [OK] %%i encontrado
)

echo.
echo [2/8] Verificando Git...
where git >nul 2>&1
if %errorLevel% neq 0 (
    echo [X] Git nao encontrado! Instalando via winget...
    winget install Git.Git --silent --accept-package-agreements
) else (
    for /f "tokens=*" %%i in ('git --version 2^>^&1') do echo [OK] %%i encontrado
)

echo.
echo [3/8] Verificando VS Code...
where code >nul 2>&1
if %errorLevel% neq 0 (
    echo [X] VS Code nao encontrado! Instalando via winget...
    winget install Microsoft.VisualStudioCode --silent --accept-package-agreements
) else (
    echo [OK] VS Code encontrado
)

echo.
echo [4/8] Instalando dependencias Python...
python -m pip install --upgrade pip --quiet
python -m pip install requests aiohttp colorama rich --quiet
echo [OK] Dependencias instaladas

echo.
echo [5/8] Configurando extensoes do VS Code...
call code --install-extension GitHub.copilot --force 2>nul
call code --install-extension ms-python.python --force 2>nul
call code --install-extension ms-python.vscode-pylance --force 2>nul
echo [OK] Extensoes configuradas

echo.
echo [6/8] Configurando MCP para GitHub Copilot...
set "MCP_CONFIG=%APPDATA%\Code\User\globalStorage\github.copilot\mcp.json"
set "MCP_DIR=%APPDATA%\Code\User\globalStorage\github.copilot"

if not exist "%MCP_DIR%" mkdir "%MCP_DIR%" 2>nul

:: Criar configuração MCP
echo { > "%MCP_CONFIG%"
echo   "servers": { >> "%MCP_CONFIG%"
echo     "megazord-hog": { >> "%MCP_CONFIG%"
echo       "type": "stdio", >> "%MCP_CONFIG%"
echo       "command": "python", >> "%MCP_CONFIG%"
echo       "args": ["%CD:\=/%/mcp_server.py"], >> "%MCP_CONFIG%"
echo       "env": {} >> "%MCP_CONFIG%"
echo     } >> "%MCP_CONFIG%"
echo   } >> "%MCP_CONFIG%"
echo } >> "%MCP_CONFIG%"
echo [OK] MCP configurado em: %MCP_CONFIG%

echo.
echo [7/8] Validando instalacao...
python -c "import json; print('[OK] JSON OK')" 2>nul || echo [X] Erro no modulo JSON
python -c "import urllib.request; print('[OK] HTTP OK')" 2>nul || echo [X] Erro no modulo HTTP
python translator.py validate >nul 2>&1 && echo [OK] Translator validado || echo [!] Translator precisa de config.json

echo.
echo [8/8] Abrindo VS Code com o projeto...
start "" code "%CD%"

echo.
echo ╔═══════════════════════════════════════════════════════════════════════════╗
echo ║                     INSTALACAO CONCLUIDA COM SUCESSO!                     ║
echo ╠═══════════════════════════════════════════════════════════════════════════╣
echo ║                                                                           ║
echo ║   COMO USAR:                                                              ║
echo ║                                                                           ║
echo ║   1. No VS Code, pressione Ctrl+Shift+P                                   ║
echo ║   2. Digite "Tasks: Run Task"                                             ║
echo ║   3. Escolha uma task [HOG] para executar                                 ║
echo ║                                                                           ║
echo ║   TASKS DISPONIVEIS:                                                      ║
echo ║   - [HOG] ENCODE          : Sanitiza codigo para IA                       ║
echo ║   - [HOG] RESTORE         : Restaura termos originais                     ║
echo ║   - [HOG] HTTP TOOLKIT    : Interceptador de requisicoes                  ║
echo ║   - [HOG] MCP SERVER      : Servidor para GitHub Copilot                  ║
echo ║                                                                           ║
echo ║   MODO INTERATIVO:                                                        ║
echo ║   python http_toolkit.py interactive                                      ║
echo ║                                                                           ║
echo ║   GitHub: https://github.com/ThiagoFrag/Megazord-Code                     ║
echo ║                                                                           ║
echo ╚═══════════════════════════════════════════════════════════════════════════╝
echo.

pause
