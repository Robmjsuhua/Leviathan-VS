#Requires -Version 5.1
<#
.SYNOPSIS
    THE HAND OF GOD - Super Instalador PowerShell v2.0
.DESCRIPTION
    Instala e configura automaticamente o Megazord-Code com HTTP Toolkit
.NOTES
    Autor: Megazord-Code Team
    Versao: 2.0
#>

param(
    [switch]$Silent,
    [switch]$SkipVSCode,
    [switch]$SkipMCP
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

# Cores
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) { Write-Output $args }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Write-Banner {
    $banner = @"

 ╔═══════════════════════════════════════════════════════════════════════════╗
 ║     ████████╗██╗  ██╗███████╗    ██╗  ██╗ █████╗ ███╗   ██╗██████╗        ║
 ║     ╚══██╔══╝██║  ██║██╔════╝    ██║  ██║██╔══██╗████╗  ██║██╔══██╗       ║
 ║        ██║   ███████║█████╗      ███████║███████║██╔██╗ ██║██║  ██║       ║
 ║        ██║   ██╔══██║██╔══╝      ██╔══██║██╔══██║██║╚██╗██║██║  ██║       ║
 ║        ██║   ██║  ██║███████╗    ██║  ██║██║  ██║██║ ╚████║██████╔╝       ║
 ║        ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝        ║
 ║                       OF GOD - MEGAZORD-CODE                              ║
 ║                    Super Instalador PowerShell v2.0                       ║
 ╚═══════════════════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Test-Command($Command) {
    return [bool](Get-Command $Command -ErrorAction SilentlyContinue)
}

function Install-WithWinget($PackageId, $Name) {
    Write-Host "  [*] Instalando $Name..." -ForegroundColor Yellow
    winget install $PackageId --silent --accept-package-agreements --accept-source-agreements 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] $Name instalado" -ForegroundColor Green
        return $true
    }
    Write-Host "  [!] Falha ao instalar $Name" -ForegroundColor Red
    return $false
}

function Install-VSCodeExtension($ExtensionId) {
    code --install-extension $ExtensionId --force 2>$null | Out-Null
}

# ============================================================================
# MAIN
# ============================================================================

Clear-Host
Write-Banner

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptPath

Write-Host "[1/8] Verificando Python..." -ForegroundColor Cyan
if (Test-Command "python") {
    $pyVersion = python --version 2>&1
    Write-Host "  [OK] $pyVersion" -ForegroundColor Green
} else {
    Install-WithWinget "Python.Python.3.12" "Python 3.12"
    # Atualizar PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

Write-Host "`n[2/8] Verificando Git..." -ForegroundColor Cyan
if (Test-Command "git") {
    $gitVersion = git --version 2>&1
    Write-Host "  [OK] $gitVersion" -ForegroundColor Green
} else {
    Install-WithWinget "Git.Git" "Git"
}

Write-Host "`n[3/8] Verificando VS Code..." -ForegroundColor Cyan
if (Test-Command "code") {
    Write-Host "  [OK] VS Code encontrado" -ForegroundColor Green
} else {
    if (-not $SkipVSCode) {
        Install-WithWinget "Microsoft.VisualStudioCode" "VS Code"
    }
}

Write-Host "`n[4/8] Instalando dependencias Python..." -ForegroundColor Cyan
$packages = @("requests", "aiohttp", "colorama", "rich", "httpx")
python -m pip install --upgrade pip --quiet 2>$null
foreach ($pkg in $packages) {
    python -m pip install $pkg --quiet 2>$null
}
Write-Host "  [OK] Dependencias: $($packages -join ', ')" -ForegroundColor Green

Write-Host "`n[5/8] Instalando extensoes VS Code..." -ForegroundColor Cyan
$extensions = @(
    "GitHub.copilot",
    "GitHub.copilot-chat",
    "ms-python.python",
    "ms-python.vscode-pylance",
    "ms-python.debugpy"
)
foreach ($ext in $extensions) {
    Install-VSCodeExtension $ext
    Write-Host "  [OK] $ext" -ForegroundColor Green
}

Write-Host "`n[6/8] Configurando MCP para GitHub Copilot..." -ForegroundColor Cyan
if (-not $SkipMCP) {
    $mcpDir = "$env:APPDATA\Code\User\globalStorage\github.copilot"
    $mcpConfig = "$mcpDir\mcp.json"

    if (-not (Test-Path $mcpDir)) {
        New-Item -ItemType Directory -Path $mcpDir -Force | Out-Null
    }

    $mcpJson = @{
        servers = @{
            "megazord-hog" = @{
                type = "stdio"
                command = "python"
                args = @("$($scriptPath -replace '\\','/')/mcp_server.py")
                env = @{}
            }
        }
    } | ConvertTo-Json -Depth 4

    $mcpJson | Out-File -FilePath $mcpConfig -Encoding utf8 -Force
    Write-Host "  [OK] MCP configurado: $mcpConfig" -ForegroundColor Green
}

Write-Host "`n[7/8] Validando instalacao..." -ForegroundColor Cyan
$checks = @(
    @{Name="Python"; Test={python -c "print('ok')" 2>$null; $LASTEXITCODE -eq 0}},
    @{Name="Config"; Test={Test-Path "$scriptPath\config.json"}},
    @{Name="Translator"; Test={Test-Path "$scriptPath\translator.py"}},
    @{Name="HTTP Toolkit"; Test={Test-Path "$scriptPath\http_toolkit.py"}},
    @{Name="MCP Server"; Test={Test-Path "$scriptPath\mcp_server.py"}}
)

foreach ($check in $checks) {
    if (& $check.Test) {
        Write-Host "  [OK] $($check.Name)" -ForegroundColor Green
    } else {
        Write-Host "  [X] $($check.Name)" -ForegroundColor Red
    }
}

Write-Host "`n[8/8] Abrindo VS Code..." -ForegroundColor Cyan
if (-not $Silent) {
    Start-Process code -ArgumentList $scriptPath
    Write-Host "  [OK] VS Code aberto com o projeto" -ForegroundColor Green
}

# Final
Write-Host "`n" -NoNewline
Write-Host "═" * 75 -ForegroundColor Cyan
Write-Host @"

  INSTALACAO CONCLUIDA COM SUCESSO!

  COMO USAR:

  1. No VS Code, pressione Ctrl+Shift+P
  2. Digite "Tasks: Run Task"
  3. Escolha uma task [HOG]

  COMANDOS RAPIDOS:

  # Sanitizar codigo
  python translator.py encode --file seu_arquivo.py

  # HTTP Toolkit interativo
  python http_toolkit.py interactive

  # Iniciar MCP Server
  python mcp_server.py

  GitHub: https://github.com/ThiagoFrag/Megazord-Code

"@ -ForegroundColor White

Write-Host "═" * 75 -ForegroundColor Cyan
Write-Host ""

if (-not $Silent) {
    Read-Host "Pressione ENTER para sair"
}
