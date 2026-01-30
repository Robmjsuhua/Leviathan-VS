# MEGAZORD CODE

## THE HAND OF GOD - Semantic Translation Engine v5.0 + HTTP Toolkit v2.0

Uma ferramenta de alto desempenho para normalizacao semantica de codigo e interceptacao de trafego HTTP com IA integrada.

![Version](https://img.shields.io/badge/version-5.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![MCP](https://img.shields.io/badge/MCP-enabled-purple)
![AI](https://img.shields.io/badge/AI-powered-red)

---

## Instalacao Rapida (1 Clique)

### Windows

```batch
# Clique duplo no arquivo:
INSTALL.bat
```

### PowerShell (Avancado)

```powershell
.\install.ps1
```

O instalador:

- Instala Python, Git, VS Code (se necessario)
- Configura extensoes do VS Code
- Configura MCP para GitHub Copilot
- Abre o projeto pronto para uso

---

## Novidades v7.0

- HTTP Toolkit v2.0 - Interceptador HTTP com IA integrada
- Header Mimicry - Rotacao automatica de User-Agent
- AI Analysis - Analise automatica de respostas
- Auto-Repair - Recuperacao automatica de erros 403/401
- MCP Server - Integracao com GitHub Copilot
- 640+ Regras - Paradigma de Teoria de Grafos expandido
- Analise Estatica - Suporte para Go, Python, JS/TS, Rust, C/C++
- GitHub Integration - Analise de repositorios e PRs

---

## Inicio Rapido

### Windows (GUI)

```batch
START_HOG.bat
```

### HTTP Toolkit (Interativo)

```bash
python http_toolkit.py interactive
```

### Linha de Comando

```bash
# Semantic Translation
python translator.py encode      # Sanitizar codigo
python translator.py restore     # Restaurar originais

# HTTP Toolkit
python http_toolkit.py dispatch https://api.example.com -X POST -d '{"key":"value"}'
python http_toolkit.py scan https://api.example.com
```

### VSCode (Ctrl+Shift+B)

Acesse o menu de tasks e selecione a operacao desejada.

---

## Requisitos

- Python 3.8+
- Windows/Linux/macOS
- VSCode com GitHub Copilot (para MCP)

---

## Instalacao

```bash
git clone git@github.com:ThiagoFrag/Megazord-Code.git
cd Megazord-Code
python translator.py
```

---

## Comandos Disponiveis

| Comando       | Alias                         | Descricao                        |
| ------------- | ----------------------------- | -------------------------------- |
| `encode`      | `e`, `sanitize`, `clean`      | Sanitiza o conteudo              |
| `decode`      | `d`, `r`, `restore`, `revert` | Restaura os termos originais     |
| `stats`       | `s`                           | Mostra estatisticas              |
| `history`     | `h`                           | Mostra historico de operacoes    |
| `undo`        | `u`                           | Desfaz a ultima operacao         |
| `validate`    | `v`                           | Valida o arquivo de configuracao |
| `preview`     | `p`                           | Preview das alteracoes           |
| `interactive` | `i`                           | Modo interativo                  |
| `help`        | `-h`, `--help`                | Mostra ajuda                     |

---

## Fluxo de Trabalho

```
1. Cole seu codigo em work.txt
2. Execute ENCODE (Ctrl+Shift+B > ENCODE)
   - "exploit" -> "performance_case"
   - "bypass" -> "bridge_compatibility"
3. Envie o codigo sanitizado para a IA
4. Cole a resposta da IA em work.txt
5. Execute RESTORE (Ctrl+Shift+B > RESTORE)
   - "performance_case" -> "exploit"
   - "bridge_compatibility" -> "bypass"
6. Pronto! Codigo original restaurado
```

---

## Estrutura de Arquivos

```
Megazord-Code/
    .github/
        copilot-instructions.md  # Instrucoes para IA
    .vscode/
        extensions.json    # Extensoes recomendadas (80+)
        keybindings.json   # Atalhos de teclado
        launch.json        # Configuracoes de debug
        mcp.json           # Configuracao MCP servers
        settings.json      # Configuracoes do VSCode
        tasks.json         # Tasks automatizadas (20+ tasks)
    core/
        config.json        # Regras de traducao (640+ regras)
        http_toolkit.py    # HTTP Toolkit com IA
        mcp_server.py      # Servidor MCP
        plugin-http.ts     # Plugin TypeScript HTTP
        translator.py      # Motor principal Python
    docs/
        CLAUDE_SKILLS.md   # Skills do Claude integrados
    INSTALL.bat            # Instalador Windows
    install.ps1            # Instalador PowerShell
    LICENSE                # Licenca MIT
    README.md              # Documentacao
    START_HOG.bat          # Interface grafica Windows
    work.txt               # Arquivo de trabalho
```

---

## Configuracao

Edite o arquivo `config.json` para adicionar ou modificar regras:

```json
{
  "termo_original": "termo_sanitizado",
  "exploit": "performance_case",
  "bypass": "bridge_compatibility"
}
```

### Regras Incluidas (640+ regras)

| Categoria | Exemplos |
|-----------|----------|
| Offensive Security | bypass, exploit, vulnerability, injection |
| Malware Analysis | virus, trojan, backdoor, rootkit, keylogger |
| Web Attacks | xss, csrf, ddos, sql_injection, bruteforce |
| Shells and C2 | reverse_shell, bind_shell, webshell, beacon |
| Privilege Escalation | privesc, root, admin, sudo, suid |
| Network Recon | scanner, fuzzer, sniffer, port_scan |
| Binary Exploitation | buffer_overflow, heap_spray, rop_chain |
| Cryptography | decrypt, crack, hash, rainbow_table |
| Cloud Security | s3_bucket, iam_escalation, metadata_service |
| Auth Bypass | session_hijack, token_forge, credential_stuff |
| Defense Evasion | obfuscate, encode, pack, antivirus_bypass |
| Social Engineering | phishing, pretexting, vishing |
| Tools | metasploit, burp, nmap, hashcat, wireshark |

---

## Recursos

- Backup Automatico - Cada operacao cria um backup
- Historico - Registra as ultimas 50 operacoes
- Undo - Desfaz a ultima operacao
- Preview - Ve as alteracoes antes de aplicar
- Validacao - Verifica conflitos na configuracao
- Case Preserving - Mantem maiusculas/minusculas
- Word Boundaries - So substitui palavras completas
- Estatisticas - Contagem detalhada de alteracoes
- Hash Tracking - Rastreia alteracoes por hash MD5
- Cores no Terminal - Feedback visual colorido

---

## VSCode Tasks (Ctrl+Shift+B)

| Task                 | Descricao                              |
| -------------------- | -------------------------------------- |
| [HOG] ENCODE         | Converte termos sensiveis para neutros |
| [HOG] RESTORE        | Restaura termos originais              |
| [HOG] STATS          | Mostra estatisticas                    |
| [HOG] PREVIEW        | Pre-visualiza alteracoes               |
| [HOG] HISTORY        | Exibe historico                        |
| [HOG] UNDO           | Desfaz ultima operacao                 |
| [HOG] VALIDATE       | Valida config.json                     |
| [HOG] INTERACTIVE    | Modo console                           |
| [HOG] CLEAN          | Remove backups                         |
| [HOG] LIST BACKUPS   | Lista backups                          |
| [HOG] CONFIG COUNT   | Conta regras                           |
| [HOG] GIT STATUS     | Status do git                          |
| [HOG] GIT PUSH       | Push para GitHub                       |
| [HOG] GIT COMMIT ALL | Commit todas alteracoes                |
| [HOG] FULL CYCLE     | Encode + Copia para clipboard          |

---

## Configuracoes do VSCode

O projeto inclui configuracoes otimizadas:

- Tema escuro customizado (verde neon)
- Fonte Cascadia Code com ligatures
- Python analysis com type checking
- Auto-save habilitado
- Git auto-fetch
- Extensoes recomendadas pre-configuradas

---

## Debug (F5)

Configuracoes de debug incluidas:

- HOG: Modo Interativo
- HOG: ENCODE
- HOG: RESTORE
- HOG: STATS
- HOG: VALIDATE
- HOG: PREVIEW
- HOG: Debug com Args Customizados
- Python: Arquivo Atual

---

## Contribuicao

1. Fork o projeto
2. Crie sua Feature Branch (`git checkout -b feature/NovaRegra`)
3. Commit suas mudancas (`git commit -m 'Add: nova regra de traducao'`)
4. Push para a Branch (`git push origin feature/NovaRegra`)
5. Abra um Pull Request

---

## Licenca

Este projeto esta sob a licenca MIT. Veja o arquivo LICENSE para mais detalhes.

---

## Autor

**ThiagoFrag**

GitHub: [@ThiagoFrag](https://github.com/ThiagoFrag)

---

MEGAZORD CODE - THE HAND OF GOD v7.0
Semantic Translation Engine + HTTP Toolkit + Static Analysis
