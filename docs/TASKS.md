# LEVIATHAN VS — Task Reference (v14.2.0)

> Auto-generated from `.vscode/tasks.json`.
> Total: **138 tasks** across **24 categories**.
> Last updated: 2026-02-25

---

## Table of Contents

- [ADB (16)](#category-adb)
- [ANDROGUARD (2)](#category-androguard)
- [APKTOOL (2)](#category-apktool)
- [BLUESTACKS (2)](#category-bluestacks)
- [BURP (3)](#category-burp)
- [FFUF (1)](#category-ffuf)
- [FRIDA (14)](#category-frida)
- [GHIDRA (5)](#category-ghidra)
- [HASHCAT (3)](#category-hashcat)
- [JADX (7)](#category-jadx)
- [LDPLAYER (10)](#category-ldplayer)
- [LEVIATHAN (33)](#category-leviathan)
- [MEMU (3)](#category-memu)
- [MITMPROXY (2)](#category-mitmproxy)
- [NMAP (2)](#category-nmap)
- [NOX (4)](#category-nox)
- [NUCLEI (2)](#category-nuclei)
- [OBJECTION (6)](#category-objection)
- [R2 (3)](#category-r2)
- [SCAPY (2)](#category-scapy)
- [SQLMAP (1)](#category-sqlmap)
- [SUBFINDER (1)](#category-subfinder)
- [WIRESHARK (9)](#category-wireshark)
- [WORKFLOW (5)](#category-workflow)

---

## Category: ADB
**16 tasks**

| Task | Description |
|------|-------------|
| `[ADB] Listar Dispositivos` | Lista todos os dispositivos ADB conectados com detalhes |
| `[ADB] Shell Interativo` | Abre shell interativo no dispositivo Android |
| `[ADB] Instalar APK` | Instala APK com reinstall e grant de permissoes |
| `[ADB] Extrair APK de App` | Extrai APK instalado do dispositivo para o PC |
| `[ADB] Screenshot` | Captura screenshot do dispositivo |
| `[ADB] Listar Apps Instalados` | Lista todos os apps de terceiros instalados |
| `[ADB] Logcat Filtrado` | Captura logcat filtrado por package |
| `[ADB] Force Stop App` | Forca parada de um app |
| `[ADB] Limpar Dados do App` | Limpa todos os dados e cache do app |
| `[ADB] Configurar Proxy` | Configura proxy HTTP no dispositivo apontando para este PC |
| `[ADB] Remover Proxy` | Remove proxy HTTP do dispositivo |
| `[ADB] Port Forward` | Configura port forward para Frida (27042/27043) |
| `[ADB] Info do Dispositivo` | Mostra info completa do dispositivo (modelo, Android, RAM, disco) |
| `[ADB] Gravar Tela` | Grava tela do dispositivo por 30 segundos |
| `[ADB] TCP Dump (Captura Rede)` | Captura trafego de rede do dispositivo com tcpdump |
| `[ADB] Conectar WiFi` | Conecta ADB via WiFi (dispositivo deve estar conectado via USB) |

---

## Category: ANDROGUARD
**2 tasks**

| Task | Description |
|------|-------------|
| `[ANDROGUARD] Security Audit` | Analise de seguranca APK via Androguard (permissoes, componentes) |
| `[ANDROGUARD] Extract Strings` | Extrai strings interessantes do APK via Androguard |

---

## Category: APKTOOL
**2 tasks**

| Task | Description |
|------|-------------|
| `[APKTOOL] Decode APK` | Decodifica APK com APKTool (resources + smali) |
| `[APKTOOL] Rebuild + Sign APK` | Rebuild APK from smali + sign with debug keystore |

---

## Category: BLUESTACKS
**2 tasks**

| Task | Description |
|------|-------------|
| `[BLUESTACKS] Listar Instancias` | Lista instancias do BlueStacks |
| `[BLUESTACKS] Conectar ADB` | Conecta ADB ao BlueStacks (porta padrao 5555) |

---

## Category: BURP
**3 tasks**

| Task | Description |
|------|-------------|
| `[BURP] Iniciar Active Scan` | Inicia active scan no Burp Suite via REST API |
| `[BURP] Ver Issues/Vulns` | Lista vulnerabilidades encontradas pelo Burp |
| `[BURP] Historico do Proxy` | Mostra ultimas 50 requisicoes do proxy Burp |

---

## Category: FFUF
**1 tasks**

| Task | Description |
|------|-------------|
| `[FFUF] Directory Fuzzing` | Fuzzing de diretorios com ffuf |

---

## Category: FRIDA
**14 tasks**

| Task | Description |
|------|-------------|
| `[FRIDA] Setup Server no Device` | Auto-detecta arch, baixa frida-server correto e inicia no device |
| `[FRIDA] Listar Processos` | Lista todos os processos rodando via USB |
| `[FRIDA] Listar Apps` | Lista todos os apps instalados via Frida |
| `[FRIDA] Bypass SSL Pinning` | Spawna app com bypass SSL (21 camadas: OkHttp, Conscrypt, Flutter, OpenSSL) |
| `[FRIDA] Bypass Root Detection` | Spawna app com bypass de deteccao de root |
| `[FRIDA] Bypass Emulator Detection` | Spawna app com bypass de deteccao de emulador |
| `[FRIDA] Bypass ALL (Nuclear)` | Spawna app com TODOS os bypasses (SSL + Root + Emulator + Frida + Integrity) |
| `[FRIDA] Interceptar Crypto` | Intercepta Cipher, Mac, MessageDigest, SecretKey - mostra chaves e dados |
| `[FRIDA] Interceptar Rede` | Intercepta send/recv/HTTP/OkHttp - mostra URL, headers, body |
| `[FRIDA] Game Inspector` | Inspector para jogos mobile - hooks de Unity, Cocos2d, protocolo, memoria |
| `[FRIDA] Dump Classes Java` | Lista classes Java carregadas filtrando pelo padrao informado |
| `[FRIDA] Hook Metodo Java` | Hook metodo Java - mostra args e retorno em tempo real |
| `[FRIDA] Trace com frida-trace` | Trace automatico de todas as chamadas que matcham o padrao |
| `[FRIDA] Attach a App Rodando` | Attach Frida a app ja em execucao (REPL interativo) |

---

## Category: GHIDRA
**5 tasks**

| Task | Description |
|------|-------------|
| `[GHIDRA] Analisar Binario` | Analise headless completa do binario (ELF, PE, .so, .dll) |
| `[GHIDRA] Listar Funcoes` | Lista todas as funcoes do ultimo binario analisado |
| `[GHIDRA] Buscar Strings` | Busca todas as strings no binario (URLs, chaves, paths) |
| `[GHIDRA] Listar Exports` | Lista simbolos exportados do binario |
| `[GHIDRA] Listar Imports` | Lista simbolos importados do binario |

---

## Category: HASHCAT
**3 tasks**

| Task | Description |
|------|-------------|
| `[HASHCAT] Identify Hash` | Identifica tipo de hash por regex patterns |
| `[HASHCAT] Crack Hash (Dictionary)` | Crack hashes MD5 com ataque dicionario (mode 0) |
| `[HASHCAT] Benchmark GPU` | Benchmark de performance GPU para todos os modos |

---

## Category: JADX
**7 tasks**

| Task | Description |
|------|-------------|
| `[JADX] Decompilar APK` | Decompila APK para codigo Java com deobfuscacao |
| `[JADX] Extrair Manifest` | Extrai AndroidManifest.xml decodificado |
| `[JADX] Buscar URLs/IPs no Codigo` | Busca URLs e IPs hardcoded no codigo decompilado |
| `[JADX] Buscar Crypto no Codigo` | Busca implementacoes criptograficas no codigo |
| `[JADX] Buscar API Keys/Secrets` | Busca API keys, secrets e tokens hardcoded |
| `[JADX] Listar Permissoes` | Extrai todas as permissoes do AndroidManifest |
| `[JADX] Listar Native Libs (.so)` | Lista bibliotecas nativas (.so) do APK decompilado |

---

## Category: LDPLAYER
**10 tasks**

| Task | Description |
|------|-------------|
| `[LDPLAYER] Listar Instancias` | Lista todas as instancias LDPlayer com detalhes |
| `[LDPLAYER] Iniciar Instancia` | Inicia instancia LDPlayer pelo index |
| `[LDPLAYER] Parar Instancia` | Para instancia LDPlayer pelo index |
| `[LDPLAYER] Parar Todas` | Para todas as instancias LDPlayer |
| `[LDPLAYER] Instalar APK` | Instala APK na instancia LDPlayer |
| `[LDPLAYER] Perfil Device Real` | Aplica perfil de dispositivo real (Samsung, Pixel, Xiaomi, etc) |
| `[LDPLAYER] Randomizar Device` | Randomiza IMEI, MAC, Android ID e telefone da instancia |
| `[LDPLAYER] Definir GPS` | Define localizacao GPS fake na instancia |
| `[LDPLAYER] Clonar Instancia` | Clona instancia LDPlayer existente |
| `[LDPLAYER] Ativar/Desativar Root` | Ativa root na instancia LDPlayer |

---

## Category: LEVIATHAN
**33 tasks**

| Task | Description |
|------|-------------|
| `[LEVIATHAN] ENCODE - Preparar para IA` | Converte termos sensiveis para termos neutros antes de enviar para IA |
| `[LEVIATHAN] RESTORE - Restaurar Original` | Restaura os termos originais apos receber resposta da IA |
| `[LEVIATHAN] SMART RESTORE - Restaurar e Abrir` | Restaura os termos e foca o editor no arquivo |
| `[LEVIATHAN] FULL CYCLE - Encode + Copy` | Sanitiza, valida conteudo e copia para clipboard - pronto para CTRL+V na IA |
| `[LEVIATHAN] STATS - Estatisticas` | Mostra estatisticas do arquivo work.txt e regras de traducao |
| `[LEVIATHAN] PREVIEW - Ver Alteracoes` | Pre-visualiza as alteracoes sem modificar o arquivo |
| `[LEVIATHAN] CHECK - Verificar Seguranca` | Verifica se o arquivo esta limpo (sem termos sensiveis) |
| `[LEVIATHAN] HISTORY - Historico` | Exibe historico de todas as operacoes realizadas |
| `[LEVIATHAN] UNDO - Desfazer Ultima` | Desfaz a ultima operacao de encode ou restore |
| `[LEVIATHAN] VALIDATE - Validar Config` | Valida integridade do config.json e detecta conflitos |
| `[LEVIATHAN] INTERACTIVE - Modo Console` | Inicia modo interativo com menu completo |
| `[LEVIATHAN] OBFUSCATE - Ofuscar Variaveis` | Renomeia variaveis sensiveis para var_a1, var_b2, etc. |
| `[LEVIATHAN] DEOBFUSCATE - Restaurar Variaveis` | Restaura nomes originais das variaveis ofuscadas |
| `[LEVIATHAN] FULL TRANSFORM - Encode + Obfuscate` | Aplica encode semantico + ofuscacao de variaveis em um passo |
| `[LEVIATHAN] GIT - SAFE DEPLOY` | Comita e sobe pro Git APENAS se o codigo estiver sanitizado |
| `[LEVIATHAN] GIT STATUS` | Mostra status do repositorio git |
| `[LEVIATHAN] GIT PUSH` | Envia alteracoes para o GitHub |
| `[LEVIATHAN] GIT COMMIT ALL` | Adiciona e comita todas as alteracoes |
| `[LEVIATHAN] CLEAN - Limpar Backups` | Remove todos os backups e arquivos temporarios |
| `[LEVIATHAN] LIST BACKUPS - Listar Backups` | Lista todos os arquivos de backup existentes |
| `[LEVIATHAN] CONFIG COUNT - Contar Regras` | Conta o numero total de regras no config.json |
| `[LEVIATHAN] START_HOG.bat` | Abre a interface grafica do LEVIATHAN |
| `[LEVIATHAN] MCP SERVER - Iniciar` | Inicia o servidor MCP para traducao em tempo real |
| `[LEVIATHAN] MCP TEST - Testar Servidor` | Testa se o servidor MCP esta funcionando |
| `[LEVIATHAN] HTTP TOOLKIT - Iniciar Interceptador` | Abre a interface de manipulacao de requisicoes com protecao HOG |
| `[LEVIATHAN] HTTP TOOLKIT - Testar Endpoint` | Testa um endpoint com protecao HOG integrada |
| `[LEVIATHAN] HTTP TOOLKIT - Scan Rapido` | Executa logic_stress_analysis no endpoint |
| `[LEVIATHAN] Doctor` | Healthcheck completo: Python, configs, tools, permissions |
| `[LEVIATHAN] Validate Configs` | Valida config.json, mcp.json e tasks.json |
| `[LEVIATHAN] Run Tests` | Roda testes unitarios via pytest |
| `[LEVIATHAN] Lint` | Lint com ruff (regras em pyproject.toml) |
| `[LEVIATHAN] Export Report` | Exporta report de ambiente em Markdown |
| `[LEVIATHAN] Status Completo` | Verifica status de TODAS as ferramentas (ADB, Frida, Ghidra, Jadx, tshark, Nuclei, Nmap, Objection, LDPlayer, R2, Hashcat, Scapy, MITMProxy) |

---

## Category: MEMU
**3 tasks**

| Task | Description |
|------|-------------|
| `[MEMU] Listar Instancias` | Lista todas as instancias MEmu |
| `[MEMU] Iniciar Instancia` | Inicia instancia MEmu pelo index |
| `[MEMU] Conectar ADB` | Conecta ADB ao MEmu (porta padrao 21503) |

---

## Category: MITMPROXY
**2 tasks**

| Task | Description |
|------|-------------|
| `[MITMPROXY] Start Proxy` | Inicia mitmproxy interativo na porta especificada |
| `[MITMPROXY] Dump Traffic` | Captura trafego HTTPS via mitmdump para arquivo .flow |

---

## Category: NMAP
**2 tasks**

| Task | Description |
|------|-------------|
| `[NMAP] Port Scan` | Nmap scan com scripts e deteccao de versao |
| `[NMAP] Scan Vuln Scripts` | Nmap com scripts de vulnerabilidade |

---

## Category: NOX
**4 tasks**

| Task | Description |
|------|-------------|
| `[NOX] Listar Instancias` | Lista todas as instancias NoxPlayer |
| `[NOX] Iniciar Instancia` | Inicia instancia NoxPlayer |
| `[NOX] Conectar ADB` | Conecta ADB ao NoxPlayer (porta padrao 62001) |
| `[NOX] Parar Todas` | Para todas as instancias NoxPlayer |

---

## Category: NUCLEI
**2 tasks**

| Task | Description |
|------|-------------|
| `[NUCLEI] Scan Completo` | Scan nuclei completo (critical + high + medium) |
| `[NUCLEI] Scan CVE Especifico` | Scan focado em CVEs criticos e altos |

---

## Category: OBJECTION
**6 tasks**

| Task | Description |
|------|-------------|
| `[OBJECTION] Explore App` | Inicia sessao interativa objection explore no app |
| `[OBJECTION] Disable SSL Pinning` | Inicia objection com SSL pinning desativado |
| `[OBJECTION] Disable Root Detection` | Inicia objection com deteccao de root desativada |
| `[OBJECTION] Dump Keystore` | Dump de entradas do Android Keystore |
| `[OBJECTION] Patch APK (Inject Frida)` | Patcha APK com Frida gadget para injecao persistente |
| `[OBJECTION] Listar Activities` | Lista activities do app Android |

---

## Category: R2
**3 tasks**

| Task | Description |
|------|-------------|
| `[R2] Analyze Binary` | Analise completa do binario: info + funcoes + strings |
| `[R2] Disassemble Function` | Disassembla funcao especifica do binario |
| `[R2] Decompile Function` | Decompila funcao para pseudo-C (requer r2ghidra) |

---

## Category: SCAPY
**2 tasks**

| Task | Description |
|------|-------------|
| `[SCAPY] ARP Scan` | Scan ARP para descobrir hosts na rede local |
| `[SCAPY] Port Scan` | SYN scan nas 20 portas mais comuns via Scapy |

---

## Category: SQLMAP
**1 tasks**

| Task | Description |
|------|-------------|
| `[SQLMAP] SQL Injection Test` | Testa SQL injection com SQLMap (nivel 3, risco 2) |

---

## Category: SUBFINDER
**1 tasks**

| Task | Description |
|------|-------------|
| `[SUBFINDER] Enum Subdominios` | Enumeracao de subdominios |

---

## Category: WIRESHARK
**9 tasks**

| Task | Description |
|------|-------------|
| `[WIRESHARK] Capturar Trafego` | Captura trafego de rede por 60 segundos |
| `[WIRESHARK] Analisar PCAP` | Analisa pcap com estatisticas de I/O, conversas e endpoints |
| `[WIRESHARK] Extrair DNS Queries` | Extrai todas as queries DNS do pcap |
| `[WIRESHARK] Extrair HTTP Requests` | Extrai requests HTTP (method, host, URI) |
| `[WIRESHARK] Buscar Credenciais` | Busca credenciais em texto claro (HTTP Basic, FTP, SMTP) |
| `[WIRESHARK] TLS Handshakes` | Extrai info de TLS handshakes (SNI, versao) |
| `[WIRESHARK] Seguir Stream TCP` | Segue primeira stream TCP (mostra dados completos) |
| `[WIRESHARK] Hierarquia de Protocolos` | Mostra hierarquia de protocolos do pcap |
| `[WIRESHARK] Listar Interfaces` | Lista interfaces de rede disponiveis para captura |

---

## Category: WORKFLOW
**5 tasks**

| Task | Description |
|------|-------------|
| `[WORKFLOW] Full App Pentest` | Pipeline completo: Extract APK -> Decompile -> Search Secrets -> Bypass -> Attach |
| `[WORKFLOW] Quick Intercept` | Inicia app com SSL bypass + Network interceptor + Crypto interceptor |
| `[WORKFLOW] Full Network Capture` | Captura simultanea: trafego do dispositivo + trafego local |
| `[WORKFLOW] Emulator Farm (Multi-Instance)` | Cria farm de 3 instancias clonadas com identidades randomizadas |
| `[WORKFLOW] APK Security Audit` | Audit completo: Decompile -> Permissions -> URLs -> Crypto -> Secrets |

---
