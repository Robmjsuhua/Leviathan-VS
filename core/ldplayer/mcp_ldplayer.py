#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP LDPlayer Server v4.0

    Model Context Protocol server for full LDPlayer administration.
    JSON-RPC 2.0 over stdio with Content-Length framing. Exposes ALL capabilities:

    - ADB Management (connect, shell, apps, files, screenshots, input, network, battery, etc.)
    - Frida Engine (attach, hook, trace, bypass, intercept, memory, class inspection)
    - LDConsole (instance management, hardware config, snapshots, profiles, batch ops)
    - Protection Bypass (SSL, root, emulator, frida, integrity, auto-scan, custom class)
    - Network Interception, Crypto Analysis, Game Inspection
    - Script Library (8 standalone Frida scripts)

    v4.0 Changes:
        - Fixed CRITICAL constructor bugs (FridaEngine/ADBManager params)
        - Content-Length framing for proper MCP protocol compliance
        - Null safety with _require() guards on all component access
        - prompts/get handler with guided workflows
        - notifications/initialized and notifications/cancelled support
        - 30+ new tools (battery, memory, CPU, dumpsys, class_info, trace_native, etc.)
        - Grouped _dispatch_tool for cleaner code
        - Binary mode stdout on Windows

    Author: ThiagoFrag / LEVIATHAN VS
    Version: 4.0.0
================================================================================
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Logging ──
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("leviathan-ldplayer-mcp")

# ── Constants ──
VERSION = "4.0.0"
SERVER_NAME = "leviathan-ldplayer-server"
BASE_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = BASE_DIR / "frida_scripts"

# ── Imports from local modules ──
try:
    from .adb_manager import ADBManager
except ImportError:
    ADBManager = None

try:
    from .frida_engine import FridaEngine
except ImportError:
    FridaEngine = None

try:
    from .ldconsole import LDConsole
except ImportError:
    LDConsole = None

try:
    from .protection_bypass import ProtectionBypass
except ImportError:
    ProtectionBypass = None

try:
    from .orchestrator import Orchestrator
except ImportError:
    Orchestrator = None


# ╔══════════════════════════════════════════════════════════════════════╗
# ║                         TOOL DEFINITIONS                            ║
# ╚══════════════════════════════════════════════════════════════════════╝


def _build_tools() -> List[Dict]:
    """Build the full tool catalogue."""
    return [
        # ━━━━━━━━━━ ADB ━━━━━━━━━━
        {
            "name": "adb_connect",
            "description": "Conecta ao dispositivo via ADB. Se host/port nao forem fornecidos, auto-detecta LDPlayer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "IP do dispositivo (default: 127.0.0.1)",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Porta ADB (default: 5555)",
                    },
                    "instance_index": {
                        "type": "integer",
                        "description": "Indice da instancia LDPlayer (0-based)",
                    },
                },
            },
        },
        {
            "name": "adb_disconnect",
            "description": "Desconecta do dispositivo ADB.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "adb_devices",
            "description": "Lista todos os dispositivos ADB conectados.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "adb_shell",
            "description": "Executa comando shell no dispositivo via ADB.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Comando shell para executar",
                    }
                },
                "required": ["command"],
            },
        },
        {
            "name": "adb_device_info",
            "description": "Retorna informacoes completas do dispositivo (modelo, Android, CPU, RAM, etc.).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "adb_install_apk",
            "description": "Instala um APK no dispositivo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "apk_path": {
                        "type": "string",
                        "description": "Caminho local do APK",
                    },
                    "replace": {
                        "type": "boolean",
                        "description": "Substituir se ja instalado (default: true)",
                    },
                    "grant_permissions": {
                        "type": "boolean",
                        "description": "Conceder todas permissoes (default: true)",
                    },
                },
                "required": ["apk_path"],
            },
        },
        {
            "name": "adb_uninstall_app",
            "description": "Desinstala um app pelo package name.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "package_name": {
                        "type": "string",
                        "description": "Package name do app",
                    }
                },
                "required": ["package_name"],
            },
        },
        {
            "name": "adb_list_packages",
            "description": "Lista packages instalados. Filtro opcional.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "filter": {
                        "type": "string",
                        "description": "Filtro para nome do package",
                    },
                    "third_party_only": {
                        "type": "boolean",
                        "description": "Apenas apps de terceiros",
                    },
                },
            },
        },
        {
            "name": "adb_start_app",
            "description": "Inicia um app pelo package name.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "package_name": {
                        "type": "string",
                        "description": "Package name do app",
                    }
                },
                "required": ["package_name"],
            },
        },
        {
            "name": "adb_force_stop",
            "description": "Forca parada de um app.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "package_name": {
                        "type": "string",
                        "description": "Package name do app",
                    }
                },
                "required": ["package_name"],
            },
        },
        {
            "name": "adb_clear_data",
            "description": "Limpa dados de um app.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "package_name": {
                        "type": "string",
                        "description": "Package name do app",
                    }
                },
                "required": ["package_name"],
            },
        },
        {
            "name": "adb_pull_apk",
            "description": "Puxa o APK de um app instalado.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "package_name": {
                        "type": "string",
                        "description": "Package name do app",
                    },
                    "output_path": {
                        "type": "string",
                        "description": "Caminho local de destino",
                    },
                },
                "required": ["package_name"],
            },
        },
        {
            "name": "adb_screenshot",
            "description": "Captura screenshot do dispositivo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "output_path": {
                        "type": "string",
                        "description": "Caminho local para salvar (default: screenshot.png)",
                    }
                },
            },
        },
        {
            "name": "adb_screen_record",
            "description": "Grava video da tela.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "duration": {
                        "type": "integer",
                        "description": "Duracao em segundos (default: 10)",
                    },
                    "output_path": {
                        "type": "string",
                        "description": "Caminho local para salvar",
                    },
                },
            },
        },
        {
            "name": "adb_tap",
            "description": "Toca na tela nas coordenadas especificadas.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "x": {"type": "integer", "description": "Coordenada X"},
                    "y": {"type": "integer", "description": "Coordenada Y"},
                },
                "required": ["x", "y"],
            },
        },
        {
            "name": "adb_swipe",
            "description": "Faz swipe na tela.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "x1": {"type": "integer"},
                    "y1": {"type": "integer"},
                    "x2": {"type": "integer"},
                    "y2": {"type": "integer"},
                    "duration_ms": {
                        "type": "integer",
                        "description": "Duracao em ms (default: 300)",
                    },
                },
                "required": ["x1", "y1", "x2", "y2"],
            },
        },
        {
            "name": "adb_input_text",
            "description": "Digita texto no dispositivo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Texto para digitar"}
                },
                "required": ["text"],
            },
        },
        {
            "name": "adb_key_event",
            "description": "Envia key event (BACK, HOME, MENU, POWER, etc.).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "Nome ou codigo da tecla (ex: BACK, HOME, 3)",
                    }
                },
                "required": ["key"],
            },
        },
        {
            "name": "adb_push_file",
            "description": "Envia arquivo do PC para o dispositivo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "local_path": {
                        "type": "string",
                        "description": "Caminho local do arquivo",
                    },
                    "remote_path": {
                        "type": "string",
                        "description": "Caminho no dispositivo",
                    },
                },
                "required": ["local_path", "remote_path"],
            },
        },
        {
            "name": "adb_pull_file",
            "description": "Puxa arquivo do dispositivo para o PC.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "remote_path": {
                        "type": "string",
                        "description": "Caminho no dispositivo",
                    },
                    "local_path": {
                        "type": "string",
                        "description": "Caminho local de destino",
                    },
                },
                "required": ["remote_path", "local_path"],
            },
        },
        {
            "name": "adb_logcat",
            "description": "Captura logcat com filtros opcionais.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "filter_tag": {"type": "string", "description": "Filtrar por tag"},
                    "filter_package": {
                        "type": "string",
                        "description": "Filtrar por package",
                    },
                    "lines": {
                        "type": "integer",
                        "description": "Numero de linhas (default: 100)",
                    },
                    "level": {
                        "type": "string",
                        "enum": ["V", "D", "I", "W", "E", "F"],
                        "description": "Nivel minimo",
                    },
                },
            },
        },
        {
            "name": "adb_set_proxy",
            "description": "Configura proxy HTTP no dispositivo. Remove com clear=true.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "IP do proxy"},
                    "port": {"type": "integer", "description": "Porta do proxy"},
                    "clear": {"type": "boolean", "description": "Remover proxy"},
                },
            },
        },
        {
            "name": "adb_port_forward",
            "description": "Cria port forwarding (PC:local_port -> Device:remote_port).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "local_port": {"type": "integer"},
                    "remote_port": {"type": "integer"},
                },
                "required": ["local_port", "remote_port"],
            },
        },
        {
            "name": "adb_get_prop",
            "description": "Le uma propriedade do sistema Android.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prop": {
                        "type": "string",
                        "description": "Nome da propriedade (ex: ro.product.model)",
                    }
                },
                "required": ["prop"],
            },
        },
        {
            "name": "adb_set_prop",
            "description": "Define uma propriedade do sistema (requer root).",
            "inputSchema": {
                "type": "object",
                "properties": {"prop": {"type": "string"}, "value": {"type": "string"}},
                "required": ["prop", "value"],
            },
        },
        {
            "name": "adb_reboot",
            "description": "Reinicia o dispositivo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "mode": {
                        "type": "string",
                        "enum": ["normal", "recovery", "bootloader"],
                        "description": "Modo de reboot",
                    }
                },
            },
        },
        # ━━━━━━━━━━ FRIDA ━━━━━━━━━━
        {
            "name": "frida_setup",
            "description": "Configura o Frida server no dispositivo (push + start). Faz tudo automaticamente.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server_path": {
                        "type": "string",
                        "description": "Caminho local do frida-server binary",
                    }
                },
            },
        },
        {
            "name": "frida_list_processes",
            "description": "Lista processos rodando no dispositivo.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "frida_list_apps",
            "description": "Lista apps instalados no dispositivo via Frida.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "running_only": {
                        "type": "boolean",
                        "description": "Apenas apps em execucao",
                    }
                },
            },
        },
        {
            "name": "frida_attach",
            "description": "Attach ao processo de um app em execucao.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Package name ou PID do app",
                    }
                },
                "required": ["target"],
            },
        },
        {
            "name": "frida_spawn",
            "description": "Spawna um app com Frida attached (cold start).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "package_name": {
                        "type": "string",
                        "description": "Package name do app",
                    }
                },
                "required": ["package_name"],
            },
        },
        {
            "name": "frida_detach",
            "description": "Desconecta do processo atual.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "frida_inject_script",
            "description": "Injeta script Frida (JavaScript) no processo attachado.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "script": {
                        "type": "string",
                        "description": "Codigo JavaScript do script Frida",
                    },
                    "name": {
                        "type": "string",
                        "description": "Nome identificador do script",
                    },
                },
                "required": ["script"],
            },
        },
        {
            "name": "frida_inject_file",
            "description": "Injeta script Frida de um arquivo .js.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Caminho do arquivo .js",
                    },
                    "name": {"type": "string", "description": "Nome identificador"},
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "frida_unload_script",
            "description": "Remove um script Frida carregado.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Nome do script para remover",
                    }
                },
                "required": ["name"],
            },
        },
        {
            "name": "frida_enumerate_classes",
            "description": "Lista todas as classes Java carregadas. Filtro opcional.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "filter": {
                        "type": "string",
                        "description": "Filtro para nome da classe",
                    }
                },
            },
        },
        {
            "name": "frida_enumerate_methods",
            "description": "Lista todos os metodos de uma classe Java.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "class_name": {
                        "type": "string",
                        "description": "Nome completo da classe Java",
                    }
                },
                "required": ["class_name"],
            },
        },
        {
            "name": "frida_hook_method",
            "description": "Hooking de metodo Java. Intercepta chamadas com args e retorno.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "class_name": {"type": "string", "description": "Nome da classe"},
                    "method_name": {"type": "string", "description": "Nome do metodo"},
                    "on_enter": {
                        "type": "string",
                        "description": "JS callback onEnter",
                    },
                    "on_leave": {
                        "type": "string",
                        "description": "JS callback onLeave",
                    },
                },
                "required": ["class_name", "method_name"],
            },
        },
        {
            "name": "frida_hook_class",
            "description": "Hooking de TODOS os metodos de uma classe.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "class_name": {
                        "type": "string",
                        "description": "Nome completo da classe",
                    }
                },
                "required": ["class_name"],
            },
        },
        {
            "name": "frida_hook_constructor",
            "description": "Hooking do constructor de uma classe.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "class_name": {
                        "type": "string",
                        "description": "Nome completo da classe",
                    }
                },
                "required": ["class_name"],
            },
        },
        {
            "name": "frida_hook_native",
            "description": "Hooking de funcao nativa por nome.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "function_name": {
                        "type": "string",
                        "description": "Nome da funcao nativa",
                    },
                    "module_name": {
                        "type": "string",
                        "description": "Nome da shared library (ex: libnative.so)",
                    },
                },
                "required": ["function_name"],
            },
        },
        {
            "name": "frida_replace_return",
            "description": "Substitui o retorno de um metodo Java por um valor fixo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "class_name": {"type": "string"},
                    "method_name": {"type": "string"},
                    "return_value": {
                        "type": "string",
                        "description": "Valor de retorno (true, false, null, numero, ou string)",
                    },
                },
                "required": ["class_name", "method_name", "return_value"],
            },
        },
        {
            "name": "frida_trace_class",
            "description": "Trace completo de uma classe (todos metodos com args, retorno, backtrace).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "class_name": {"type": "string"},
                    "include_args": {
                        "type": "boolean",
                        "description": "Incluir argumentos (default: true)",
                    },
                    "include_return": {
                        "type": "boolean",
                        "description": "Incluir retorno (default: true)",
                    },
                    "include_backtrace": {
                        "type": "boolean",
                        "description": "Incluir stack trace (default: false)",
                    },
                },
                "required": ["class_name"],
            },
        },
        {
            "name": "frida_memory_scan",
            "description": "Busca padrao de bytes na memoria do processo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Padrao hex (ex: '48 65 6C 6C 6F')",
                    },
                    "module_name": {
                        "type": "string",
                        "description": "Limitar busca a um modulo",
                    },
                },
                "required": ["pattern"],
            },
        },
        {
            "name": "frida_read_memory",
            "description": "Le bytes de um endereco de memoria.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Endereco hex (ex: '0x7fff1234')",
                    },
                    "size": {"type": "integer", "description": "Quantidade de bytes"},
                },
                "required": ["address", "size"],
            },
        },
        {
            "name": "frida_write_memory",
            "description": "Escreve bytes em um endereco de memoria.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Endereco hex"},
                    "data": {
                        "type": "string",
                        "description": "Bytes em hex para escrever",
                    },
                },
                "required": ["address", "data"],
            },
        },
        {
            "name": "frida_list_modules",
            "description": "Lista modulos (shared libraries) carregados no processo.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "frida_list_exports",
            "description": "Lista exports de um modulo nativo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_name": {
                        "type": "string",
                        "description": "Nome do modulo (ex: libnative.so)",
                    }
                },
                "required": ["module_name"],
            },
        },
        {
            "name": "frida_get_messages",
            "description": "Recupera mensagens enviadas pelos scripts Frida (send()).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "script_name": {
                        "type": "string",
                        "description": "Nome do script (ou 'all')",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximo de mensagens (default: 50)",
                    },
                },
            },
        },
        {
            "name": "frida_intercept_crypto",
            "description": "Intercepta todas operacoes criptograficas (Cipher, Mac, MessageDigest, Keys).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "frida_intercept_http",
            "description": "Intercepta todas requisicoes HTTP/HTTPS (OkHttp, URLConnection, Volley, WebView).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "frida_intercept_intents",
            "description": "Intercepta todos Intents (startActivity, sendBroadcast, startService).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "frida_intercept_prefs",
            "description": "Intercepta operacoes em SharedPreferences.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "frida_intercept_sqlite",
            "description": "Intercepta queries SQLite.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "frida_intercept_files",
            "description": "Intercepta operacoes de File I/O.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "frida_android_info",
            "description": "Obtem informacoes do sistema Android via Frida (package, activity, etc.).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "frida_find_instances",
            "description": "Encontra instancias vivas de uma classe no heap.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "class_name": {
                        "type": "string",
                        "description": "Nome completo da classe",
                    }
                },
                "required": ["class_name"],
            },
        },
        {
            "name": "frida_call_method",
            "description": "Chama metodo em instancia de classe (use find_instances primeiro).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "class_name": {"type": "string"},
                    "method_name": {"type": "string"},
                    "args": {
                        "type": "string",
                        "description": "Argumentos em formato JSON",
                    },
                },
                "required": ["class_name", "method_name"],
            },
        },
        {
            "name": "frida_get_field",
            "description": "Le valor de um campo de uma classe/instancia.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "class_name": {"type": "string"},
                    "field_name": {"type": "string"},
                },
                "required": ["class_name", "field_name"],
            },
        },
        {
            "name": "frida_set_field",
            "description": "Define valor de um campo de uma classe/instancia.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "class_name": {"type": "string"},
                    "field_name": {"type": "string"},
                    "value": {"type": "string", "description": "Novo valor"},
                },
                "required": ["class_name", "field_name", "value"],
            },
        },
        # ━━━━━━━━━━ PROTECTION BYPASS ━━━━━━━━━━
        {
            "name": "bypass_all",
            "description": "Aplica TODOS os bypasses universais (SSL + Root + Emulator + Frida + Integrity).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "bypass_ssl",
            "description": "Bypass universal de SSL Pinning (21 camadas incluindo OkHttp3, Conscrypt, Flutter, OpenSSL nativo).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "bypass_root",
            "description": "Bypass universal de Root Detection (File, exec, Build, SystemProperties, PackageManager, native).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "bypass_emulator",
            "description": "Bypass de Emulator Detection (Build props, files, TelephonyManager, WifiInfo, native).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "bypass_frida",
            "description": "Bypass de Frida/Debug Detection (ports, maps, strings, threads, signals).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "bypass_integrity",
            "description": "Bypass de Integrity/Tamper checks (signature, installer, dex).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "bypass_scan",
            "description": "Scan do app para identificar mecanismos de protecao (RootBeer, GameGuard, etc.).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "bypass_auto",
            "description": "Modo automatico: scan + bypass universal + bypass customizado para protecoes encontradas.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "bypass_rootbeer",
            "description": "Bypass especifico para RootBeer library.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "bypass_gameguard",
            "description": "Bypass para GameGuard/nProtect anti-cheat.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "bypass_tencent",
            "description": "Bypass para Tencent TP protection.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "bypass_decompile_scan",
            "description": "Decompila APK e analisa source code para encontrar protecoes. Requer jadx ou apktool.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "apk_path": {
                        "type": "string",
                        "description": "Caminho do APK para decompiler",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Diretorio de saida",
                    },
                },
                "required": ["apk_path"],
            },
        },
        {
            "name": "bypass_inject_universal",
            "description": "Injeta o script universal_bypass.js (all-in-one nuclear bypass).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        # ━━━━━━━━━━ FRIDA SCRIPT LIBRARY ━━━━━━━━━━
        {
            "name": "script_load",
            "description": "Carrega e injeta um script da biblioteca Frida (ssl_bypass, root_bypass, emulator_bypass, frida_bypass, network_interceptor, crypto_interceptor, game_inspector, universal_bypass).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "script_name": {
                        "type": "string",
                        "enum": [
                            "ssl_bypass",
                            "root_bypass",
                            "emulator_bypass",
                            "frida_bypass",
                            "network_interceptor",
                            "crypto_interceptor",
                            "game_inspector",
                            "universal_bypass",
                        ],
                        "description": "Nome do script para carregar",
                    }
                },
                "required": ["script_name"],
            },
        },
        {
            "name": "script_list",
            "description": "Lista scripts disponiveis na biblioteca Frida.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        # ━━━━━━━━━━ LDCONSOLE ━━━━━━━━━━
        {
            "name": "ld_list_instances",
            "description": "Lista todas as instancias LDPlayer.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "ld_create_instance",
            "description": "Cria nova instancia LDPlayer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Nome da instancia"}
                },
                "required": ["name"],
            },
        },
        {
            "name": "ld_launch",
            "description": "Inicia uma instancia LDPlayer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Nome ou indice da instancia",
                    }
                },
                "required": ["name"],
            },
        },
        {
            "name": "ld_quit",
            "description": "Fecha uma instancia LDPlayer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Nome ou indice da instancia",
                    }
                },
                "required": ["name"],
            },
        },
        {
            "name": "ld_reboot",
            "description": "Reinicia uma instancia LDPlayer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Nome ou indice"}
                },
                "required": ["name"],
            },
        },
        {
            "name": "ld_modify_instance",
            "description": "Modifica configuracao de instancia (CPU, RAM, resolucao, IMEI, modelo, etc.).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Nome da instancia"},
                    "resolution": {
                        "type": "string",
                        "description": "Ex: 1920x1080x320",
                    },
                    "cpu": {"type": "integer", "description": "Numero de cores"},
                    "memory": {"type": "integer", "description": "RAM em MB"},
                    "manufacturer": {"type": "string"},
                    "model": {"type": "string"},
                    "imei": {"type": "string"},
                    "mac": {"type": "string"},
                },
                "required": ["name"],
            },
        },
        {
            "name": "ld_set_location",
            "description": "Define GPS da instancia.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "latitude": {"type": "number"},
                    "longitude": {"type": "number"},
                },
                "required": ["name", "latitude", "longitude"],
            },
        },
        {
            "name": "ld_install_app",
            "description": "Instala APK na instancia via ldconsole.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Nome da instancia"},
                    "apk_path": {"type": "string", "description": "Caminho do APK"},
                },
                "required": ["name", "apk_path"],
            },
        },
        {
            "name": "ld_backup",
            "description": "Cria backup (snapshot) de uma instancia.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Nome da instancia"},
                    "backup_path": {
                        "type": "string",
                        "description": "Caminho do backup",
                    },
                },
                "required": ["name", "backup_path"],
            },
        },
        {
            "name": "ld_restore",
            "description": "Restaura backup de uma instancia.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Nome da instancia"},
                    "backup_path": {
                        "type": "string",
                        "description": "Caminho do backup",
                    },
                },
                "required": ["name", "backup_path"],
            },
        },
        {
            "name": "ld_clone",
            "description": "Clona uma instancia. Pode clonar multiplas copias.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source": {
                        "type": "string",
                        "description": "Nome da instancia fonte",
                    },
                    "count": {
                        "type": "integer",
                        "description": "Numero de clones (default: 1)",
                    },
                },
                "required": ["source"],
            },
        },
        {
            "name": "ld_device_profile",
            "description": "Aplica perfil de dispositivo real (Samsung S23, Pixel 8, Xiaomi 14, OnePlus 12, Huawei P60).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Nome da instancia"},
                    "profile": {
                        "type": "string",
                        "enum": [
                            "samsung_s23",
                            "pixel_8",
                            "xiaomi_14",
                            "oneplus_12",
                            "huawei_p60",
                        ],
                        "description": "Perfil de dispositivo",
                    },
                },
                "required": ["name", "profile"],
            },
        },
        {
            "name": "ld_set_root",
            "description": "Ativa/desativa root na instancia.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "enabled": {
                        "type": "boolean",
                        "description": "true para ativar root",
                    },
                },
                "required": ["name", "enabled"],
            },
        },
        {
            "name": "ld_shared_folder",
            "description": "Configura pasta compartilhada entre PC e instancia.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "pc_path": {"type": "string"},
                    "android_path": {"type": "string"},
                },
                "required": ["name", "pc_path"],
            },
        },
        # ━━━━━━━━━━ SYSTEM ━━━━━━━━━━
        {
            "name": "status",
            "description": "Retorna status completo de todos os componentes (ADB, Frida, LDConsole, Bypass).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "help",
            "description": "Lista todas as ferramentas disponiveis com descricoes.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        # ━━━━━━━━━━ NEW v4.0 TOOLS ━━━━━━━━━━
        {
            "name": "adb_battery_info",
            "description": "Retorna informacoes detalhadas da bateria.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "adb_memory_info",
            "description": "Retorna uso de memoria do dispositivo.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "adb_cpu_info",
            "description": "Retorna informacoes da CPU do dispositivo.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "adb_disk_space",
            "description": "Retorna espaco em disco do dispositivo.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "adb_dumpsys",
            "description": "Executa dumpsys de um servico especifico.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Nome do servico (ex: battery, wifi, activity)",
                    }
                },
                "required": ["service"],
            },
        },
        {
            "name": "adb_list_services",
            "description": "Lista todos os servicos do sistema Android.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "adb_wifi_info",
            "description": "Retorna informacoes da conexao WiFi.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "adb_ip_address",
            "description": "Retorna IP do dispositivo.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "adb_airplane_mode",
            "description": "Liga/desliga modo aviao.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "enable": {"type": "boolean", "description": "true para ativar"}
                },
                "required": ["enable"],
            },
        },
        {
            "name": "adb_install_cert",
            "description": "Instala certificado CA no sistema.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cert_path": {
                        "type": "string",
                        "description": "Caminho local do certificado",
                    }
                },
                "required": ["cert_path"],
            },
        },
        {
            "name": "adb_open_url",
            "description": "Abre URL no navegador do dispositivo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL para abrir"}
                },
                "required": ["url"],
            },
        },
        {
            "name": "adb_screen_resolution",
            "description": "Retorna ou define resolucao da tela.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "width": {
                        "type": "integer",
                        "description": "Largura (para definir)",
                    },
                    "height": {
                        "type": "integer",
                        "description": "Altura (para definir)",
                    },
                },
            },
        },
        {
            "name": "adb_package_info",
            "description": "Retorna informacoes detalhadas de um package.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "package_name": {"type": "string", "description": "Package name"}
                },
                "required": ["package_name"],
            },
        },
        {
            "name": "adb_running_processes",
            "description": "Lista processos em execucao no dispositivo.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "adb_focused_activity",
            "description": "Retorna a activity em foco no dispositivo.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "frida_get_class_info",
            "description": "Retorna informacao completa de uma classe Java (metodos, campos, construtores, interfaces).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "class_name": {
                        "type": "string",
                        "description": "Nome completo da classe",
                    }
                },
                "required": ["class_name"],
            },
        },
        {
            "name": "frida_trace_native",
            "description": "Trace de chamadas nativas de um modulo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_name": {
                        "type": "string",
                        "description": "Nome do modulo nativo",
                    },
                    "function_pattern": {
                        "type": "string",
                        "description": "Filtro de funcao (optional)",
                    },
                },
                "required": ["module_name"],
            },
        },
        {
            "name": "frida_list_imports",
            "description": "Lista imports de um modulo nativo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_name": {"type": "string", "description": "Nome do modulo"}
                },
                "required": ["module_name"],
            },
        },
        {
            "name": "frida_intercept_sqlite",
            "description": "Intercepta operacoes SQLite (queries, inserts, updates, deletes).",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "frida_intercept_files",
            "description": "Intercepta operacoes de I/O de arquivos.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "frida_status",
            "description": "Retorna status completo do Frida Engine.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "ld_run_app",
            "description": "Inicia app dentro de uma instancia.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Nome da instancia"},
                    "package_name": {
                        "type": "string",
                        "description": "Package name do app",
                    },
                },
                "required": ["name", "package_name"],
            },
        },
        {
            "name": "ld_kill_app",
            "description": "Para app dentro de uma instancia.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Nome da instancia"},
                    "package_name": {
                        "type": "string",
                        "description": "Package name do app",
                    },
                },
                "required": ["name", "package_name"],
            },
        },
        {
            "name": "ld_randomize_device",
            "description": "Randomiza IMEI, MAC, Android ID e telefone da instancia.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Nome da instancia"}
                },
                "required": ["name"],
            },
        },
        {
            "name": "ld_quit_all",
            "description": "Para todas as instancias LDPlayer.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "ld_instance_config",
            "description": "Retorna configuracao completa de uma instancia.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Nome da instancia"}
                },
                "required": ["name"],
            },
        },
        {
            "name": "bypass_status",
            "description": "Retorna status de todos os bypasses aplicados.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "bypass_custom_class",
            "description": "Aplica bypass automatico baseado em scan de uma classe especifica.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "class_name": {
                        "type": "string",
                        "description": "Nome da classe para bypass",
                    }
                },
                "required": ["class_name"],
            },
        },
        # ━━━━━━━━━━ WORKFLOW / ORCHESTRATOR ━━━━━━━━━━
        {
            "name": "workflow_full_intercept",
            "description": "🚀 Pipeline completo: Abre emulador → abre app → bypass → intercepta tudo → analisa. O comando 'faz tudo'.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "package": {
                        "type": "string",
                        "description": "Package name do app (ex: com.example.game)",
                    },
                    "instance": {
                        "type": "string",
                        "description": "Instancia LDPlayer (default: 0)",
                    },
                    "bypasses": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Lista de bypasses: ssl, root, emulator, frida, integrity, all",
                    },
                    "wait_time": {
                        "type": "integer",
                        "description": "Segundos para coletar dados (default: 5)",
                    },
                },
                "required": ["package"],
            },
        },
        {
            "name": "workflow_quick_attach",
            "description": "⚡ Attach rapido: Conecta Frida a um app JA RODANDO, aplica bypasses e interceptacoes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "package": {
                        "type": "string",
                        "description": "Package name do app",
                    },
                    "bypasses": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Bypasses a aplicar",
                    },
                },
                "required": ["package"],
            },
        },
        {
            "name": "workflow_launch_emulator",
            "description": "Inicia o emulador LDPlayer e aguarda boot completo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "instance": {
                        "type": "string",
                        "description": "Nome ou indice da instancia (default: 0)",
                    }
                },
            },
        },
        {
            "name": "workflow_open_app",
            "description": "Abre um app no emulador (conecta ADB se necessario).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "package": {
                        "type": "string",
                        "description": "Package name do app",
                    }
                },
                "required": ["package"],
            },
        },
        {
            "name": "workflow_intercept_all",
            "description": "Ativa todas as interceptacoes (network, crypto, file_io, intents, shared_prefs, sqlite).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "intercepts": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Lista de interceptacoes (default: todas)",
                    }
                },
            },
        },
        {
            "name": "workflow_analyze",
            "description": "📊 Analisa todos os dados interceptados e gera relatorio completo com findings de seguranca.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "workflow_collect_data",
            "description": "Coleta e categoriza todas as mensagens interceptadas pelo Frida.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "workflow_stop_all",
            "description": "Para tudo: desconecta Frida, fecha app, opcionalmente fecha emulador.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "close_emulator": {
                        "type": "boolean",
                        "description": "Fechar o emulador tambem (default: false)",
                    }
                },
            },
        },
        {
            "name": "workflow_find_app",
            "description": "Busca um app instalado por nome/keyword.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Termo de busca",
                    }
                },
                "required": ["keyword"],
            },
        },
        {
            "name": "workflow_save_report",
            "description": "Salva o relatorio de analise em arquivo JSON.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Caminho do arquivo (default: auto-gerado)",
                    }
                },
            },
        },
        {
            "name": "workflow_status",
            "description": "Mostra o estado completo do orquestrador (emulador, ADB, Frida, bypasses, dados).",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]


# ╔══════════════════════════════════════════════════════════════════════╗
# ║                          MCP SERVER                                 ║
# ╚══════════════════════════════════════════════════════════════════════╝


class MCPLDPlayerServer:
    """MCP Server for full LDPlayer administration."""

    def __init__(self, config_path: Optional[str] = None):
        self.running = True
        self.config = self._load_config(config_path)
        self.tools = _build_tools()

        # Initialize components
        self.adb: Optional[Any] = None
        self.frida: Optional[Any] = None
        self.ldconsole: Optional[Any] = None
        self.bypass: Optional[Any] = None
        self.orchestrator: Optional[Any] = None

        self._init_components()

    def _load_config(self, path: Optional[str]) -> Dict:
        cfg_path = Path(path) if path else BASE_DIR / "config_ldplayer.json"
        if cfg_path.exists():
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Config load error: {e}")
        return {}

    def _init_components(self):
        """Initialize all sub-components with correct constructor signatures."""
        adb_cfg = self.config.get("adb", {})
        frida_cfg = self.config.get("frida", {})
        ld_cfg = self.config.get("ldplayer", {})

        # ADBManager(adb_path, host, base_port, timeout)
        if ADBManager:
            try:
                self.adb = ADBManager(
                    adb_path=adb_cfg.get("adb_path", "adb"),
                    host=adb_cfg.get("host", "127.0.0.1"),
                    base_port=adb_cfg.get("base_port", 5555),
                    timeout=adb_cfg.get("timeout", 30),
                )
                logger.info("ADB Manager initialized")
            except Exception as e:
                logger.warning(f"ADB init failed: {e}")

        # FridaEngine(adb_manager, config) — NOT host/port/server_path
        if FridaEngine:
            try:
                self.frida = FridaEngine(
                    adb_manager=self.adb,
                    config=frida_cfg,
                )
                logger.info("Frida Engine initialized")
            except Exception as e:
                logger.warning(f"Frida init failed: {e}")

        # LDConsole(install_path, ldconsole_name)
        if LDConsole:
            try:
                self.ldconsole = LDConsole(
                    install_path=ld_cfg.get("install_path", r"C:\LDPlayer\LDPlayer9"),
                    ldconsole_name=ld_cfg.get("ldconsole", "ldconsole.exe"),
                )
                logger.info("LDConsole initialized")
            except Exception as e:
                logger.warning(f"LDConsole init failed: {e}")

        # ProtectionBypass(frida_engine, adb_manager)
        if ProtectionBypass:
            try:
                self.bypass = ProtectionBypass(
                    frida_engine=self.frida, adb_manager=self.adb
                )
                logger.info("Protection Bypass initialized")
            except Exception as e:
                logger.warning(f"Bypass init failed: {e}")

        # Orchestrator (uses all other components)
        if Orchestrator:
            try:
                self.orchestrator = Orchestrator(config_path=None)
                # Share existing components to avoid re-init
                self.orchestrator.adb = self.adb
                self.orchestrator.frida = self.frida
                self.orchestrator.ld = self.ldconsole
                self.orchestrator.bypass = self.bypass
                logger.info("Orchestrator initialized")
            except Exception as e:
                logger.warning(f"Orchestrator init failed: {e}")

    # ──────────────────────────────────────────────────────────
    # MCP PROTOCOL HANDLERS
    # ──────────────────────────────────────────────────────────

    async def handle_request(self, request: Dict) -> Optional[Dict]:
        method = request.get("method", "")
        params = request.get("params", {})
        rid = request.get("id")

        logger.info(f"Request: {method}")

        try:
            if method == "initialize":
                return self._handle_initialize(rid, params)
            elif method == "initialized":
                return None
            elif method == "shutdown":
                self.running = False
                return {"jsonrpc": "2.0", "id": rid, "result": None}
            elif method == "tools/list":
                return self._handle_tools_list(rid)
            elif method == "tools/call":
                return await self._handle_tool_call(rid, params)
            elif method == "resources/list":
                return self._handle_resources_list(rid)
            elif method == "resources/read":
                return self._handle_resource_read(rid, params)
            elif method == "prompts/list":
                return self._handle_prompts_list(rid)
            elif method == "prompts/get":
                return self._handle_prompt_get(rid, params)
            elif method == "notifications/initialized":
                return None
            elif method == "notifications/cancelled":
                return None
            else:
                return self._error(rid, -32601, f"Method not found: {method}")
        except Exception as e:
            logger.error(f"Error handling {method}: {e}", exc_info=True)
            return self._error(rid, -32603, str(e))

    def _handle_initialize(self, rid, params: Dict) -> Dict:
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": SERVER_NAME, "version": VERSION},
                "capabilities": {
                    "tools": {"listChanged": True},
                    "resources": {"subscribe": False, "listChanged": True},
                    "prompts": {"listChanged": True},
                },
            },
        }

    def _handle_tools_list(self, rid) -> Dict:
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": self.tools}}

    def _handle_resources_list(self, rid) -> Dict:
        resources = [
            {
                "uri": "ldplayer://scripts",
                "name": "Frida Scripts Library",
                "description": "Biblioteca de scripts Frida universais",
                "mimeType": "application/json",
            },
            {
                "uri": "ldplayer://status",
                "name": "System Status",
                "description": "Status de todos os componentes",
                "mimeType": "application/json",
            },
            {
                "uri": "ldplayer://config",
                "name": "Configuration",
                "description": "Configuracao atual do servidor",
                "mimeType": "application/json",
            },
        ]
        return {"jsonrpc": "2.0", "id": rid, "result": {"resources": resources}}

    def _handle_resource_read(self, rid, params: Dict) -> Dict:
        uri = params.get("uri", "")
        if uri == "ldplayer://scripts":
            scripts = self._list_available_scripts()
            content = json.dumps(scripts, indent=2)
        elif uri == "ldplayer://status":
            content = json.dumps(self._get_full_status(), indent=2)
        elif uri == "ldplayer://config":
            content = json.dumps(self.config, indent=2)
        else:
            return self._error(rid, -32602, f"Resource not found: {uri}")

        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "contents": [
                    {"uri": uri, "mimeType": "application/json", "text": content}
                ]
            },
        }

    def _handle_prompts_list(self, rid) -> Dict:
        prompts = [
            {
                "name": "bypass_app",
                "description": "Bypass completo de protecoes de um app",
                "arguments": [
                    {
                        "name": "package_name",
                        "description": "Package name do app",
                        "required": True,
                    }
                ],
            },
            {
                "name": "analyze_app",
                "description": "Analise completa de um app (classes, metodos, protecoes, network, crypto)",
                "arguments": [
                    {
                        "name": "package_name",
                        "description": "Package name do app",
                        "required": True,
                    }
                ],
            },
            {
                "name": "setup_environment",
                "description": "Setup completo do ambiente (conectar LDPlayer, Frida, auto-bypass)",
                "arguments": [
                    {
                        "name": "instance",
                        "description": "Nome ou indice da instancia LDPlayer",
                        "required": False,
                    }
                ],
            },
        ]
        return {"jsonrpc": "2.0", "id": rid, "result": {"prompts": prompts}}

    def _handle_prompt_get(self, rid, params: Dict) -> Dict:
        """Handle prompts/get — return prompt messages for a given prompt name."""
        prompt_name = params.get("name", "")
        prompt_args = params.get("arguments", {})

        if prompt_name == "bypass_app":
            pkg = prompt_args.get("package_name", "com.example.app")
            messages = [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": (
                            f"Execute o seguinte fluxo para bypass completo do app {pkg}:\n"
                            f"1. Conecte ao dispositivo via ADB\n"
                            f"2. Inicie o Frida server\n"
                            f"3. Faça spawn do app: {pkg}\n"
                            f"4. Aplique todos os bypasses (SSL, root, emulator, frida, integrity)\n"
                            f"5. Injete o universal_bypass.js\n"
                            f"6. Verifique o status dos bypasses\n"
                            f"7. Retorne o status completo"
                        ),
                    },
                }
            ]
        elif prompt_name == "analyze_app":
            pkg = prompt_args.get("package_name", "com.example.app")
            messages = [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": (
                            f"Execute analise completa do app {pkg}:\n"
                            f"1. Conecte ao dispositivo e inicie Frida\n"
                            f"2. Faça attach ao processo {pkg}\n"
                            f"3. Enumere classes Java (filtre pelo package)\n"
                            f"4. Escaneie protecoes (SSL pinning, root, emulator, frida detection)\n"
                            f"5. Intercepte operacoes de criptografia\n"
                            f"6. Intercepte requisicoes HTTP/network\n"
                            f"7. Inspecione SharedPreferences e SQLite\n"
                            f"8. Liste modulos nativos carregados\n"
                            f"9. Gere relatorio completo"
                        ),
                    },
                }
            ]
        elif prompt_name == "setup_environment":
            inst = prompt_args.get("instance", "LDPlayer")
            messages = [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": (
                            f"Configure o ambiente completo para a instancia '{inst}':\n"
                            f"1. Liste instancias LDPlayer disponiveis\n"
                            f"2. Inicie a instancia '{inst}' se nao estiver rodando\n"
                            f"3. Conecte via ADB (auto-detect porta)\n"
                            f"4. Verifique e inicie Frida server\n"
                            f"5. Aplique bypasses de root e emulador\n"
                            f"6. Retorne status completo do ambiente"
                        ),
                    },
                }
            ]
        else:
            return self._error(rid, -32602, f"Prompt not found: {prompt_name}")

        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {"messages": messages},
        }

    # ──────────────────────────────────────────────────────────
    # TOOL CALL DISPATCHER
    # ──────────────────────────────────────────────────────────

    async def _handle_tool_call(self, rid, params: Dict) -> Dict:
        tool = params.get("name", "")
        args = params.get("arguments", {})

        try:
            result = await self._dispatch_tool(tool, args)
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2, default=str),
                        }
                    ]
                },
            }
        except Exception as e:
            logger.error(f"Tool {tool} error: {e}", exc_info=True)
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({"error": str(e)}, indent=2),
                        }
                    ],
                    "isError": True,
                },
            }

    def _require(self, component_name: str):
        """Ensure a component is available, raise clear error if not."""
        comp = getattr(self, component_name, None)
        if comp is None:
            raise RuntimeError(
                f"Component '{component_name}' is not available. "
                f"Check server logs for initialization errors."
            )
        return comp

    async def _dispatch_tool(self, tool: str, args: Dict) -> Any:
        """Route tool call to the appropriate handler."""

        # ── ADB Tools ──
        if tool.startswith("adb_"):
            adb = self._require("adb")

            if tool == "adb_connect":
                return adb.connect(
                    args.get("host", "127.0.0.1"),
                    args.get("port", 5555 + args.get("instance_index", 0) * 2),
                )
            elif tool == "adb_disconnect":
                return adb.disconnect()
            elif tool == "adb_devices":
                return adb.list_devices()
            elif tool == "adb_shell":
                return adb.shell(args["command"])
            elif tool == "adb_device_info":
                return adb.get_device_info()
            elif tool == "adb_install_apk":
                return adb.install_apk(
                    args["apk_path"],
                    replace=args.get("replace", True),
                    grant_permissions=args.get("grant_permissions", True),
                )
            elif tool == "adb_uninstall_app":
                return adb.uninstall_app(args["package_name"])
            elif tool == "adb_list_packages":
                return adb.list_packages(
                    filter_str=args.get("filter"),
                    third_party_only=args.get("third_party_only", False),
                )
            elif tool == "adb_start_app":
                return adb.start_app(args["package_name"])
            elif tool == "adb_force_stop":
                return adb.force_stop(args["package_name"])
            elif tool == "adb_clear_data":
                return adb.clear_app_data(args["package_name"])
            elif tool == "adb_pull_apk":
                return adb.pull_apk(args["package_name"], args.get("output_path"))
            elif tool == "adb_screenshot":
                return adb.screenshot(args.get("output_path", "screenshot.png"))
            elif tool == "adb_screen_record":
                return adb.screen_record(
                    args.get("duration", 10), args.get("output_path", "recording.mp4")
                )
            elif tool == "adb_tap":
                return adb.tap(args["x"], args["y"])
            elif tool == "adb_swipe":
                return adb.swipe(
                    args["x1"],
                    args["y1"],
                    args["x2"],
                    args["y2"],
                    args.get("duration_ms", 300),
                )
            elif tool == "adb_input_text":
                return adb.input_text(args["text"])
            elif tool == "adb_key_event":
                return adb.key_event(args["key"])
            elif tool == "adb_push_file":
                return adb.push_file(args["local_path"], args["remote_path"])
            elif tool == "adb_pull_file":
                return adb.pull_file(args["remote_path"], args["local_path"])
            elif tool == "adb_logcat":
                return adb.logcat(
                    tag=args.get("filter_tag"),
                    package=args.get("filter_package"),
                    lines=args.get("lines", 100),
                    level=args.get("level"),
                )
            elif tool == "adb_set_proxy":
                if args.get("clear"):
                    return adb.shell("settings put global http_proxy :0")
                return adb.set_proxy(args.get("host", ""), args.get("port", 8080))
            elif tool == "adb_port_forward":
                return adb.port_forward(args["local_port"], args["remote_port"])
            elif tool == "adb_get_prop":
                return adb.get_prop(args["prop"])
            elif tool == "adb_set_prop":
                return adb.set_prop(args["prop"], args["value"])
            elif tool == "adb_reboot":
                return adb.reboot(args.get("mode", "normal"))
            # ── New v4.0 ADB Tools ──
            elif tool == "adb_battery_info":
                return adb.get_battery_info()
            elif tool == "adb_memory_info":
                return adb.get_memory_info()
            elif tool == "adb_cpu_info":
                return adb.get_cpu_info()
            elif tool == "adb_disk_space":
                return adb.get_disk_space()
            elif tool == "adb_dumpsys":
                return adb.get_dumpsys(args["service"])
            elif tool == "adb_list_services":
                return adb.list_services()
            elif tool == "adb_wifi_info":
                return adb.get_wifi_info()
            elif tool == "adb_ip_address":
                return {"ip": adb.get_ip_address()}
            elif tool == "adb_airplane_mode":
                return adb.toggle_airplane_mode(args["enable"])
            elif tool == "adb_install_cert":
                return adb.install_certificate(args["cert_path"])
            elif tool == "adb_open_url":
                return adb.open_url(args["url"])
            elif tool == "adb_screen_resolution":
                if args.get("width") and args.get("height"):
                    return adb.set_screen_resolution(args["width"], args["height"])
                return adb.get_screen_resolution()
            elif tool == "adb_package_info":
                return adb.get_package_info(args["package_name"])
            elif tool == "adb_running_processes":
                return adb.list_running_processes()
            elif tool == "adb_focused_activity":
                return {"activity": adb.get_focused_activity()}
            else:
                raise ValueError(f"Unknown adb tool: {tool}")

        # ── Frida Tools ──
        elif tool.startswith("frida_"):
            frida = self._require("frida")

            if tool == "frida_setup":
                results = {}
                if args.get("server_path"):
                    results["push"] = frida.push_server(args["server_path"])
                results["start"] = frida.start_server()
                return results
            elif tool == "frida_list_processes":
                return frida.list_processes()
            elif tool == "frida_list_apps":
                return frida.list_applications(
                    running_only=args.get("running_only", False)
                )
            elif tool == "frida_attach":
                target = args["target"]
                try:
                    target = int(target)
                except ValueError:
                    pass
                return frida.attach(target)
            elif tool == "frida_spawn":
                return frida.spawn(args["package_name"])
            elif tool == "frida_detach":
                return frida.detach()
            elif tool == "frida_inject_script":
                return frida.inject_script(
                    args["script"], args.get("name", "custom_script")
                )
            elif tool == "frida_inject_file":
                return frida.inject_script_file(args["file_path"], args.get("name"))
            elif tool == "frida_unload_script":
                return frida.unload_script(args["name"])
            elif tool == "frida_enumerate_classes":
                return frida.enumerate_classes(args.get("filter"))
            elif tool == "frida_enumerate_methods":
                return frida.enumerate_methods(args["class_name"])
            elif tool == "frida_hook_method":
                return frida.hook_method(
                    args["class_name"],
                    args["method_name"],
                    on_enter=args.get("on_enter"),
                    on_leave=args.get("on_leave"),
                )
            elif tool == "frida_hook_class":
                return frida.hook_class(args["class_name"])
            elif tool == "frida_hook_constructor":
                return frida.hook_constructor(args["class_name"])
            elif tool == "frida_hook_native":
                return frida.hook_native(args["function_name"], args.get("module_name"))
            elif tool == "frida_replace_return":
                return frida.replace_method_return(
                    args["class_name"], args["method_name"], args["return_value"]
                )
            elif tool == "frida_trace_class":
                return frida.trace_class(
                    args["class_name"],
                    include_args=args.get("include_args", True),
                    include_return=args.get("include_return", True),
                    include_backtrace=args.get("include_backtrace", False),
                )
            elif tool == "frida_memory_scan":
                return frida.memory_scan(args["pattern"], args.get("module_name"))
            elif tool == "frida_read_memory":
                return frida.read_memory(args["address"], args["size"])
            elif tool == "frida_write_memory":
                return frida.write_memory(args["address"], args["data"])
            elif tool == "frida_list_modules":
                return frida.enumerate_modules()
            elif tool == "frida_list_exports":
                return frida.enumerate_exports(args["module_name"])
            elif tool == "frida_get_messages":
                return frida.get_messages(
                    args.get("script_name"), args.get("limit", 50)
                )
            elif tool == "frida_intercept_crypto":
                return frida.intercept_crypto()
            elif tool == "frida_intercept_http":
                return frida.intercept_http()
            elif tool == "frida_intercept_intents":
                return frida.intercept_intents()
            elif tool == "frida_intercept_prefs":
                return frida.intercept_shared_prefs()
            elif tool == "frida_intercept_sqlite":
                return frida.intercept_sqlite()
            elif tool == "frida_intercept_files":
                return frida.intercept_file_io()
            elif tool == "frida_android_info":
                return frida.get_android_info()
            elif tool == "frida_find_instances":
                return frida.find_instances(args["class_name"])
            elif tool == "frida_call_method":
                a = json.loads(args["args"]) if args.get("args") else []
                return frida.call_method(args["class_name"], args["method_name"], a)
            elif tool == "frida_get_field":
                return frida.get_field_value(args["class_name"], args["field_name"])
            elif tool == "frida_set_field":
                return frida.set_field_value(
                    args["class_name"], args["field_name"], args["value"]
                )
            # ── New v4.0 Frida Tools ──
            elif tool == "frida_get_class_info":
                return frida.get_class_info(args["class_name"])
            elif tool == "frida_trace_native":
                return frida.trace_native_calls(
                    args["module_name"], args.get("function_pattern", "")
                )
            elif tool == "frida_list_imports":
                return frida.enumerate_imports(args["module_name"])
            elif tool == "frida_status":
                return frida.get_status()
            else:
                raise ValueError(f"Unknown frida tool: {tool}")

        # ── Bypass Tools ──
        elif tool.startswith("bypass_"):
            bypass = self._require("bypass")

            if tool == "bypass_all":
                return bypass.apply_all_bypasses()
            elif tool == "bypass_ssl":
                return bypass.bypass_ssl_pinning()
            elif tool == "bypass_root":
                return bypass.bypass_root_detection()
            elif tool == "bypass_emulator":
                return bypass.bypass_emulator_detection()
            elif tool == "bypass_frida":
                return bypass.bypass_frida_detection()
            elif tool == "bypass_integrity":
                return bypass.bypass_integrity_checks()
            elif tool == "bypass_scan":
                return bypass.scan_protections()
            elif tool == "bypass_auto":
                return bypass.scan_and_bypass_all()
            elif tool == "bypass_rootbeer":
                return bypass.bypass_rootbeer()
            elif tool == "bypass_gameguard":
                return bypass.bypass_gameguard()
            elif tool == "bypass_tencent":
                return bypass.bypass_tencent_protection()
            elif tool == "bypass_decompile_scan":
                return bypass.decompile_and_scan(
                    args["apk_path"], args.get("output_dir", "decompiled")
                )
            elif tool == "bypass_inject_universal":
                frida = self._require("frida")
                script_path = SCRIPTS_DIR / "universal_bypass.js"
                if script_path.exists():
                    return frida.inject_script_file(
                        str(script_path), "universal_bypass"
                    )
                return {"error": "universal_bypass.js not found"}
            # ── New v4.0 Bypass Tools ──
            elif tool == "bypass_status":
                return bypass.get_bypass_status()
            elif tool == "bypass_custom_class":
                return bypass.auto_bypass_class(args["class_name"])
            else:
                raise ValueError(f"Unknown bypass tool: {tool}")

        # ── Script Library ──
        elif tool.startswith("script_"):
            if tool == "script_load":
                frida = self._require("frida")
                script_name = args["script_name"]
                script_path = SCRIPTS_DIR / f"{script_name}.js"
                if not script_path.exists():
                    return {
                        "error": f"Script {script_name}.js not found at {script_path}"
                    }
                return frida.inject_script_file(str(script_path), script_name)
            elif tool == "script_list":
                return self._list_available_scripts()
            else:
                raise ValueError(f"Unknown script tool: {tool}")

        # ── LDConsole Tools ──
        elif tool.startswith("ld_"):
            ld = self._require("ldconsole")

            if tool == "ld_list_instances":
                return ld.list_instances()
            elif tool == "ld_create_instance":
                return ld.create_instance(args["name"])
            elif tool == "ld_launch":
                return ld.launch(args["name"])
            elif tool == "ld_quit":
                return ld.quit(args["name"])
            elif tool == "ld_reboot":
                return ld.reboot(args["name"])
            elif tool == "ld_modify_instance":
                return ld.modify_instance(
                    args["name"],
                    resolution=args.get("resolution"),
                    cpu=args.get("cpu"),
                    memory=args.get("memory"),
                    manufacturer=args.get("manufacturer"),
                    model=args.get("model"),
                    imei=args.get("imei"),
                    mac=args.get("mac"),
                )
            elif tool == "ld_set_location":
                return ld.set_location(
                    args["name"], args["latitude"], args["longitude"]
                )
            elif tool == "ld_install_app":
                return ld.install_app(args["name"], args["apk_path"])
            elif tool == "ld_backup":
                return ld.backup(args["name"], args["backup_path"])
            elif tool == "ld_restore":
                return ld.restore(args["name"], args["backup_path"])
            elif tool == "ld_clone":
                return ld.clone_instances(args["source"], args.get("count", 1))
            elif tool == "ld_device_profile":
                return ld.apply_device_profile(args["name"], args["profile"])
            elif tool == "ld_set_root":
                return ld.set_root(args["name"], args["enabled"])
            elif tool == "ld_shared_folder":
                return ld.set_shared_folder(
                    args["name"],
                    args["pc_path"],
                    args.get("android_path", "/sdcard/shared"),
                )
            # ── New v4.0 LD Tools ──
            elif tool == "ld_run_app":
                return ld.run_app(args["name"], args["package_name"])
            elif tool == "ld_kill_app":
                return ld.kill_app(args["name"], args["package_name"])
            elif tool == "ld_randomize_device":
                return ld.randomize_device_info(args["name"])
            elif tool == "ld_quit_all":
                return ld.quit_all()
            elif tool == "ld_instance_config":
                return ld.get_instance_config(args["name"])
            else:
                raise ValueError(f"Unknown ld tool: {tool}")

        # ── Workflow / Orchestrator ──
        elif tool.startswith("workflow_"):
            orch = self._require("orchestrator")

            if tool == "workflow_full_intercept":
                return orch.full_intercept(
                    package=args["package"],
                    instance=args.get("instance", "0"),
                    bypasses=args.get("bypasses"),
                    wait_time=args.get("wait_time", 5),
                    auto_analyze=True,
                )
            elif tool == "workflow_quick_attach":
                return orch.quick_attach(
                    package=args["package"],
                    bypasses=args.get("bypasses"),
                )
            elif tool == "workflow_launch_emulator":
                return orch.launch_emulator(args.get("instance", "0"))
            elif tool == "workflow_open_app":
                return orch.open_app(args["package"])
            elif tool == "workflow_intercept_all":
                return orch.start_interceptions(args.get("intercepts"))
            elif tool == "workflow_analyze":
                return orch.analyze()
            elif tool == "workflow_collect_data":
                return orch.collect_data()
            elif tool == "workflow_stop_all":
                return orch.stop_all(close_emulator=args.get("close_emulator", False))
            elif tool == "workflow_find_app":
                return orch.find_app(args["keyword"])
            elif tool == "workflow_save_report":
                path = orch.save_report(args.get("filepath"))
                return {"success": True, "filepath": path}
            elif tool == "workflow_status":
                return orch.get_state()
            else:
                raise ValueError(f"Unknown workflow tool: {tool}")

        # ── System ──
        elif tool == "status":
            return self._get_full_status()
        elif tool == "help":
            return [
                {"name": t["name"], "description": t["description"]} for t in self.tools
            ]

        else:
            raise ValueError(f"Unknown tool: {tool}")

    # ──────────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────────

    def _list_available_scripts(self) -> List[Dict]:
        scripts = []
        if SCRIPTS_DIR.exists():
            for f in sorted(SCRIPTS_DIR.glob("*.js")):
                # Read first line as description
                desc = ""
                try:
                    with open(f, "r", encoding="utf-8") as fh:
                        for line in fh:
                            line = line.strip()
                            if line.startswith("*") and "LEVIATHAN" in line:
                                desc = line.lstrip("* ").strip()
                                break
                except Exception:
                    pass
                scripts.append(
                    {
                        "name": f.stem,
                        "file": f.name,
                        "path": str(f),
                        "description": desc,
                        "size": f.stat().st_size,
                    }
                )
        return scripts

    def _get_full_status(self) -> Dict:
        status = {
            "server": {
                "name": SERVER_NAME,
                "version": VERSION,
                "running": self.running,
            },
            "components": {
                "adb": {"available": self.adb is not None},
                "frida": {"available": self.frida is not None},
                "ldconsole": {"available": self.ldconsole is not None},
                "bypass": {"available": self.bypass is not None},
            },
            "scripts": len(self._list_available_scripts()),
            "tools": len(self.tools),
        }
        if self.frida:
            try:
                status["components"]["frida"]["status"] = self.frida.get_status()
            except Exception:
                pass
        if self.bypass:
            try:
                status["components"]["bypass"][
                    "status"
                ] = self.bypass.get_bypass_status()
            except Exception:
                pass
        return status

    @staticmethod
    def _error(rid, code: int, message: str) -> Dict:
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "error": {"code": code, "message": message},
        }

    # ──────────────────────────────────────────────────────────
    # STDIO TRANSPORT
    # ──────────────────────────────────────────────────────────

    async def run_stdio(self):
        """Main loop - read JSON-RPC from stdin, write to stdout.

        Supports two framing modes:
          1. Content-Length header framing (MCP standard)
          2. Newline-delimited JSON fallback
        """
        logger.info(f"{SERVER_NAME} v{VERSION} starting on stdio...")
        logger.info(
            f"Tools: {len(self.tools)} | Scripts: {len(self._list_available_scripts())}"
        )

        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        # Configure stdout to binary for Content-Length framing
        if sys.platform == "win32":
            import msvcrt

            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)

        buffer = b""

        while self.running:
            try:
                chunk = await reader.read(4096)
                if not chunk:
                    break

                buffer += chunk

                # Process all complete messages in buffer
                while buffer:
                    request, buffer = self._parse_message(buffer)
                    if request is None:
                        break  # Need more data

                    response = await self.handle_request(request)
                    if response is not None:
                        self._write_response(response)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Stdio loop error: {e}", exc_info=True)
                buffer = b""

        logger.info("Server shutting down...")

    @staticmethod
    def _parse_message(buffer: bytes):
        """Parse a single JSON-RPC message from buffer.

        Tries Content-Length framing first, then newline-delimited JSON.
        Returns (parsed_message, remaining_buffer) or (None, buffer) if incomplete.
        """
        # Try Content-Length header framing
        header_end = buffer.find(b"\r\n\r\n")
        if header_end != -1:
            header_section = buffer[:header_end].decode("utf-8", errors="replace")
            content_length = None
            for line in header_section.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    try:
                        content_length = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass
            if content_length is not None:
                body_start = header_end + 4
                if len(buffer) >= body_start + content_length:
                    body = buffer[body_start : body_start + content_length]
                    remaining = buffer[body_start + content_length :]
                    try:
                        msg = json.loads(body.decode("utf-8"))
                        return msg, remaining
                    except json.JSONDecodeError:
                        return None, buffer[body_start + content_length :]
                return None, buffer  # Need more data

        # Fallback: newline-delimited JSON
        newline_idx = buffer.find(b"\n")
        if newline_idx != -1:
            line = buffer[:newline_idx].strip()
            remaining = buffer[newline_idx + 1 :]
            if line:
                try:
                    msg = json.loads(line.decode("utf-8", errors="replace"))
                    return msg, remaining
                except json.JSONDecodeError:
                    # Skip malformed line
                    return None, remaining
            return None, remaining

        # Try to parse buffer as complete JSON (no newline yet)
        try:
            msg = json.loads(buffer.decode("utf-8", errors="replace"))
            return msg, b""
        except json.JSONDecodeError:
            return None, buffer

    @staticmethod
    def _write_response(response: Dict):
        """Write response with Content-Length framing."""
        body = json.dumps(response).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
        sys.stdout.buffer.write(header + body)
        sys.stdout.buffer.flush()


# ╔══════════════════════════════════════════════════════════════════════╗
# ║                            MAIN                                     ║
# ╚══════════════════════════════════════════════════════════════════════╝


def main():
    """Entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="LEVIATHAN VS - LDPlayer MCP Server")
    parser.add_argument("--config", help="Path to config_ldplayer.json")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    server = MCPLDPlayerServer(config_path=args.config)
    asyncio.run(server.run_stdio())


if __name__ == "__main__":
    main()
