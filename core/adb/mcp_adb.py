#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP ADB Server v1.0

    Standalone ADB (Android Debug Bridge) MCP server.
    JSON-RPC 2.0 over stdio with Content-Length framing.

    Tools:
        - adb_devices: List connected devices
        - adb_connect: Connect to device via TCP/IP
        - adb_shell: Execute shell command on device
        - adb_install: Install APK on device
        - adb_uninstall: Uninstall package
        - adb_push: Push file to device
        - adb_pull: Pull file from device
        - adb_logcat: Capture logcat output with filters
        - adb_screencap: Take screenshot
        - adb_screenrecord: Record screen
        - adb_input: Send input events (tap, swipe, text, keyevent)
        - adb_pm_list: List packages with filters
        - adb_dumpsys: Dump system service info
        - adb_getprop: Get system property
        - adb_setprop: Set system property
        - adb_forward: Forward port
        - adb_reverse: Reverse port forward
        - adb_root: Restart ADB as root
        - adb_remount: Remount /system as read-write
        - adb_reboot: Reboot device
        - adb_backup: Backup app data
        - adb_start_activity: Start an activity via am start
        - adb_broadcast: Send broadcast intent
        - adb_kill_process: Kill a process by name or PID
        - adb_top: Show top processes (CPU/memory)
        - adb_netstat: Show network connections
        - adb_get_ip: Get device IP address
        - adb_wifi_connect: Connect ADB over WiFi
        - adb_get_apk_path: Get installed APK path
        - adb_extract_apk: Extract APK from device
        - adb_tcp_dump: Capture network traffic with tcpdump
        - adb_bugreport: Generate device bugreport
        - adb_disable_verity: Disable dm-verity
        - adb_sideload: Sideload OTA zip
        - adb_list_features: List device features
        - adb_memory_info: Get memory info (meminfo)
        - adb_battery_info: Get battery status
        - adb_disk_info: Get disk usage
        - adb_window_dump: Dump current window hierarchy
        - adb_start_service: Start a service via am startservice
        - adb_clear_data: Clear app data and cache

    Author: ThiagoFrag / LEVIATHAN VS
    Version: 1.0.0
================================================================================
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("leviathan-adb-mcp")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-adb-server"


# ── Locate ADB ──
def _find_adb() -> str:
    """Find ADB executable in common locations."""
    candidates = [
        shutil.which("adb"),
        r"C:\Users\Kishi\AppData\Local\Android\Sdk\platform-tools\adb.exe",
        r"C:\Android\platform-tools\adb.exe",
        r"C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe",
        r"C:\LDPlayer\LDPlayer9\adb.exe",
        r"C:\Program Files\BlueStacks_nxt\HD-Adb.exe",
        r"C:\Program Files\Microvirt\MEmu\adb.exe",
    ]
    for c in candidates:
        if c and Path(c).exists():
            return str(c)
    return "adb"  # fallback to PATH


ADB = _find_adb()


def _run_adb(args: List[str], device: str = "", timeout: int = 30) -> Dict:
    """Execute ADB command and return result."""
    cmd = [ADB]
    if device:
        cmd.extend(["-s", device])
    cmd.extend(args)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return {
            "success": proc.returncode == 0,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "command": " ".join(cmd),
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Timeout after {timeout}s",
            "command": " ".join(cmd),
        }
    except Exception as e:
        return {"success": False, "error": str(e), "command": " ".join(cmd)}


# ── Tool Definitions ──
TOOLS = [
    {
        "name": "adb_devices",
        "description": "Lista todos os dispositivos ADB conectados",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "adb_connect",
        "description": "Conecta a dispositivo via TCP/IP (host:port)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "host:port (ex: 127.0.0.1:5555)",
                }
            },
            "required": ["target"],
        },
    },
    {
        "name": "adb_shell",
        "description": "Executa comando shell no dispositivo Android",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Comando shell a executar",
                },
                "device": {
                    "type": "string",
                    "description": "Serial do device (opcional)",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout em segundos (default 30)",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "adb_install",
        "description": "Instala APK no dispositivo (-r para reinstalar, -g para grant permissions)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"},
                "device": {"type": "string"},
                "flags": {
                    "type": "string",
                    "description": "Flags extras (ex: -r -g -t)",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "adb_uninstall",
        "description": "Desinstala pacote do dispositivo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {
                    "type": "string",
                    "description": "Nome do pacote (ex: com.game.app)",
                },
                "device": {"type": "string"},
                "keep_data": {"type": "boolean", "description": "Manter dados (-k)"},
            },
            "required": ["package"],
        },
    },
    {
        "name": "adb_push",
        "description": "Envia arquivo para o dispositivo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "local": {"type": "string", "description": "Caminho local"},
                "remote": {"type": "string", "description": "Caminho no device"},
                "device": {"type": "string"},
            },
            "required": ["local", "remote"],
        },
    },
    {
        "name": "adb_pull",
        "description": "Baixa arquivo do dispositivo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "remote": {"type": "string", "description": "Caminho no device"},
                "local": {"type": "string", "description": "Caminho local"},
                "device": {"type": "string"},
            },
            "required": ["remote", "local"],
        },
    },
    {
        "name": "adb_logcat",
        "description": "Captura logcat com filtros. Use tags como 'ActivityManager:I *:S' ou grep patterns",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": "Filtro de logcat (ex: 'Unity:V *:S')",
                },
                "grep": {
                    "type": "string",
                    "description": "Grep pattern para filtrar output",
                },
                "lines": {
                    "type": "integer",
                    "description": "Numero de linhas (-t N), default 100",
                },
                "device": {"type": "string"},
                "timeout": {
                    "type": "integer",
                    "description": "Timeout em segundos (default 10)",
                },
            },
        },
    },
    {
        "name": "adb_screencap",
        "description": "Tira screenshot e salva localmente",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output": {
                    "type": "string",
                    "description": "Caminho local para salvar PNG",
                },
                "device": {"type": "string"},
            },
            "required": ["output"],
        },
    },
    {
        "name": "adb_input",
        "description": "Envia evento de input (tap, swipe, text, keyevent)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["tap", "swipe", "text", "keyevent", "long_press"],
                    "description": "Tipo de input",
                },
                "args": {
                    "type": "string",
                    "description": "Argumentos: tap='x y', swipe='x1 y1 x2 y2 [duration]', text='string', keyevent='KEYCODE_HOME'",
                },
                "device": {"type": "string"},
            },
            "required": ["action", "args"],
        },
    },
    {
        "name": "adb_pm_list",
        "description": "Lista pacotes instalados com filtros",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": "Filtro: -3 (third-party), -s (system), -d (disabled)",
                },
                "grep": {"type": "string", "description": "Filtro por nome"},
                "device": {"type": "string"},
            },
        },
    },
    {
        "name": "adb_dumpsys",
        "description": "Dump info de servico do sistema (activity, meminfo, battery, window, etc)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Servico: activity, meminfo, battery, window, package, etc",
                },
                "args": {"type": "string", "description": "Argumentos adicionais"},
                "device": {"type": "string"},
            },
            "required": ["service"],
        },
    },
    {
        "name": "adb_getprop",
        "description": "Obtem propriedade do sistema Android",
        "inputSchema": {
            "type": "object",
            "properties": {
                "property": {
                    "type": "string",
                    "description": "Nome da propriedade (ex: ro.build.version.sdk)",
                },
                "device": {"type": "string"},
            },
            "required": ["property"],
        },
    },
    {
        "name": "adb_setprop",
        "description": "Define propriedade do sistema (requer root)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "property": {"type": "string"},
                "value": {"type": "string"},
                "device": {"type": "string"},
            },
            "required": ["property", "value"],
        },
    },
    {
        "name": "adb_forward",
        "description": "Forward de porta: PC -> Device",
        "inputSchema": {
            "type": "object",
            "properties": {
                "local": {
                    "type": "string",
                    "description": "Porta local (ex: tcp:8080)",
                },
                "remote": {
                    "type": "string",
                    "description": "Porta remota (ex: tcp:8080)",
                },
                "device": {"type": "string"},
            },
            "required": ["local", "remote"],
        },
    },
    {
        "name": "adb_reverse",
        "description": "Reverse forward: Device -> PC",
        "inputSchema": {
            "type": "object",
            "properties": {
                "remote": {"type": "string"},
                "local": {"type": "string"},
                "device": {"type": "string"},
            },
            "required": ["remote", "local"],
        },
    },
    {
        "name": "adb_root",
        "description": "Reinicia ADB daemon como root",
        "inputSchema": {"type": "object", "properties": {"device": {"type": "string"}}},
    },
    {
        "name": "adb_remount",
        "description": "Remonta /system como read-write (requer root)",
        "inputSchema": {"type": "object", "properties": {"device": {"type": "string"}}},
    },
    {
        "name": "adb_reboot",
        "description": "Reinicia dispositivo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["normal", "recovery", "bootloader", "sideload"],
                    "description": "Modo de reboot",
                },
                "device": {"type": "string"},
            },
        },
    },
    {
        "name": "adb_start_activity",
        "description": "Inicia uma activity via am start",
        "inputSchema": {
            "type": "object",
            "properties": {
                "intent": {
                    "type": "string",
                    "description": "Intent completo (ex: com.app/.MainActivity ou -a android.intent.action.VIEW -d http://url)",
                },
                "device": {"type": "string"},
            },
            "required": ["intent"],
        },
    },
    {
        "name": "adb_broadcast",
        "description": "Envia broadcast intent",
        "inputSchema": {
            "type": "object",
            "properties": {
                "intent": {"type": "string", "description": "Intent do broadcast"},
                "device": {"type": "string"},
            },
            "required": ["intent"],
        },
    },
    {
        "name": "adb_kill_process",
        "description": "Mata processo por nome ou PID",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Nome do pacote ou PID"},
                "force": {"type": "boolean", "description": "Force kill (-9)"},
                "device": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "adb_top",
        "description": "Mostra top processos (CPU/memoria)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lines": {
                    "type": "integer",
                    "description": "Numero de processos (default 20)",
                },
                "device": {"type": "string"},
            },
        },
    },
    {
        "name": "adb_netstat",
        "description": "Mostra conexoes de rede do dispositivo",
        "inputSchema": {"type": "object", "properties": {"device": {"type": "string"}}},
    },
    {
        "name": "adb_get_ip",
        "description": "Obtem IP do dispositivo",
        "inputSchema": {"type": "object", "properties": {"device": {"type": "string"}}},
    },
    {
        "name": "adb_wifi_connect",
        "description": "Conecta ADB via WiFi (device deve estar conectado via USB primeiro)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "description": "Porta TCP (default 5555)"},
                "device": {"type": "string"},
            },
        },
    },
    {
        "name": "adb_backup",
        "description": "Backup de dados de app",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "Pacote para backup"},
                "output": {"type": "string", "description": "Arquivo de saida .ab"},
                "device": {"type": "string"},
            },
            "required": ["package", "output"],
        },
    },
    {
        "name": "adb_screenrecord",
        "description": "Grava tela do dispositivo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "duration": {
                    "type": "integer",
                    "description": "Duracao em segundos (max 180)",
                },
                "output": {
                    "type": "string",
                    "description": "Caminho local para salvar",
                },
                "device": {"type": "string"},
            },
            "required": ["output"],
        },
    },
    {
        "name": "adb_get_apk_path",
        "description": "Obtem caminho do APK instalado de um pacote",
        "inputSchema": {
            "type": "object",
            "properties": {"package": {"type": "string"}, "device": {"type": "string"}},
            "required": ["package"],
        },
    },
    {
        "name": "adb_extract_apk",
        "description": "Extrai APK do dispositivo para local",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string"},
                "output": {
                    "type": "string",
                    "description": "Caminho local para salvar APK",
                },
                "device": {"type": "string"},
            },
            "required": ["package", "output"],
        },
    },
    {
        "name": "adb_tcp_dump",
        "description": "Captura trafego de rede com tcpdump (requer root)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Interface (default: any)",
                },
                "output": {"type": "string", "description": "Arquivo .pcap no device"},
                "filter": {
                    "type": "string",
                    "description": "BPF filter (ex: 'port 80')",
                },
                "count": {"type": "integer", "description": "Numero de pacotes"},
                "device": {"type": "string"},
            },
            "required": ["output"],
        },
    },
    {
        "name": "adb_bugreport",
        "description": "Gera bugreport completo do dispositivo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output": {
                    "type": "string",
                    "description": "Caminho local para salvar bugreport",
                },
                "device": {"type": "string"},
            },
            "required": ["output"],
        },
    },
    {
        "name": "adb_disable_verity",
        "description": "Desativa dm-verity (requer root + reboot)",
        "inputSchema": {"type": "object", "properties": {"device": {"type": "string"}}},
    },
    {
        "name": "adb_sideload",
        "description": "Sideload OTA zip (device em recovery)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "zip_path": {"type": "string", "description": "Caminho do zip OTA"},
                "device": {"type": "string"},
            },
            "required": ["zip_path"],
        },
    },
    {
        "name": "adb_list_features",
        "description": "Lista features do dispositivo (pm list features)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "grep": {"type": "string", "description": "Filtro"},
                "device": {"type": "string"},
            },
        },
    },
    {
        "name": "adb_memory_info",
        "description": "Obtem informacoes de memoria do dispositivo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {
                    "type": "string",
                    "description": "Pacote especifico (opcional)",
                },
                "device": {"type": "string"},
            },
        },
    },
    {
        "name": "adb_battery_info",
        "description": "Obtem status da bateria (level, status, health, temp)",
        "inputSchema": {"type": "object", "properties": {"device": {"type": "string"}}},
    },
    {
        "name": "adb_disk_info",
        "description": "Obtem uso de disco do dispositivo",
        "inputSchema": {"type": "object", "properties": {"device": {"type": "string"}}},
    },
    {
        "name": "adb_window_dump",
        "description": "Dump da hierarquia de janelas (UI automator dump)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output": {"type": "string", "description": "Caminho local para XML"},
                "device": {"type": "string"},
            },
            "required": ["output"],
        },
    },
    {
        "name": "adb_start_service",
        "description": "Inicia um service Android via am startservice",
        "inputSchema": {
            "type": "object",
            "properties": {
                "intent": {"type": "string", "description": "Intent do service"},
                "device": {"type": "string"},
            },
            "required": ["intent"],
        },
    },
    {
        "name": "adb_clear_data",
        "description": "Limpa dados e cache de um app",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "Nome do pacote"},
                "device": {"type": "string"},
            },
            "required": ["package"],
        },
    },
]


async def dispatch_tool(name: str, args: Dict) -> str:
    """Dispatch tool call to appropriate handler."""
    device = args.get("device", "")

    if name == "adb_devices":
        r = _run_adb(["devices", "-l"])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "adb_connect":
        r = _run_adb(["connect", args["target"]])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "adb_shell":
        timeout = args.get("timeout", 30)
        r = _run_adb(["shell", args["command"]], device=device, timeout=timeout)
        return (
            r["stdout"]
            if r["success"]
            else f"ERROR: {r.get('stderr', r.get('error', ''))}\nSTDOUT: {r.get('stdout', '')}"
        )

    elif name == "adb_install":
        cmd = ["install"]
        if args.get("flags"):
            cmd.extend(args["flags"].split())
        else:
            cmd.extend(["-r", "-g"])
        cmd.append(args["apk_path"])
        r = _run_adb(cmd, device=device, timeout=120)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "adb_uninstall":
        cmd = ["uninstall"]
        if args.get("keep_data"):
            cmd.append("-k")
        cmd.append(args["package"])
        r = _run_adb(cmd, device=device)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "adb_push":
        r = _run_adb(
            ["push", args["local"], args["remote"]], device=device, timeout=120
        )
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "adb_pull":
        r = _run_adb(
            ["pull", args["remote"], args["local"]], device=device, timeout=120
        )
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "adb_logcat":
        cmd = ["logcat"]
        lines = args.get("lines", 100)
        cmd.extend(["-t", str(lines)])
        if args.get("filter"):
            cmd.extend(args["filter"].split())
        timeout = args.get("timeout", 10)
        r = _run_adb(cmd, device=device, timeout=timeout)
        output = r["stdout"]
        if args.get("grep"):
            output = "\n".join(
                l for l in output.splitlines() if args["grep"].lower() in l.lower()
            )
        return output if output else "(no matching logs)"

    elif name == "adb_screencap":
        remote = "/sdcard/leviathan_screenshot.png"
        _run_adb(["shell", "screencap", "-p", remote], device=device)
        r = _run_adb(["pull", remote, args["output"]], device=device)
        _run_adb(["shell", "rm", remote], device=device)
        return (
            f"Screenshot salvo em {args['output']}"
            if r["success"]
            else r.get("error", "")
        )

    elif name == "adb_input":
        action = args["action"]
        a = args["args"]
        if action == "tap":
            cmd = f"input tap {a}"
        elif action == "swipe":
            cmd = f"input swipe {a}"
        elif action == "text":
            cmd = f"input text '{a}'"
        elif action == "keyevent":
            cmd = f"input keyevent {a}"
        elif action == "long_press":
            parts = a.split()
            cmd = f"input swipe {parts[0]} {parts[1]} {parts[0]} {parts[1]} 1500"
        else:
            return f"Unknown action: {action}"
        r = _run_adb(["shell", cmd], device=device)
        return f"Input sent: {action} {a}" if r["success"] else r.get("error", "")

    elif name == "adb_pm_list":
        cmd = ["shell", "pm", "list", "packages"]
        if args.get("filter"):
            cmd.extend(args["filter"].split())
        r = _run_adb(cmd, device=device)
        output = r["stdout"]
        if args.get("grep"):
            output = "\n".join(
                l for l in output.splitlines() if args["grep"].lower() in l.lower()
            )
        return output if output else "(no packages found)"

    elif name == "adb_dumpsys":
        cmd = ["shell", "dumpsys", args["service"]]
        if args.get("args"):
            cmd.extend(args["args"].split())
        r = _run_adb(cmd, device=device, timeout=30)
        out = r["stdout"]
        return out[:50000] if len(out) > 50000 else out

    elif name == "adb_getprop":
        r = _run_adb(["shell", "getprop", args["property"]], device=device)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "adb_setprop":
        r = _run_adb(
            ["shell", "setprop", args["property"], args["value"]], device=device
        )
        return (
            f"Set {args['property']}={args['value']}"
            if r["success"]
            else r.get("error", "")
        )

    elif name == "adb_forward":
        r = _run_adb(["forward", args["local"], args["remote"]], device=device)
        return (
            f"Forward {args['local']} -> {args['remote']}"
            if r["success"]
            else r.get("error", "")
        )

    elif name == "adb_reverse":
        r = _run_adb(["reverse", args["remote"], args["local"]], device=device)
        return (
            f"Reverse {args['remote']} -> {args['local']}"
            if r["success"]
            else r.get("error", "")
        )

    elif name == "adb_root":
        r = _run_adb(["root"], device=device)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "adb_remount":
        r = _run_adb(["remount"], device=device)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "adb_reboot":
        mode = args.get("mode", "normal")
        cmd = ["reboot"] if mode == "normal" else ["reboot", mode]
        r = _run_adb(cmd, device=device)
        return f"Rebooting in {mode} mode" if r["success"] else r.get("error", "")

    elif name == "adb_start_activity":
        r = _run_adb(["shell", "am", "start"] + args["intent"].split(), device=device)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "adb_broadcast":
        r = _run_adb(
            ["shell", "am", "broadcast"] + args["intent"].split(), device=device
        )
        return r["stdout"]

    elif name == "adb_kill_process":
        target = args["target"]
        if args.get("force"):
            r = _run_adb(["shell", "kill", "-9", target], device=device)
        else:
            r = _run_adb(["shell", "am", "force-stop", target], device=device)
        return f"Killed {target}" if r["success"] else r.get("error", "")

    elif name == "adb_top":
        lines = args.get("lines", 20)
        r = _run_adb(["shell", "top", "-n", "1", "-b"], device=device, timeout=15)
        out = r["stdout"].splitlines()
        return "\n".join(out[: lines + 5])

    elif name == "adb_netstat":
        r = _run_adb(["shell", "netstat", "-tlnp"], device=device)
        return (
            r["stdout"]
            if r["success"]
            else _run_adb(["shell", "ss", "-tlnp"], device=device)["stdout"]
        )

    elif name == "adb_get_ip":
        r = _run_adb(["shell", "ip", "addr", "show", "wlan0"], device=device)
        if r["success"]:
            for line in r["stdout"].splitlines():
                if "inet " in line:
                    return line.strip().split()[1].split("/")[0]
        return r["stdout"]

    elif name == "adb_wifi_connect":
        port = args.get("port", 5555)
        _run_adb(["tcpip", str(port)], device=device)
        ip_r = _run_adb(["shell", "ip", "route"], device=device)
        ip = ""
        for line in ip_r["stdout"].splitlines():
            if "src" in line:
                parts = line.split()
                idx = parts.index("src") + 1
                ip = parts[idx]
                break
        if ip:
            r = _run_adb(["connect", f"{ip}:{port}"])
            return f"Connected to {ip}:{port}" if r["success"] else r.get("error", "")
        return "Could not determine device IP"

    elif name == "adb_backup":
        r = _run_adb(
            ["backup", "-f", args["output"], "-apk", args["package"]],
            device=device,
            timeout=300,
        )
        return (
            f"Backup saved to {args['output']}" if r["success"] else r.get("error", "")
        )

    elif name == "adb_screenrecord":
        duration = min(args.get("duration", 30), 180)
        remote = "/sdcard/leviathan_record.mp4"
        _run_adb(
            ["shell", "screenrecord", "--time-limit", str(duration), remote],
            device=device,
            timeout=duration + 10,
        )
        r = _run_adb(["pull", remote, args["output"]], device=device)
        _run_adb(["shell", "rm", remote], device=device)
        return (
            f"Recording saved to {args['output']}"
            if r["success"]
            else r.get("error", "")
        )

    elif name == "adb_get_apk_path":
        r = _run_adb(["shell", "pm", "path", args["package"]], device=device)
        return (
            r["stdout"].replace("package:", "") if r["success"] else r.get("error", "")
        )

    elif name == "adb_extract_apk":
        path_r = _run_adb(["shell", "pm", "path", args["package"]], device=device)
        if path_r["success"]:
            remote_path = path_r["stdout"].replace("package:", "").strip()
            r = _run_adb(
                ["pull", remote_path, args["output"]], device=device, timeout=120
            )
            return (
                f"APK extracted to {args['output']}"
                if r["success"]
                else r.get("error", "")
            )
        return f"Package not found: {args['package']}"

    elif name == "adb_tcp_dump":
        iface = args.get("interface", "any")
        count = args.get("count", 1000)
        cmd = f"tcpdump -i {iface} -c {count} -w {args['output']}"
        if args.get("filter"):
            cmd += f" {args['filter']}"
        r = _run_adb(["shell", cmd], device=device, timeout=60)
        return (
            f"Capture saved to {args['output']}"
            if r["success"]
            else r.get("error", r.get("stderr", ""))
        )

    elif name == "adb_bugreport":
        r = _run_adb(["bugreport", args["output"]], device=device, timeout=180)
        return (
            f"Bugreport saved to {args['output']}"
            if r["success"]
            else r.get("error", r.get("stderr", ""))
        )

    elif name == "adb_disable_verity":
        r = _run_adb(["disable-verity"], device=device)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "adb_sideload":
        r = _run_adb(["sideload", args["zip_path"]], device=device, timeout=600)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "adb_list_features":
        r = _run_adb(["shell", "pm", "list", "features"], device=device)
        out = r["stdout"]
        if args.get("grep"):
            out = "\n".join(
                l for l in out.splitlines() if args["grep"].lower() in l.lower()
            )
        return out if out else "No features found"

    elif name == "adb_memory_info":
        if args.get("package"):
            r = _run_adb(
                ["shell", "dumpsys", "meminfo", args["package"]],
                device=device,
                timeout=30,
            )
        else:
            r = _run_adb(["shell", "cat", "/proc/meminfo"], device=device)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "adb_battery_info":
        r = _run_adb(["shell", "dumpsys", "battery"], device=device)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "adb_disk_info":
        r = _run_adb(["shell", "df", "-h"], device=device)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "adb_window_dump":
        remote = "/sdcard/window_dump.xml"
        _run_adb(["shell", "uiautomator", "dump", remote], device=device, timeout=30)
        r = _run_adb(["pull", remote, args["output"]], device=device)
        _run_adb(["shell", "rm", remote], device=device)
        return (
            f"Window dump saved to {args['output']}"
            if r["success"]
            else r.get("error", r.get("stderr", ""))
        )

    elif name == "adb_start_service":
        r = _run_adb(
            ["shell", "am", "startservice"] + args["intent"].split(), device=device
        )
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "adb_clear_data":
        r = _run_adb(["shell", "pm", "clear", args["package"]], device=device)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    return f"Unknown tool: {name}"


# ── MCP Server ──
class MCPServer:
    def __init__(self):
        self.running = True

    def _response(self, id: Any, result: Any) -> Dict:
        return {"jsonrpc": "2.0", "id": id, "result": result}

    def _error(self, id: Any, code: int, msg: str) -> Dict:
        return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}}

    async def handle(self, req: Dict) -> Optional[Dict]:
        method = req.get("method", "")
        params = req.get("params", {})
        rid = req.get("id")

        if method == "initialize":
            return self._response(
                rid,
                {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": SERVER_NAME, "version": VERSION},
                    "capabilities": {"tools": {"listChanged": False}},
                },
            )
        elif method == "initialized":
            return None
        elif method == "shutdown":
            self.running = False
            return self._response(rid, None)
        elif method == "tools/list":
            return self._response(rid, {"tools": TOOLS})
        elif method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments", {})
            try:
                result = await dispatch_tool(name, args)
                return self._response(
                    rid, {"content": [{"type": "text", "text": str(result)}]}
                )
            except Exception as e:
                return self._response(
                    rid,
                    {
                        "content": [{"type": "text", "text": f"ERROR: {e}"}],
                        "isError": True,
                    },
                )
        elif method == "resources/list":
            return self._response(rid, {"resources": []})
        elif method == "prompts/list":
            return self._response(rid, {"prompts": []})
        elif method.startswith("notifications/"):
            return None
        else:
            return self._error(rid, -32601, f"Unknown method: {method}")

    async def run(self):
        if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
            import msvcrt

            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)

        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(
            lambda: protocol, sys.stdin.buffer
        )

        logger.info(f"{SERVER_NAME} v{VERSION} started (ADB: {ADB})")

        buf = b""
        while self.running:
            try:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buf += chunk

                while True:
                    if b"Content-Length:" not in buf:
                        break
                    header_end = buf.find(b"\r\n\r\n")
                    if header_end == -1:
                        break
                    header = buf[:header_end].decode("utf-8")
                    length = 0
                    for line in header.split("\r\n"):
                        if line.startswith("Content-Length:"):
                            length = int(line.split(":")[1].strip())
                    body_start = header_end + 4
                    if len(buf) < body_start + length:
                        break
                    body = buf[body_start : body_start + length].decode("utf-8")
                    buf = buf[body_start + length :]

                    req = json.loads(body)
                    resp = await self.handle(req)
                    if resp:
                        data = json.dumps(resp).encode("utf-8")
                        frame = f"Content-Length: {len(data)}\r\n\r\n".encode("utf-8")
                        sys.stdout.buffer.write(frame + data)
                        sys.stdout.buffer.flush()
            except Exception as e:
                logger.error(f"Error: {e}")
                break

        logger.info("Server shutdown")


if __name__ == "__main__":
    asyncio.run(MCPServer().run())
