#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP NoxPlayer Server v1.0

    NoxPlayer emulator control MCP server.
    Uses Nox.exe CLI and ADB for full emulator management.
    JSON-RPC 2.0 over stdio with Content-Length framing.

    Tools:
        - nox_list_instances: List Nox instances
        - nox_launch: Launch instance
        - nox_stop: Stop instance
        - nox_stop_all: Stop all instances
        - nox_create: Create new instance
        - nox_clone: Clone instance
        - nox_remove: Remove instance
        - nox_install_apk: Install APK
        - nox_run_app: Launch app in emulator
        - nox_adb_connect: Connect ADB to Nox
        - nox_shell: Execute shell via ADB
        - nox_screenshot: Take screenshot
        - nox_input: Send input events (tap, swipe, text, keyevent)
        - nox_set_config: Set instance config (resolution, CPU, RAM, root)
        - nox_get_config: Get instance config
        - nox_list_apps: List installed apps
        - nox_pull: Pull file from emulator
        - nox_push: Push file to emulator
        - nox_gps: Set GPS coordinates
        - nox_rotate: Rotate screen
        - nox_root_toggle: Enable/disable root access
        - nox_macro: Execute macro/script file

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
logger = logging.getLogger("leviathan-nox-mcp")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-nox-server"


def _find_nox() -> Dict[str, str]:
    paths = {}
    candidates = [
        r"C:\Program Files\Nox\bin",
        r"C:\Program Files (x86)\Nox\bin",
        r"D:\Program Files\Nox\bin",
        r"C:\Program Files\Bignox\BigNoxVM\RT",
        r"D:\Nox\bin",
    ]
    for base in candidates:
        p = Path(base)
        if p.exists():
            nox = p / "Nox.exe"
            if nox.exists():
                paths["nox"] = str(nox)
            nox_console = p / "NoxConsole.exe"
            if nox_console.exists():
                paths["console"] = str(nox_console)
            adb = p / "nox_adb.exe"
            if adb.exists():
                paths["adb"] = str(adb)
            break
    if "console" not in paths:
        c = shutil.which("NoxConsole")
        if c:
            paths["console"] = c
    if "adb" not in paths:
        a = shutil.which("nox_adb") or shutil.which("adb")
        if a:
            paths["adb"] = a
        else:
            paths["adb"] = "adb"
    return paths


NOX_PATHS = _find_nox()
NOX_CONSOLE = NOX_PATHS.get("console", "NoxConsole")
NOX_ADB = NOX_PATHS.get("adb", "adb")
NOX_ADB_PORT = 62001


def _run_console(args: List[str], timeout: int = 60) -> Dict:
    cmd = [NOX_CONSOLE] + args
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
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Timeout after {timeout}s"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _run_adb(args: List[str], timeout: int = 30) -> Dict:
    cmd = [NOX_ADB] + args
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
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Timeout after {timeout}s"}
    except Exception as e:
        return {"success": False, "error": str(e)}


TOOLS = [
    {
        "name": "nox_list_instances",
        "description": "Lista todas as instancias NoxPlayer",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "nox_launch",
        "description": "Inicia instancia NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Nome da instancia (default: Nox)",
                }
            },
        },
    },
    {
        "name": "nox_stop",
        "description": "Para instancia NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Nome da instancia"}
            },
        },
    },
    {
        "name": "nox_stop_all",
        "description": "Para todas as instancias NoxPlayer",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "nox_create",
        "description": "Cria nova instancia NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Nome para a nova instancia"}
            },
            "required": ["name"],
        },
    },
    {
        "name": "nox_clone",
        "description": "Clona instancia existente",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "description": "Nome da instancia a clonar",
                },
                "name": {"type": "string", "description": "Nome do clone"},
            },
            "required": ["source", "name"],
        },
    },
    {
        "name": "nox_remove",
        "description": "Remove instancia NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    {
        "name": "nox_install_apk",
        "description": "Instala APK na instancia NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {"apk_path": {"type": "string"}, "name": {"type": "string"}},
            "required": ["apk_path"],
        },
    },
    {
        "name": "nox_run_app",
        "description": "Inicia app na instancia NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {"package": {"type": "string"}, "name": {"type": "string"}},
            "required": ["package"],
        },
    },
    {
        "name": "nox_adb_connect",
        "description": "Conecta ADB ao NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer",
                    "description": "Porta ADB (default: 62001)",
                },
                "name": {"type": "string"},
            },
        },
    },
    {
        "name": "nox_shell",
        "description": "Executa comando shell no NoxPlayer via ADB",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "port": {"type": "integer"},
                "timeout": {"type": "integer"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "nox_screenshot",
        "description": "Tira screenshot do NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {"output": {"type": "string"}, "port": {"type": "integer"}},
            "required": ["output"],
        },
    },
    {
        "name": "nox_input",
        "description": "Envia input para o NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["tap", "swipe", "text", "keyevent", "long_press"],
                },
                "args": {"type": "string"},
                "port": {"type": "integer"},
            },
            "required": ["action", "args"],
        },
    },
    {
        "name": "nox_set_config",
        "description": "Define configuracao da instancia (resolution, cpu, ram, root)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "key": {
                    "type": "string",
                    "description": "Chave: resolution, cpu, ram, root, fps, phone_model",
                },
                "value": {"type": "string"},
            },
            "required": ["key", "value"],
        },
    },
    {
        "name": "nox_get_config",
        "description": "Obtem configuracao da instancia",
        "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}},
    },
    {
        "name": "nox_list_apps",
        "description": "Lista apps instalados no NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {"port": {"type": "integer"}, "grep": {"type": "string"}},
        },
    },
    {
        "name": "nox_pull",
        "description": "Baixa arquivo do NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {
                "remote": {"type": "string"},
                "local": {"type": "string"},
                "port": {"type": "integer"},
            },
            "required": ["remote", "local"],
        },
    },
    {
        "name": "nox_push",
        "description": "Envia arquivo para o NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {
                "local": {"type": "string"},
                "remote": {"type": "string"},
                "port": {"type": "integer"},
            },
            "required": ["local", "remote"],
        },
    },
    {
        "name": "nox_gps",
        "description": "Define coordenadas GPS no NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {
                "latitude": {"type": "number"},
                "longitude": {"type": "number"},
                "port": {"type": "integer"},
            },
            "required": ["latitude", "longitude"],
        },
    },
    {
        "name": "nox_rotate",
        "description": "Rotaciona tela do NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {
                "orientation": {"type": "string", "enum": ["portrait", "landscape"]},
                "port": {"type": "integer"},
            },
            "required": ["orientation"],
        },
    },
    {
        "name": "nox_root_toggle",
        "description": "Ativa/desativa root no NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {
                "enable": {
                    "type": "boolean",
                    "description": "true=ativar root, false=desativar",
                },
                "name": {"type": "string"},
            },
            "required": ["enable"],
        },
    },
    {
        "name": "nox_macro",
        "description": "Executa arquivo de macro/script no NoxPlayer",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Nome da instancia"},
                "macro_file": {
                    "type": "string",
                    "description": "Caminho do arquivo de macro",
                },
            },
            "required": ["macro_file"],
        },
    },
]


async def dispatch_tool(name: str, args: Dict) -> str:
    nox_name = args.get("name", "Nox")
    port = args.get("port", NOX_ADB_PORT)
    device = f"127.0.0.1:{port}"

    if name == "nox_list_instances":
        r = _run_console(["list"])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "nox_launch":
        r = _run_console(["launch", "-name:" + nox_name])
        return (
            f"Launching NoxPlayer: {nox_name}" if r["success"] else r.get("error", "")
        )

    elif name == "nox_stop":
        r = _run_console(["quit", "-name:" + nox_name])
        return f"Stopping NoxPlayer: {nox_name}" if r["success"] else r.get("error", "")

    elif name == "nox_stop_all":
        r = _run_console(["quitall"])
        return "All NoxPlayer instances stopped" if r["success"] else r.get("error", "")

    elif name == "nox_create":
        r = _run_console(["add", "-name:" + args["name"]])
        return (
            f"Created instance: {args['name']}" if r["success"] else r.get("error", "")
        )

    elif name == "nox_clone":
        r = _run_console(["copy", "-name:" + args["source"], "-rename:" + args["name"]])
        return (
            f"Cloned {args['source']} -> {args['name']}"
            if r["success"]
            else r.get("error", "")
        )

    elif name == "nox_remove":
        r = _run_console(["remove", "-name:" + args["name"]])
        return (
            f"Removed instance: {args['name']}" if r["success"] else r.get("error", "")
        )

    elif name == "nox_install_apk":
        r = _run_console(
            ["installapp", "-name:" + nox_name, "-apk:" + args["apk_path"]], timeout=120
        )
        if not r["success"]:
            _run_adb(["connect", device])
            r = _run_adb(
                ["-s", device, "install", "-r", "-g", args["apk_path"]], timeout=120
            )
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "nox_run_app":
        r = _run_console(
            ["runapp", "-name:" + nox_name, "-packagename:" + args["package"]]
        )
        return f"Starting {args['package']}" if r["success"] else r.get("error", "")

    elif name == "nox_adb_connect":
        r = _run_adb(["connect", device])
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "nox_shell":
        _run_adb(["connect", device])
        timeout = args.get("timeout", 30)
        r = _run_adb(["-s", device, "shell", args["command"]], timeout=timeout)
        return (
            r["stdout"]
            if r["success"]
            else f"ERROR: {r.get('stderr', r.get('error', ''))}"
        )

    elif name == "nox_screenshot":
        _run_adb(["connect", device])
        remote = "/sdcard/screenshot.png"
        _run_adb(["-s", device, "shell", "screencap", "-p", remote])
        r = _run_adb(["-s", device, "pull", remote, args["output"]])
        _run_adb(["-s", device, "shell", "rm", remote])
        return (
            f"Screenshot saved to {args['output']}"
            if r["success"]
            else r.get("error", "")
        )

    elif name == "nox_input":
        _run_adb(["connect", device])
        action = args["action"]
        a = args["args"]
        cmd_map = {
            "tap": f"input tap {a}",
            "swipe": f"input swipe {a}",
            "text": f"input text '{a}'",
            "keyevent": f"input keyevent {a}",
        }
        if action == "long_press":
            parts = a.split()
            shell_cmd = f"input swipe {parts[0]} {parts[1]} {parts[0]} {parts[1]} 1500"
        else:
            shell_cmd = cmd_map.get(action, "")
        r = _run_adb(["-s", device, "shell", shell_cmd])
        return f"Input sent: {action} {a}"

    elif name == "nox_set_config":
        key = args["key"]
        value = args["value"]
        config_map = {
            "resolution": ["modify", "-name:" + nox_name, "-resolution:" + value],
            "cpu": ["modify", "-name:" + nox_name, "-cpu:" + value],
            "ram": ["modify", "-name:" + nox_name, "-memory:" + value],
            "root": ["modify", "-name:" + nox_name, "-root:" + value],
            "fps": ["modify", "-name:" + nox_name, "-fps:" + value],
            "phone_model": ["modify", "-name:" + nox_name, "-manufacturer:" + value],
        }
        cmd = config_map.get(key, ["modify", "-name:" + nox_name, f"-{key}:{value}"])
        r = _run_console(cmd)
        return f"Set {key}={value}" if r["success"] else r.get("error", "")

    elif name == "nox_get_config":
        r = _run_console(["list"])
        output = r["stdout"] if r["success"] else ""
        lines = [l for l in output.splitlines() if nox_name.lower() in l.lower()]
        return "\n".join(lines) if lines else f"Instance {nox_name} config not found"

    elif name == "nox_list_apps":
        _run_adb(["connect", device])
        r = _run_adb(["-s", device, "shell", "pm", "list", "packages", "-3"])
        output = r["stdout"]
        if args.get("grep"):
            output = "\n".join(
                l for l in output.splitlines() if args["grep"].lower() in l.lower()
            )
        return output if output else "No apps found"

    elif name == "nox_pull":
        _run_adb(["connect", device])
        r = _run_adb(["-s", device, "pull", args["remote"], args["local"]], timeout=120)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "nox_push":
        _run_adb(["connect", device])
        r = _run_adb(["-s", device, "push", args["local"], args["remote"]], timeout=120)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "nox_gps":
        _run_adb(["connect", device])
        r = _run_adb(
            [
                "-s",
                device,
                "emu",
                "geo",
                "fix",
                str(args["longitude"]),
                str(args["latitude"]),
            ]
        )
        return f"GPS set to {args['latitude']}, {args['longitude']}"

    elif name == "nox_rotate":
        _run_adb(["connect", device])
        rotation = "0" if args["orientation"] == "portrait" else "1"
        _run_adb(
            [
                "-s",
                device,
                "shell",
                "settings",
                "put",
                "system",
                "accelerometer_rotation",
                "0",
            ]
        )
        _run_adb(
            [
                "-s",
                device,
                "shell",
                "settings",
                "put",
                "system",
                "user_rotation",
                rotation,
            ]
        )
        return f"Rotated to {args['orientation']}"

    elif name == "nox_root_toggle":
        enable = "1" if args["enable"] else "0"
        r = _run_console(["modify", "-name:" + nox_name, "-root:" + enable])
        state = "enabled" if args["enable"] else "disabled"
        return f"Root {state} for {nox_name}" if r["success"] else r.get("error", "")

    elif name == "nox_macro":
        r = _run_console(
            ["macro", "-name:" + nox_name, "-filepath:" + args["macro_file"]]
        )
        return r["stdout"] if r["success"] else r.get("error", "")

    return f"Unknown tool: {name}"


class MCPServer:
    def __init__(self):
        self.running = True

    def _response(self, id, result):
        return {"jsonrpc": "2.0", "id": id, "result": result}

    def _error(self, id, code, msg):
        return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}}

    async def handle(self, req):
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
            try:
                result = await dispatch_tool(
                    params.get("name", ""), params.get("arguments", {})
                )
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
        elif method in ("resources/list", "prompts/list"):
            return self._response(rid, {method.split("/")[0]: []})
        elif method.startswith("notifications/"):
            return None
        return self._error(rid, -32601, f"Unknown method: {method}")

    async def run(self):
        if sys.platform == "win32":
            import msvcrt

            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(
            lambda: protocol, sys.stdin.buffer
        )
        logger.info(f"{SERVER_NAME} v{VERSION} started (NoxConsole: {NOX_CONSOLE})")
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


if __name__ == "__main__":
    asyncio.run(MCPServer().run())
