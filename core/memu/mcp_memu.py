#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP MEmu Server v1.0

    MEmu emulator control MCP server.
    Uses memuc.exe CLI for full emulator management.
    JSON-RPC 2.0 over stdio with Content-Length framing.

    Tools:
        - memu_list_instances: List MEmu instances
        - memu_create: Create new instance
        - memu_start: Start instance
        - memu_stop: Stop instance
        - memu_install_apk: Install APK
        - memu_run_app: Launch app
        - memu_adb_connect: Connect ADB
        - memu_shell: Execute shell command
        - memu_screenshot: Take screenshot
        - memu_input: Send input events
        - memu_set_config: Set instance config
        - memu_get_config: Get instance config
        - memu_clone: Clone instance
        - memu_import_apk: Import APK into instance
        - memu_list_apps: List installed apps
        - memu_pull: Pull file from emulator
        - memu_push: Push file to emulator
        - memu_gps: Set GPS location
        - memu_rotate: Rotate screen

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
logger = logging.getLogger("leviathan-memu-mcp")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-memu-server"


def _find_memuc() -> str:
    candidates = [
        shutil.which("memuc"),
        r"C:\Program Files\Microvirt\MEmu\memuc.exe",
        r"C:\Program Files (x86)\Microvirt\MEmu\memuc.exe",
        r"D:\Program Files\Microvirt\MEmu\memuc.exe",
    ]
    for c in candidates:
        if c and Path(c).exists():
            return str(c)
    return "memuc"


def _find_memu_adb() -> str:
    candidates = [
        r"C:\Program Files\Microvirt\MEmu\adb.exe",
        r"C:\Program Files (x86)\Microvirt\MEmu\adb.exe",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    adb = shutil.which("adb")
    return adb if adb else "adb"


MEMUC = _find_memuc()
MEMU_ADB = _find_memu_adb()
MEMU_ADB_PORT = 21503  # Default MEmu ADB port


def _run_memuc(args: List[str], timeout: int = 60) -> Dict:
    cmd = [MEMUC] + args
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
    cmd = [MEMU_ADB] + args
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
        "name": "memu_list_instances",
        "description": "Lista todas as instancias MEmu",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "memu_create",
        "description": "Cria nova instancia MEmu",
        "inputSchema": {
            "type": "object",
            "properties": {
                "version": {
                    "type": "string",
                    "description": "Versao Android: 71 (7.1), 51 (5.1), 44 (4.4)",
                }
            },
        },
    },
    {
        "name": "memu_start",
        "description": "Inicia instancia MEmu",
        "inputSchema": {
            "type": "object",
            "properties": {
                "index": {
                    "type": "integer",
                    "description": "Index da instancia (default 0)",
                }
            },
        },
    },
    {
        "name": "memu_stop",
        "description": "Para instancia MEmu",
        "inputSchema": {"type": "object", "properties": {"index": {"type": "integer"}}},
    },
    {
        "name": "memu_install_apk",
        "description": "Instala APK na instancia MEmu",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "index": {"type": "integer"},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "memu_run_app",
        "description": "Inicia app na instancia MEmu",
        "inputSchema": {
            "type": "object",
            "properties": {"package": {"type": "string"}, "index": {"type": "integer"}},
            "required": ["package"],
        },
    },
    {
        "name": "memu_adb_connect",
        "description": "Conecta ADB ao MEmu",
        "inputSchema": {
            "type": "object",
            "properties": {"index": {"type": "integer"}, "port": {"type": "integer"}},
        },
    },
    {
        "name": "memu_shell",
        "description": "Executa comando shell no MEmu via ADB",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "index": {"type": "integer"},
                "timeout": {"type": "integer"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "memu_screenshot",
        "description": "Tira screenshot do MEmu",
        "inputSchema": {
            "type": "object",
            "properties": {"output": {"type": "string"}, "index": {"type": "integer"}},
            "required": ["output"],
        },
    },
    {
        "name": "memu_input",
        "description": "Envia input para o MEmu",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["tap", "swipe", "text", "keyevent"],
                },
                "args": {"type": "string"},
                "index": {"type": "integer"},
            },
            "required": ["action", "args"],
        },
    },
    {
        "name": "memu_set_config",
        "description": "Define configuracao da instancia (cpus, memory, resolution)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "index": {"type": "integer"},
                "key": {
                    "type": "string",
                    "description": "Chave: cpus, memory, resolution, etc",
                },
                "value": {"type": "string"},
            },
            "required": ["key", "value"],
        },
    },
    {
        "name": "memu_get_config",
        "description": "Obtem configuracao da instancia",
        "inputSchema": {
            "type": "object",
            "properties": {
                "index": {"type": "integer"},
                "key": {
                    "type": "string",
                    "description": "Chave: cpus, memory, resolution, etc",
                },
            },
            "required": ["key"],
        },
    },
    {
        "name": "memu_clone",
        "description": "Clona instancia MEmu",
        "inputSchema": {
            "type": "object",
            "properties": {
                "index": {
                    "type": "integer",
                    "description": "Index da instancia a clonar",
                }
            },
        },
    },
    {
        "name": "memu_list_apps",
        "description": "Lista apps instalados no MEmu",
        "inputSchema": {
            "type": "object",
            "properties": {"index": {"type": "integer"}, "grep": {"type": "string"}},
        },
    },
    {
        "name": "memu_pull",
        "description": "Baixa arquivo do MEmu",
        "inputSchema": {
            "type": "object",
            "properties": {
                "remote": {"type": "string"},
                "local": {"type": "string"},
                "index": {"type": "integer"},
            },
            "required": ["remote", "local"],
        },
    },
    {
        "name": "memu_push",
        "description": "Envia arquivo para o MEmu",
        "inputSchema": {
            "type": "object",
            "properties": {
                "local": {"type": "string"},
                "remote": {"type": "string"},
                "index": {"type": "integer"},
            },
            "required": ["local", "remote"],
        },
    },
    {
        "name": "memu_gps",
        "description": "Define coordenadas GPS no MEmu",
        "inputSchema": {
            "type": "object",
            "properties": {
                "latitude": {"type": "number"},
                "longitude": {"type": "number"},
                "index": {"type": "integer"},
            },
            "required": ["latitude", "longitude"],
        },
    },
    {
        "name": "memu_rotate",
        "description": "Rotaciona tela do MEmu (portrait/landscape)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "orientation": {
                    "type": "string",
                    "enum": ["portrait", "landscape"],
                    "description": "Orientacao",
                },
                "index": {"type": "integer"},
            },
            "required": ["orientation"],
        },
    },
    {
        "name": "memu_import_apk",
        "description": "Importa APK para instancia MEmu (drag-and-drop install)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "index": {"type": "integer"},
            },
            "required": ["apk_path"],
        },
    },
]


async def dispatch_tool(name: str, args: Dict) -> str:
    index = args.get("index", 0)
    port = args.get("port", MEMU_ADB_PORT + (index * 10))
    device = f"127.0.0.1:{port}"

    if name == "memu_list_instances":
        r = _run_memuc(["listvms"])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "memu_create":
        version = args.get("version", "71")
        r = _run_memuc(["create", version])
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "memu_start":
        r = _run_memuc(["start", "-i", str(index)])
        return f"Starting MEmu instance {index}" if r["success"] else r.get("error", "")

    elif name == "memu_stop":
        r = _run_memuc(["stop", "-i", str(index)])
        return f"Stopping MEmu instance {index}" if r["success"] else r.get("error", "")

    elif name == "memu_install_apk":
        r = _run_memuc(["installapp", "-i", str(index), args["apk_path"]], timeout=120)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "memu_run_app":
        r = _run_memuc(["startapp", "-i", str(index), args["package"]])
        return f"Starting {args['package']}" if r["success"] else r.get("error", "")

    elif name == "memu_adb_connect":
        r = _run_adb(["connect", device])
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "memu_shell":
        _run_adb(["connect", device])
        timeout = args.get("timeout", 30)
        r = _run_memuc(
            ["execcmd", "-i", str(index), f"shell {args['command']}"], timeout=timeout
        )
        if not r["success"]:
            r = _run_adb(["-s", device, "shell", args["command"]], timeout=timeout)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "memu_screenshot":
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

    elif name == "memu_input":
        _run_adb(["connect", device])
        action = args["action"]
        a = args["args"]
        cmd_map = {
            "tap": f"input tap {a}",
            "swipe": f"input swipe {a}",
            "text": f"input text '{a}'",
            "keyevent": f"input keyevent {a}",
        }
        r = _run_adb(["-s", device, "shell", cmd_map.get(action, "")])
        return f"Input sent: {action} {a}"

    elif name == "memu_set_config":
        r = _run_memuc(["setconfigex", "-i", str(index), args["key"], args["value"]])
        return (
            f"Set {args['key']}={args['value']}" if r["success"] else r.get("error", "")
        )

    elif name == "memu_get_config":
        r = _run_memuc(["getconfigex", "-i", str(index), args["key"]])
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "memu_clone":
        r = _run_memuc(["clone", "-i", str(index)])
        return f"Cloned instance {index}" if r["success"] else r.get("error", "")

    elif name == "memu_list_apps":
        _run_adb(["connect", device])
        r = _run_adb(["-s", device, "shell", "pm", "list", "packages", "-3"])
        output = r["stdout"]
        if args.get("grep"):
            output = "\n".join(
                l for l in output.splitlines() if args["grep"].lower() in l.lower()
            )
        return output if output else "No apps found"

    elif name == "memu_pull":
        _run_adb(["connect", device])
        r = _run_adb(["-s", device, "pull", args["remote"], args["local"]], timeout=120)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "memu_push":
        _run_adb(["connect", device])
        r = _run_adb(["-s", device, "push", args["local"], args["remote"]], timeout=120)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "memu_gps":
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

    elif name == "memu_rotate":
        _run_adb(["connect", device])
        orientation = args["orientation"]
        rotation = "0" if orientation == "portrait" else "1"
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
        r = _run_adb(
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
        return f"MEmu screen rotated to {orientation}"

    elif name == "memu_import_apk":
        r = _run_memuc(["installapp", "-i", str(index), args["apk_path"]], timeout=120)
        if not r["success"]:
            _run_adb(["connect", device])
            r = _run_adb(
                ["-s", device, "install", "-r", "-g", args["apk_path"]], timeout=120
            )
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    return f"Unknown tool: {name}"


# ── MCP Server ──
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
        logger.info(f"{SERVER_NAME} v{VERSION} started (memuc: {MEMUC})")
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
