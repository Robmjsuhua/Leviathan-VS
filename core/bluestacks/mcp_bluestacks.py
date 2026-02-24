#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP BlueStacks Server v1.0

    BlueStacks emulator control MCP server.
    Uses HD-Player CLI and ADB for full emulator control.
    JSON-RPC 2.0 over stdio with Content-Length framing.

    Tools:
        - bs_list_instances: List BlueStacks instances
        - bs_launch: Launch instance
        - bs_stop: Stop instance
        - bs_install_apk: Install APK
        - bs_run_app: Launch app
        - bs_adb_connect: Connect ADB to BlueStacks
        - bs_screenshot: Take screenshot
        - bs_input: Send input events
        - bs_shell: Execute shell via ADB
        - bs_get_config: Get instance configuration
        - bs_set_config: Modify instance config (resolution, CPU, RAM)
        - bs_list_apps: List installed apps
        - bs_pull_file: Pull file from emulator
        - bs_push_file: Push file to emulator
        - bs_rotate: Rotate screen
        - bs_shake: Shake device
        - bs_gps: Set GPS coordinates

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
logger = logging.getLogger("leviathan-bluestacks-mcp")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-bluestacks-server"


def _find_bluestacks() -> Dict[str, str]:
    """Find BlueStacks installation paths."""
    paths = {}
    candidates = [
        r"C:\Program Files\BlueStacks_nxt",
        r"C:\Program Files\BlueStacks",
        r"C:\Program Files (x86)\BlueStacks_nxt",
        r"C:\ProgramData\BlueStacks_nxt",
    ]
    for c in candidates:
        p = Path(c)
        if p.exists():
            hd_player = p / "HD-Player.exe"
            hd_adb = p / "HD-Adb.exe"
            hd_quit = p / "HD-Quit.exe"
            hd_configure = p / "HD-ConfigHttpProxy.exe"
            if hd_player.exists():
                paths["player"] = str(hd_player)
            if hd_adb.exists():
                paths["adb"] = str(hd_adb)
            if hd_quit.exists():
                paths["quit"] = str(hd_quit)
            paths["base"] = str(p)
            break
    # Fallback to regular ADB
    if "adb" not in paths:
        adb = shutil.which("adb")
        if adb:
            paths["adb"] = adb
    return paths


BS_PATHS = _find_bluestacks()
BS_ADB_PORT = 5555  # Default BS ADB port


def _run_cmd(cmd: List[str], timeout: int = 30) -> Dict:
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
    adb = BS_PATHS.get("adb", "adb")
    return _run_cmd([adb] + args, timeout)


def _get_conf_path() -> Optional[Path]:
    """Find bluestacks.conf file."""
    candidates = [
        Path(r"C:\ProgramData\BlueStacks_nxt\bluestacks.conf"),
        Path(r"C:\ProgramData\BlueStacks\bluestacks.conf"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


TOOLS = [
    {
        "name": "bs_list_instances",
        "description": "Lista instancias do BlueStacks configuradas",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "bs_launch",
        "description": "Inicia instancia do BlueStacks",
        "inputSchema": {
            "type": "object",
            "properties": {
                "instance": {
                    "type": "string",
                    "description": "Nome da instancia (default: Nougat64)",
                }
            },
        },
    },
    {
        "name": "bs_stop",
        "description": "Para instancia do BlueStacks",
        "inputSchema": {
            "type": "object",
            "properties": {"instance": {"type": "string"}},
        },
    },
    {
        "name": "bs_install_apk",
        "description": "Instala APK no BlueStacks via ADB",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "port": {"type": "integer", "description": "ADB port (default 5555)"},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "bs_run_app",
        "description": "Inicia app no BlueStacks",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "Nome do pacote"},
                "activity": {"type": "string", "description": "Activity (opcional)"},
                "port": {"type": "integer"},
            },
            "required": ["package"],
        },
    },
    {
        "name": "bs_adb_connect",
        "description": "Conecta ADB ao BlueStacks",
        "inputSchema": {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "description": "Port (default 5555)"}
            },
        },
    },
    {
        "name": "bs_screenshot",
        "description": "Tira screenshot do BlueStacks",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output": {
                    "type": "string",
                    "description": "Caminho local para salvar",
                },
                "port": {"type": "integer"},
            },
            "required": ["output"],
        },
    },
    {
        "name": "bs_input",
        "description": "Envia input para o BlueStacks (tap, swipe, text, keyevent)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["tap", "swipe", "text", "keyevent"],
                },
                "args": {"type": "string"},
                "port": {"type": "integer"},
            },
            "required": ["action", "args"],
        },
    },
    {
        "name": "bs_shell",
        "description": "Executa comando shell no BlueStacks via ADB",
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
        "name": "bs_get_config",
        "description": "Obtem configuracao da instancia BlueStacks",
        "inputSchema": {
            "type": "object",
            "properties": {"instance": {"type": "string"}},
        },
    },
    {
        "name": "bs_list_apps",
        "description": "Lista apps instalados no BlueStacks",
        "inputSchema": {
            "type": "object",
            "properties": {"port": {"type": "integer"}, "grep": {"type": "string"}},
        },
    },
    {
        "name": "bs_pull_file",
        "description": "Baixa arquivo do BlueStacks",
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
        "name": "bs_push_file",
        "description": "Envia arquivo para o BlueStacks",
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
        "name": "bs_gps",
        "description": "Define coordenadas GPS no BlueStacks",
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
        "name": "bs_set_config",
        "description": "Modifica configuracao da instancia BlueStacks (resolucao, CPU, RAM)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "instance": {
                    "type": "string",
                    "description": "Nome da instancia (default: Nougat64)",
                },
                "key": {
                    "type": "string",
                    "description": "Chave de config (ex: display_width, display_height, ram, cpus)",
                },
                "value": {"type": "string", "description": "Novo valor"},
            },
            "required": ["key", "value"],
        },
    },
    {
        "name": "bs_rotate",
        "description": "Rotaciona tela do BlueStacks (portrait/landscape)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "orientation": {
                    "type": "string",
                    "enum": ["portrait", "landscape"],
                    "description": "Orientacao desejada",
                },
                "port": {"type": "integer"},
            },
            "required": ["orientation"],
        },
    },
    {
        "name": "bs_shake",
        "description": "Simula shake do dispositivo no BlueStacks",
        "inputSchema": {
            "type": "object",
            "properties": {
                "port": {"type": "integer"},
            },
        },
    },
]


async def dispatch_tool(name: str, args: Dict) -> str:
    port = args.get("port", BS_ADB_PORT)
    device = f"127.0.0.1:{port}"

    if name == "bs_list_instances":
        conf = _get_conf_path()
        if conf:
            content = conf.read_text(encoding="utf-8", errors="replace")
            instances = set()
            for line in content.splitlines():
                if "bst.instance" in line:
                    parts = line.split(".")
                    if len(parts) >= 3:
                        instances.add(parts[2])
            return (
                f"BlueStacks instances:\n" + "\n".join(sorted(instances))
                if instances
                else "No instances found"
            )
        return "BlueStacks config not found"

    elif name == "bs_launch":
        player = BS_PATHS.get("player")
        if not player:
            return "BlueStacks HD-Player.exe not found"
        instance = args.get("instance", "Nougat64")
        r = _run_cmd([player, "--instance", instance], timeout=5)
        return f"Launching BlueStacks instance: {instance}"

    elif name == "bs_stop":
        quit_exe = BS_PATHS.get("quit")
        if quit_exe:
            instance = args.get("instance", "Nougat64")
            r = _run_cmd([quit_exe, "--instance", instance], timeout=10)
            return f"Stopping instance: {instance}"
        return "BlueStacks HD-Quit.exe not found"

    elif name == "bs_install_apk":
        _run_adb(["connect", device])
        r = _run_adb(
            ["-s", device, "install", "-r", "-g", args["apk_path"]], timeout=120
        )
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "bs_run_app":
        _run_adb(["connect", device])
        pkg = args["package"]
        activity = args.get("activity", "")
        if activity:
            r = _run_adb(
                ["-s", device, "shell", "am", "start", "-n", f"{pkg}/{activity}"]
            )
        else:
            r = _run_adb(
                [
                    "-s",
                    device,
                    "shell",
                    "monkey",
                    "-p",
                    pkg,
                    "-c",
                    "android.intent.category.LAUNCHER",
                    "1",
                ]
            )
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "bs_adb_connect":
        r = _run_adb(["connect", device])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "bs_screenshot":
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

    elif name == "bs_input":
        _run_adb(["connect", device])
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
        else:
            return f"Unknown action: {action}"
        r = _run_adb(["-s", device, "shell", cmd])
        return f"Input sent: {action} {a}"

    elif name == "bs_shell":
        _run_adb(["connect", device])
        timeout = args.get("timeout", 30)
        r = _run_adb(["-s", device, "shell", args["command"]], timeout=timeout)
        return (
            r["stdout"]
            if r["success"]
            else f"ERROR: {r.get('stderr', r.get('error', ''))}"
        )

    elif name == "bs_get_config":
        conf = _get_conf_path()
        if not conf:
            return "Config not found"
        instance = args.get("instance", "Nougat64")
        content = conf.read_text(encoding="utf-8", errors="replace")
        lines = [l for l in content.splitlines() if instance.lower() in l.lower()]
        return "\n".join(lines[:100]) if lines else f"No config found for {instance}"

    elif name == "bs_list_apps":
        _run_adb(["connect", device])
        r = _run_adb(["-s", device, "shell", "pm", "list", "packages", "-3"])
        output = r["stdout"]
        if args.get("grep"):
            output = "\n".join(
                l for l in output.splitlines() if args["grep"].lower() in l.lower()
            )
        return output if output else "No apps found"

    elif name == "bs_pull_file":
        _run_adb(["connect", device])
        r = _run_adb(["-s", device, "pull", args["remote"], args["local"]], timeout=120)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "bs_push_file":
        _run_adb(["connect", device])
        r = _run_adb(["-s", device, "push", args["local"], args["remote"]], timeout=120)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "bs_gps":
        _run_adb(["connect", device])
        lat = args["latitude"]
        lon = args["longitude"]
        r = _run_adb(["-s", device, "emu", "geo", "fix", str(lon), str(lat)])
        return f"GPS set to {lat}, {lon}" if r["success"] else r.get("error", "")

    elif name == "bs_set_config":
        conf = _get_conf_path()
        if not conf:
            return "BlueStacks config not found"
        instance = args.get("instance", "Nougat64")
        key = args["key"]
        value = args["value"]
        full_key = f"bst.instance.{instance}.{key}"
        content = conf.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
        found = False
        for i, line in enumerate(lines):
            if line.startswith(full_key + "="):
                lines[i] = f"{full_key}={value}"
                found = True
                break
        if not found:
            lines.append(f"{full_key}={value}")
        conf.write_text("\n".join(lines), encoding="utf-8")
        return f"Set {full_key}={value}" + ("" if found else " (new key added)")

    elif name == "bs_rotate":
        _run_adb(["connect", device])
        orientation = args["orientation"]
        if orientation == "portrait":
            r = _run_adb(
                [
                    "-s",
                    device,
                    "shell",
                    "settings",
                    "put",
                    "system",
                    "user_rotation",
                    "0",
                ]
            )
        else:
            r = _run_adb(
                [
                    "-s",
                    device,
                    "shell",
                    "settings",
                    "put",
                    "system",
                    "user_rotation",
                    "1",
                ]
            )
        # Also toggle accelerometer
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
        return f"Screen rotated to {orientation}"

    elif name == "bs_shake":
        _run_adb(["connect", device])
        # Simulate shake via sensor acceleration values
        _run_adb(["-s", device, "emu", "sensor", "set", "acceleration", "50:0:0"])
        import time

        time.sleep(0.15)
        _run_adb(["-s", device, "emu", "sensor", "set", "acceleration", "0:50:0"])
        time.sleep(0.15)
        _run_adb(["-s", device, "emu", "sensor", "set", "acceleration", "0:0:9.8"])
        return "Shake event sent"

    return f"Unknown tool: {name}"


# ── MCP Server (standard boilerplate) ──
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
        logger.info(f"{SERVER_NAME} v{VERSION} started (BS: {BS_PATHS})")
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
