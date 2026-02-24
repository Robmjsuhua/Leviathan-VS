#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP Objection Server v1.0

    Mobile runtime exploration MCP server using objection (Frida-based).
    Full Android + iOS runtime manipulation via objection CLI.
    JSON-RPC 2.0 over stdio with Content-Length framing.

    Tools:
        - obj_explore: Start objection explore session
        - obj_env: Get device environment info
        - obj_ssl_disable: Disable SSL pinning
        - obj_root_disable: Disable root/jailbreak detection
        - obj_android_hooking: Hook Android methods
        - obj_android_intent: Launch Android intent
        - obj_android_keystore: Dump Android keystore
        - obj_android_clipboard: Get/set clipboard
        - obj_memory_dump: Dump process memory
        - obj_memory_search: Search memory for pattern
        - obj_sqlite: Execute SQLite commands
        - obj_file_download: Download file from device
        - obj_file_upload: Upload file to device
        - obj_file_ls: List files on device
        - obj_patchapk: Patch APK with Frida gadget
        - obj_run_command: Run arbitrary objection command
        - obj_android_activities: List Android activities
        - obj_android_services: List Android services
        - obj_android_providers: List content providers
        - obj_android_receivers: List broadcast receivers

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
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("leviathan-objection-mcp")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-objection-server"


def _find_objection() -> str:
    p = shutil.which("objection")
    return p if p else "objection"


OBJECTION = _find_objection()


def _run_objection(gadget: str, command: str, timeout: int = 60) -> Dict:
    cmd = [OBJECTION]
    if gadget:
        cmd += ["-g", gadget]
    cmd += ["explore", "--startup-command", command]
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
    except FileNotFoundError:
        return {
            "success": False,
            "error": "objection not found. Install: pip install objection",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _run_objection_multi(gadget: str, commands: List[str], timeout: int = 60) -> Dict:
    cmd = [OBJECTION]
    if gadget:
        cmd += ["-g", gadget]
    cmd.append("explore")
    for c in commands:
        cmd += ["--startup-command", c]
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
    except FileNotFoundError:
        return {
            "success": False,
            "error": "objection not found. Install: pip install objection",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _run_patchapk(
    apk_path: str, extra_args: List[str] = None, timeout: int = 300
) -> Dict:
    cmd = [OBJECTION, "patchapk", "--source", apk_path]
    if extra_args:
        cmd += extra_args
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
        "name": "obj_explore",
        "description": "Inicia sessao objection explore no app",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gadget": {
                    "type": "string",
                    "description": "Package name do app (ex: com.example.app)",
                },
                "startup_commands": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Comandos a executar ao iniciar",
                },
            },
            "required": ["gadget"],
        },
    },
    {
        "name": "obj_env",
        "description": "Obtem informacoes do ambiente do dispositivo",
        "inputSchema": {
            "type": "object",
            "properties": {"gadget": {"type": "string"}},
            "required": ["gadget"],
        },
    },
    {
        "name": "obj_ssl_disable",
        "description": "Desativa SSL pinning no app",
        "inputSchema": {
            "type": "object",
            "properties": {"gadget": {"type": "string"}},
            "required": ["gadget"],
        },
    },
    {
        "name": "obj_root_disable",
        "description": "Desativa deteccao de root/jailbreak",
        "inputSchema": {
            "type": "object",
            "properties": {"gadget": {"type": "string"}, "quiet": {"type": "boolean"}},
            "required": ["gadget"],
        },
    },
    {
        "name": "obj_android_hooking",
        "description": "Hook metodo Android (watch class/method)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gadget": {"type": "string"},
                "class_name": {"type": "string"},
                "method": {
                    "type": "string",
                    "description": "Nome do metodo (omitir para hookar toda a classe)",
                },
                "dump_args": {"type": "boolean"},
                "dump_return": {"type": "boolean"},
                "dump_backtrace": {"type": "boolean"},
            },
            "required": ["gadget", "class_name"],
        },
    },
    {
        "name": "obj_android_intent",
        "description": "Lanca Android intent",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gadget": {"type": "string"},
                "action": {"type": "string"},
                "component": {"type": "string"},
                "data_uri": {"type": "string"},
                "extras": {"type": "object"},
            },
            "required": ["gadget"],
        },
    },
    {
        "name": "obj_android_keystore",
        "description": "Dump Android keystore entries",
        "inputSchema": {
            "type": "object",
            "properties": {"gadget": {"type": "string"}},
            "required": ["gadget"],
        },
    },
    {
        "name": "obj_android_clipboard",
        "description": "Get/set clipboard do Android",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gadget": {"type": "string"},
                "action": {"type": "string", "enum": ["get", "set"]},
                "text": {"type": "string", "description": "Texto para set"},
            },
            "required": ["gadget", "action"],
        },
    },
    {
        "name": "obj_memory_dump",
        "description": "Dump de memoria do processo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gadget": {"type": "string"},
                "output": {
                    "type": "string",
                    "description": "Caminho do arquivo de saida",
                },
                "base": {"type": "string", "description": "Endereco base hex"},
                "size": {"type": "integer", "description": "Tamanho em bytes"},
            },
            "required": ["gadget", "output"],
        },
    },
    {
        "name": "obj_memory_search",
        "description": "Busca padrao na memoria do processo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gadget": {"type": "string"},
                "pattern": {
                    "type": "string",
                    "description": "Padrao a buscar (string ou hex)",
                },
            },
            "required": ["gadget", "pattern"],
        },
    },
    {
        "name": "obj_sqlite",
        "description": "Executa comandos SQLite no app",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gadget": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": ["list", "connect", "execute"],
                    "description": "Acao: list dbs, connect, execute query",
                },
                "database": {"type": "string"},
                "query": {"type": "string"},
            },
            "required": ["gadget", "action"],
        },
    },
    {
        "name": "obj_file_download",
        "description": "Baixa arquivo do dispositivo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gadget": {"type": "string"},
                "remote_path": {"type": "string"},
                "local_path": {"type": "string"},
            },
            "required": ["gadget", "remote_path", "local_path"],
        },
    },
    {
        "name": "obj_file_upload",
        "description": "Envia arquivo para o dispositivo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gadget": {"type": "string"},
                "local_path": {"type": "string"},
                "remote_path": {"type": "string"},
            },
            "required": ["gadget", "local_path", "remote_path"],
        },
    },
    {
        "name": "obj_file_ls",
        "description": "Lista arquivos no dispositivo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gadget": {"type": "string"},
                "path": {
                    "type": "string",
                    "description": "Diretorio a listar (default: app data dir)",
                },
            },
            "required": ["gadget"],
        },
    },
    {
        "name": "obj_patchapk",
        "description": "Patch APK com Frida gadget para injecao",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "architecture": {
                    "type": "string",
                    "enum": ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"],
                },
                "skip_resources": {"type": "boolean"},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "obj_run_command",
        "description": "Executa comando objection arbitrario",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gadget": {"type": "string"},
                "command": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["gadget", "command"],
        },
    },
    {
        "name": "obj_android_activities",
        "description": "Lista activities do app Android",
        "inputSchema": {
            "type": "object",
            "properties": {"gadget": {"type": "string"}},
            "required": ["gadget"],
        },
    },
    {
        "name": "obj_android_services",
        "description": "Lista services do app Android",
        "inputSchema": {
            "type": "object",
            "properties": {"gadget": {"type": "string"}},
            "required": ["gadget"],
        },
    },
    {
        "name": "obj_android_providers",
        "description": "Lista content providers do app",
        "inputSchema": {
            "type": "object",
            "properties": {"gadget": {"type": "string"}},
            "required": ["gadget"],
        },
    },
    {
        "name": "obj_android_receivers",
        "description": "Lista broadcast receivers do app",
        "inputSchema": {
            "type": "object",
            "properties": {"gadget": {"type": "string"}},
            "required": ["gadget"],
        },
    },
]


async def dispatch_tool(name: str, args: Dict) -> str:
    gadget = args.get("gadget", "")
    timeout = args.get("timeout", 60)

    if name == "obj_explore":
        cmds = args.get("startup_commands", [])
        if cmds:
            r = _run_objection_multi(gadget, cmds, timeout)
        else:
            r = _run_objection(gadget, "env", timeout)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "obj_env":
        r = _run_objection(gadget, "env", timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_ssl_disable":
        r = _run_objection(gadget, "android sslpinning disable", timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_root_disable":
        quiet = "--quiet" if args.get("quiet") else ""
        r = _run_objection(gadget, f"android root disable {quiet}".strip(), timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_android_hooking":
        cls = args["class_name"]
        method = args.get("method", "")
        if method:
            cmd = f"android hooking watch class_method {cls}.{method}"
            if args.get("dump_args"):
                cmd += " --dump-args"
            if args.get("dump_return"):
                cmd += " --dump-return"
            if args.get("dump_backtrace"):
                cmd += " --dump-backtrace"
        else:
            cmd = f"android hooking watch class {cls}"
        r = _run_objection(gadget, cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_android_intent":
        parts = ["android intent launch_activity"]
        if args.get("component"):
            parts.append(args["component"])
        elif args.get("action"):
            parts = [f"android intent launch_service --action {args['action']}"]
        r = _run_objection(gadget, " ".join(parts), timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_android_keystore":
        r = _run_objection(gadget, "android keystore list", timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_android_clipboard":
        action = args["action"]
        if action == "get":
            r = _run_objection(gadget, "android clipboard monitor", timeout)
        else:
            text = args.get("text", "")
            r = _run_objection(gadget, f'android clipboard set "{text}"', timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_memory_dump":
        output = args["output"]
        if args.get("base") and args.get("size"):
            cmd = f"memory dump from_base {args['base']} {args['size']} {output}"
        else:
            cmd = f"memory dump all {output}"
        r = _run_objection(gadget, cmd, 300)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_memory_search":
        pattern = args["pattern"]
        r = _run_objection(gadget, f'memory search "{pattern}"', timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_sqlite":
        action = args["action"]
        if action == "list":
            r = _run_objection(gadget, "sqlite list", timeout)
        elif action == "connect":
            db = args.get("database", "")
            r = _run_objection(gadget, f"sqlite connect {db}", timeout)
        else:
            db = args.get("database", "")
            query = args.get("query", "")
            cmds = []
            if db:
                cmds.append(f"sqlite connect {db}")
            cmds.append(f'sqlite execute query "{query}"')
            r = _run_objection_multi(gadget, cmds, timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_file_download":
        r = _run_objection(
            gadget, f"file download {args['remote_path']} {args['local_path']}", timeout
        )
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_file_upload":
        r = _run_objection(
            gadget, f"file upload {args['local_path']} {args['remote_path']}", timeout
        )
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_file_ls":
        path = args.get("path", ".")
        r = _run_objection(gadget, f"ls {path}", timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_patchapk":
        extra = []
        if args.get("architecture"):
            extra += ["--architecture", args["architecture"]]
        if args.get("skip_resources"):
            extra.append("--skip-resources")
        r = _run_patchapk(args["apk_path"], extra)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "obj_run_command":
        r = _run_objection(gadget, args["command"], timeout)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "obj_android_activities":
        r = _run_objection(gadget, "android hooking list activities", timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_android_services":
        r = _run_objection(gadget, "android hooking list services", timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_android_providers":
        r = _run_objection(gadget, "android hooking list providers", timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "obj_android_receivers":
        r = _run_objection(gadget, "android hooking list receivers", timeout)
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
        logger.info(f"{SERVER_NAME} v{VERSION} started (objection: {OBJECTION})")
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
