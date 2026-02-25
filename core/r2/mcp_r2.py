#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP Radare2 Server v1.0

    Binary analysis and reverse engineering MCP server via r2pipe.
    Uses radare2 CLI for complete binary analysis.
    JSON-RPC 2.0 over stdio with Content-Length framing.

    Tools:
        - r2_analyze: Open and auto-analyze binary
        - r2_functions: List all functions
        - r2_disasm: Disassemble at address/function
        - r2_strings: Extract strings from binary
        - r2_imports: List imports
        - r2_exports: List exports
        - r2_sections: List sections/segments
        - r2_xrefs_to: Cross-references to address
        - r2_xrefs_from: Cross-references from address
        - r2_hex_dump: Hex dump at address
        - r2_search: Search bytes/string/regex in binary
        - r2_info: Binary info (arch, bits, format, etc)
        - r2_entry_points: List entry points
        - r2_cmd: Execute raw r2 command
        - r2_decompile: Decompile function (with r2ghidra/r2dec)
        - r2_patch: Patch bytes at address

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
logger = logging.getLogger("leviathan-r2-mcp")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-r2-server"


def _find_r2() -> str:
    candidates = [
        shutil.which("radare2"),
        shutil.which("r2"),
        r"C:\Program Files\radare2\bin\radare2.exe",
        r"C:\Program Files (x86)\radare2\bin\radare2.exe",
        r"C:\radare2\bin\radare2.exe",
        r"C:\Users\Kishi\AppData\Local\Programs\radare2\bin\radare2.exe",
    ]
    for c in candidates:
        if c and Path(c).exists():
            return str(c)
    return "radare2"


R2 = _find_r2()


def _run_r2(binary: str, cmds: List[str], timeout: int = 60) -> Dict:
    """Run radare2 with -q (quiet) -c (commands) and return output."""
    cmd_str = ";".join(cmds)
    cmd = [R2, "-q", "-e", "bin.cache=true", "-c", cmd_str, binary]
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
            "success": proc.returncode == 0 or bool(proc.stdout.strip()),
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Timeout after {timeout}s"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _run_r2_json(binary: str, cmds: List[str], timeout: int = 60) -> Dict:
    """Run r2 and parse JSON output."""
    r = _run_r2(binary, cmds, timeout)
    if not r["success"]:
        return r
    try:
        data = json.loads(r["stdout"])
        return {"success": True, "data": data}
    except json.JSONDecodeError:
        return {"success": True, "stdout": r["stdout"]}


TOOLS = [
    {
        "name": "r2_analyze",
        "description": "Abre binario e faz auto-analise completa (aaa). Retorna info basica.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {
                    "type": "string",
                    "description": "Caminho do binario (ELF, PE, Mach-O, .so, .dll, APK .dex)",
                },
                "deep": {
                    "type": "boolean",
                    "description": "Analise profunda com aaaa (mais lento)",
                },
            },
            "required": ["binary"],
        },
    },
    {
        "name": "r2_functions",
        "description": "Lista todas as funcoes encontradas na analise",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string"},
                "filter": {
                    "type": "string",
                    "description": "Filtro por nome da funcao",
                },
            },
            "required": ["binary"],
        },
    },
    {
        "name": "r2_disasm",
        "description": "Disassembla funcao ou endereco",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string"},
                "address": {
                    "type": "string",
                    "description": "Endereco hex ou nome de funcao (ex: main, 0x401000)",
                },
                "length": {
                    "type": "integer",
                    "description": "Numero de instrucoes (default 50)",
                },
            },
            "required": ["binary", "address"],
        },
    },
    {
        "name": "r2_strings",
        "description": "Extrai strings do binario",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string"},
                "min_length": {
                    "type": "integer",
                    "description": "Comprimento minimo (default 5)",
                },
                "filter": {"type": "string", "description": "Filtro por conteudo"},
            },
            "required": ["binary"],
        },
    },
    {
        "name": "r2_imports",
        "description": "Lista funcoes importadas do binario",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string"},
                "filter": {"type": "string"},
            },
            "required": ["binary"],
        },
    },
    {
        "name": "r2_exports",
        "description": "Lista funcoes exportadas do binario",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string"},
                "filter": {"type": "string"},
            },
            "required": ["binary"],
        },
    },
    {
        "name": "r2_sections",
        "description": "Lista secoes/segmentos do binario",
        "inputSchema": {
            "type": "object",
            "properties": {"binary": {"type": "string"}},
            "required": ["binary"],
        },
    },
    {
        "name": "r2_xrefs_to",
        "description": "Lista cross-references TO endereco/funcao",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string"},
                "address": {"type": "string", "description": "Endereco hex ou nome"},
            },
            "required": ["binary", "address"],
        },
    },
    {
        "name": "r2_xrefs_from",
        "description": "Lista cross-references FROM endereco/funcao",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string"},
                "address": {"type": "string", "description": "Endereco hex ou nome"},
            },
            "required": ["binary", "address"],
        },
    },
    {
        "name": "r2_hex_dump",
        "description": "Hex dump em endereco especifico",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string"},
                "address": {"type": "string", "description": "Endereco hex"},
                "size": {
                    "type": "integer",
                    "description": "Bytes para ler (default 256)",
                },
            },
            "required": ["binary", "address"],
        },
    },
    {
        "name": "r2_search",
        "description": "Busca bytes, string ou regex no binario",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string"},
                "pattern": {"type": "string", "description": "Padrao de busca"},
                "type": {
                    "type": "string",
                    "enum": ["string", "hex", "regex"],
                    "description": "Tipo de busca (default string)",
                },
            },
            "required": ["binary", "pattern"],
        },
    },
    {
        "name": "r2_info",
        "description": "Info completa do binario (arch, bits, os, formato, checksums, etc)",
        "inputSchema": {
            "type": "object",
            "properties": {"binary": {"type": "string"}},
            "required": ["binary"],
        },
    },
    {
        "name": "r2_entry_points",
        "description": "Lista entry points do binario",
        "inputSchema": {
            "type": "object",
            "properties": {"binary": {"type": "string"}},
            "required": ["binary"],
        },
    },
    {
        "name": "r2_cmd",
        "description": "Executa comando r2 raw no binario. Para usuarios avancados.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string"},
                "command": {
                    "type": "string",
                    "description": "Comando r2 (ex: afl, pdf @main, /R JMP ESP)",
                },
                "analyze": {
                    "type": "boolean",
                    "description": "Rodar aaa antes do comando (default true)",
                },
            },
            "required": ["binary", "command"],
        },
    },
    {
        "name": "r2_decompile",
        "description": "Decompila funcao (requer r2ghidra ou r2dec plugin)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string"},
                "function": {
                    "type": "string",
                    "description": "Nome ou endereco da funcao",
                },
                "plugin": {
                    "type": "string",
                    "enum": ["ghidra", "dec"],
                    "description": "Plugin: ghidra (pdg) ou dec (pdd) - default ghidra",
                },
            },
            "required": ["binary", "function"],
        },
    },
    {
        "name": "r2_patch",
        "description": "Patcha bytes em endereco do binario (cria backup)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary": {"type": "string"},
                "address": {
                    "type": "string",
                    "description": "Endereco hex para patchar",
                },
                "hex_bytes": {
                    "type": "string",
                    "description": "Bytes hex para escrever (ex: 9090)",
                },
                "backup": {
                    "type": "boolean",
                    "description": "Criar backup antes (default true)",
                },
            },
            "required": ["binary", "address", "hex_bytes"],
        },
    },
]


async def dispatch_tool(name: str, args: Dict) -> str:
    binary = args.get("binary", "")

    if name == "r2_analyze":
        deep = args.get("deep", False)
        analysis = "aaaa" if deep else "aaa"
        r = _run_r2(binary, [analysis, "iI", "afl | wc -l"])
        if not r["success"]:
            return r.get("error", r.get("stderr", ""))
        return f"Analysis complete ({analysis})\n{r['stdout']}"

    elif name == "r2_functions":
        filt = args.get("filter", "")
        if filt:
            r = _run_r2(binary, ["aaa", f"afl~{filt}"])
        else:
            r = _run_r2(binary, ["aaa", "afl"])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "r2_disasm":
        addr = args["address"]
        length = args.get("length", 50)
        # Seek + print disassembly
        r = _run_r2(binary, ["aaa", f"s {addr}", f"pd {length}"])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "r2_strings":
        min_len = args.get("min_length", 5)
        filt = args.get("filter", "")
        cmd = f"iz~{filt}" if filt else "iz"
        r = _run_r2(binary, [f"e bin.minstr={min_len}", cmd])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "r2_imports":
        filt = args.get("filter", "")
        cmd = f"ii~{filt}" if filt else "ii"
        r = _run_r2(binary, [cmd])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "r2_exports":
        filt = args.get("filter", "")
        cmd = f"iE~{filt}" if filt else "iE"
        r = _run_r2(binary, [cmd])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "r2_sections":
        r = _run_r2(binary, ["iS"])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "r2_xrefs_to":
        addr = args["address"]
        r = _run_r2(binary, ["aaa", f"s {addr}", "axt"])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "r2_xrefs_from":
        addr = args["address"]
        r = _run_r2(binary, ["aaa", f"s {addr}", "axf"])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "r2_hex_dump":
        addr = args["address"]
        size = args.get("size", 256)
        r = _run_r2(binary, [f"s {addr}", f"px {size}"])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "r2_search":
        pattern = args["pattern"]
        stype = args.get("type", "string")
        search_cmds = {
            "string": f"/ {pattern}",
            "hex": f"/x {pattern}",
            "regex": f"/e {pattern}",
        }
        cmd = search_cmds.get(stype, f"/ {pattern}")
        r = _run_r2(binary, [cmd])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "r2_info":
        r = _run_r2(binary, ["iI"])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "r2_entry_points":
        r = _run_r2(binary, ["ie"])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "r2_cmd":
        command = args["command"]
        analyze = args.get("analyze", True)
        cmds = ["aaa", command] if analyze else [command]
        r = _run_r2(binary, cmds, timeout=120)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "r2_decompile":
        func = args["function"]
        plugin = args.get("plugin", "ghidra")
        decompile_cmd = "pdg" if plugin == "ghidra" else "pdd"
        r = _run_r2(binary, ["aaa", f"s {func}", decompile_cmd], timeout=120)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "r2_patch":
        addr = args["address"]
        hex_bytes = args["hex_bytes"]
        backup = args.get("backup", True)

        if backup:
            import shutil as sh

            bak = binary + ".bak"
            sh.copy2(binary, bak)

        # Open in write mode and patch
        cmd = [R2, "-q", "-w", "-c", f"s {addr};wx {hex_bytes}", binary]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                encoding="utf-8",
                errors="replace",
            )
            if proc.returncode == 0:
                msg = f"Patched {len(hex_bytes)//2} byte(s) at {addr}"
                if backup:
                    msg += f"\nBackup: {binary}.bak"
                return msg
            return proc.stderr.strip() or "Patch failed"
        except Exception as e:
            return f"Error: {e}"

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
            name = params.get("name", "")
            tool_args = params.get("arguments", {})
            try:
                result = await dispatch_tool(name, tool_args)
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
        if sys.platform == "win32":
            import msvcrt

            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)

        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(
            lambda: protocol, sys.stdin.buffer
        )

        logger.info(f"{SERVER_NAME} v{VERSION} started")
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
