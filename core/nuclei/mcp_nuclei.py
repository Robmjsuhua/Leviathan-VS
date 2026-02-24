#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP Nuclei + SQLMap + Nmap Server v1.0

    Vulnerability scanning MCP server.
    Integrates nuclei, sqlmap, nmap, nikto, dirb, ffuf, whatweb CLIs.
    JSON-RPC 2.0 over stdio with Content-Length framing.

    Tools:
        - nuclei_scan: Run nuclei vulnerability scan
        - nuclei_templates: List/search nuclei templates
        - nuclei_cve_scan: Scan for specific CVE
        - nuclei_custom: Run nuclei with custom template
        - sqlmap_scan: Run SQLMap injection scan
        - sqlmap_dump: Dump database tables via SQLMap
        - sqlmap_tables: List tables from database
        - sqlmap_dbs: List databases
        - nmap_scan: Run nmap port scan
        - nmap_services: Detect services on target
        - nmap_vuln: Run nmap vuln scripts
        - dirb_scan: Directory brute-force scan
        - ffuf_fuzz: Web fuzzing with ffuf
        - nikto_scan: Run nikto web scanner
        - whatweb_scan: Identify web technologies
        - subfinder_enum: Subdomain enumeration
        - httpx_probe: HTTP probing of hosts

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
import tempfile
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("leviathan-nuclei-mcp")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-nuclei-server"


def _find_tool(name: str) -> str:
    p = shutil.which(name)
    return p if p else name


def _run_tool(cmd: List[str], timeout: int = 300) -> Dict:
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
            "error": f"Tool not found: {cmd[0]}. Install it first.",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


TOOLS = [
    {
        "name": "nuclei_scan",
        "description": "Executa scan nuclei em alvo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "templates": {
                    "type": "string",
                    "description": "Tags de template (ex: cve,xss,sqli)",
                },
                "severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                },
                "timeout": {"type": "integer"},
                "extra_args": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "nuclei_templates",
        "description": "Lista/busca templates nuclei",
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string"},
                "tags": {"type": "string"},
                "severity": {"type": "string"},
            },
        },
    },
    {
        "name": "nuclei_cve_scan",
        "description": "Escaneia CVE especifico com nuclei",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "cve_id": {
                    "type": "string",
                    "description": "CVE ID ex: CVE-2021-44228",
                },
            },
            "required": ["target", "cve_id"],
        },
    },
    {
        "name": "nuclei_custom",
        "description": "Executa nuclei com template customizado",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "template_path": {"type": "string"},
            },
            "required": ["target", "template_path"],
        },
    },
    {
        "name": "sqlmap_scan",
        "description": "Executa SQLMap em URL alvo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "data": {"type": "string", "description": "POST data"},
                "cookie": {"type": "string"},
                "level": {"type": "integer", "description": "Level 1-5"},
                "risk": {"type": "integer", "description": "Risk 1-3"},
                "technique": {"type": "string", "description": "BEUSTQ"},
                "tamper": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "sqlmap_dump",
        "description": "Dump tabela via SQLMap",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "database": {"type": "string"},
                "table": {"type": "string"},
                "columns": {"type": "string"},
                "cookie": {"type": "string"},
            },
            "required": ["url", "database", "table"],
        },
    },
    {
        "name": "sqlmap_tables",
        "description": "Lista tabelas de database via SQLMap",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "database": {"type": "string"},
                "cookie": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "sqlmap_dbs",
        "description": "Lista databases via SQLMap",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}, "cookie": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "nmap_scan",
        "description": "Executa nmap port scan",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "ports": {
                    "type": "string",
                    "description": "Range de portas (ex: 1-1000, 80,443)",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["syn", "connect", "udp", "ack", "fin"],
                    "description": "Tipo de scan",
                },
                "extra_args": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "nmap_services",
        "description": "Detecta servicos em alvo com nmap",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}, "ports": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "nmap_vuln",
        "description": "Executa scripts de vulnerabilidade nmap",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "scripts": {
                    "type": "string",
                    "description": "Scripts nmap (default: vuln)",
                },
                "ports": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "dirb_scan",
        "description": "Directory brute-force com dirb/gobuster",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "wordlist": {"type": "string"},
                "extensions": {
                    "type": "string",
                    "description": "Extensoes: php,html,txt",
                },
                "timeout": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "ffuf_fuzz",
        "description": "Web fuzzing com ffuf",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL com FUZZ placeholder"},
                "wordlist": {"type": "string"},
                "method": {"type": "string"},
                "headers": {"type": "object"},
                "data": {"type": "string"},
                "filter_code": {"type": "string"},
                "filter_size": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["url", "wordlist"],
        },
    },
    {
        "name": "nikto_scan",
        "description": "Executa scan nikto em web server",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "ssl": {"type": "boolean"},
                "timeout": {"type": "integer"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "whatweb_scan",
        "description": "Identifica tecnologias web com whatweb",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "aggression": {
                    "type": "integer",
                    "description": "1-4 (1=stealthy, 4=heavy)",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "subfinder_enum",
        "description": "Enumeracao de subdominios com subfinder",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "sources": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "httpx_probe",
        "description": "HTTP probing de hosts com httpx",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}},
                "ports": {"type": "string"},
                "path": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["targets"],
        },
    },
]


async def dispatch_tool(name: str, args: Dict) -> str:
    timeout = args.get("timeout", 300)

    if name == "nuclei_scan":
        cmd = [_find_tool("nuclei"), "-target", args["target"], "-jsonl", "-silent"]
        if args.get("templates"):
            cmd += ["-tags", args["templates"]]
        if args.get("severity"):
            cmd += ["-severity", args["severity"]]
        if args.get("extra_args"):
            cmd += args["extra_args"].split()
        r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "nuclei_templates":
        cmd = [_find_tool("nuclei"), "-tl"]
        if args.get("tags"):
            cmd += ["-tags", args["tags"]]
        if args.get("severity"):
            cmd += ["-severity", args["severity"]]
        r = _run_tool(cmd, 60)
        output = r["stdout"]
        if args.get("search"):
            output = "\n".join(
                l for l in output.splitlines() if args["search"].lower() in l.lower()
            )
        return output if output else "No templates found"

    elif name == "nuclei_cve_scan":
        cmd = [
            _find_tool("nuclei"),
            "-target",
            args["target"],
            "-tags",
            args["cve_id"].lower().replace("-", ""),
            "-jsonl",
            "-silent",
        ]
        r = _run_tool(cmd, timeout)
        if not r["stdout"]:
            cmd = [
                _find_tool("nuclei"),
                "-target",
                args["target"],
                "-id",
                args["cve_id"],
                "-jsonl",
                "-silent",
            ]
            r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "nuclei_custom":
        cmd = [
            _find_tool("nuclei"),
            "-target",
            args["target"],
            "-t",
            args["template_path"],
            "-jsonl",
        ]
        r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "sqlmap_scan":
        cmd = [
            _find_tool("sqlmap"),
            "-u",
            args["url"],
            "--batch",
            "--output-dir",
            tempfile.mkdtemp(),
        ]
        if args.get("data"):
            cmd += ["--data", args["data"]]
        if args.get("cookie"):
            cmd += ["--cookie", args["cookie"]]
        if args.get("level"):
            cmd += ["--level", str(args["level"])]
        if args.get("risk"):
            cmd += ["--risk", str(args["risk"])]
        if args.get("technique"):
            cmd += ["--technique", args["technique"]]
        if args.get("tamper"):
            cmd += ["--tamper", args["tamper"]]
        r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "sqlmap_dump":
        cmd = [
            _find_tool("sqlmap"),
            "-u",
            args["url"],
            "--batch",
            "-D",
            args["database"],
            "-T",
            args["table"],
            "--dump",
        ]
        if args.get("columns"):
            cmd += ["-C", args["columns"]]
        if args.get("cookie"):
            cmd += ["--cookie", args["cookie"]]
        r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "sqlmap_tables":
        cmd = [_find_tool("sqlmap"), "-u", args["url"], "--batch", "--tables"]
        if args.get("database"):
            cmd += ["-D", args["database"]]
        if args.get("cookie"):
            cmd += ["--cookie", args["cookie"]]
        r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "sqlmap_dbs":
        cmd = [_find_tool("sqlmap"), "-u", args["url"], "--batch", "--dbs"]
        if args.get("cookie"):
            cmd += ["--cookie", args["cookie"]]
        r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "nmap_scan":
        scan_flags = {
            "syn": "-sS",
            "connect": "-sT",
            "udp": "-sU",
            "ack": "-sA",
            "fin": "-sF",
        }
        cmd = [_find_tool("nmap")]
        st = args.get("scan_type", "connect")
        cmd.append(scan_flags.get(st, "-sT"))
        if args.get("ports"):
            cmd += ["-p", args["ports"]]
        if args.get("extra_args"):
            cmd += args["extra_args"].split()
        cmd.append(args["target"])
        r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "nmap_services":
        cmd = [_find_tool("nmap"), "-sV"]
        if args.get("ports"):
            cmd += ["-p", args["ports"]]
        cmd.append(args["target"])
        r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "nmap_vuln":
        scripts = args.get("scripts", "vuln")
        cmd = [_find_tool("nmap"), "--script", scripts]
        if args.get("ports"):
            cmd += ["-p", args["ports"]]
        cmd.append(args["target"])
        r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "dirb_scan":
        gobuster = shutil.which("gobuster")
        dirb = shutil.which("dirb")
        if gobuster:
            cmd = [gobuster, "dir", "-u", args["url"]]
            wl = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            cmd += ["-w", wl]
            if args.get("extensions"):
                cmd += ["-x", args["extensions"]]
        elif dirb:
            cmd = [dirb, args["url"]]
            if args.get("wordlist"):
                cmd.append(args["wordlist"])
            if args.get("extensions"):
                cmd += ["-X", "." + ",.".join(args["extensions"].split(","))]
        else:
            return "ERROR: neither gobuster nor dirb found. Install one first."
        r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ffuf_fuzz":
        cmd = [
            _find_tool("ffuf"),
            "-u",
            args["url"],
            "-w",
            args["wordlist"],
            "-mc",
            "all",
        ]
        if args.get("method"):
            cmd += ["-X", args["method"]]
        if args.get("data"):
            cmd += ["-d", args["data"]]
        if args.get("filter_code"):
            cmd += ["-fc", args["filter_code"]]
        if args.get("filter_size"):
            cmd += ["-fs", args["filter_size"]]
        if args.get("headers"):
            for k, v in args["headers"].items():
                cmd += ["-H", f"{k}: {v}"]
        r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "nikto_scan":
        cmd = [_find_tool("nikto"), "-h", args["host"]]
        if args.get("port"):
            cmd += ["-p", str(args["port"])]
        if args.get("ssl"):
            cmd.append("-ssl")
        r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "whatweb_scan":
        cmd = [_find_tool("whatweb"), args["target"]]
        if args.get("aggression"):
            cmd += ["-a", str(args["aggression"])]
        r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "subfinder_enum":
        cmd = [_find_tool("subfinder"), "-d", args["domain"], "-silent"]
        if args.get("sources"):
            cmd += ["-sources", args["sources"]]
        r = _run_tool(cmd, timeout)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "httpx_probe":
        targets = args["targets"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            targets_file = f.name
        cmd = [
            _find_tool("httpx"),
            "-l",
            targets_file,
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
        ]
        if args.get("ports"):
            cmd += ["-p", args["ports"]]
        if args.get("path"):
            cmd += ["-path", args["path"]]
        r = _run_tool(cmd, timeout)
        try:
            os.unlink(targets_file)
        except Exception:
            pass
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
