#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP Burp Suite Server v1.0

    Burp Suite REST API integration MCP server.
    Interfaces with Burp Suite Professional/Community via REST API.
    JSON-RPC 2.0 over stdio with Content-Length framing.

    Tools:
        - burp_scan: Start active scan on target URL
        - burp_spider: Spider/crawl a target URL
        - burp_sitemap: Get sitemap contents
        - burp_issues: Get scan issues/findings
        - burp_proxy_history: Get proxy history
        - burp_intruder_attack: Configure and launch intruder attack
        - burp_repeater_send: Send request via repeater
        - burp_decoder_encode: Encode payload (base64, URL, HTML)
        - burp_decoder_decode: Decode payload
        - burp_target_scope: Manage target scope
        - burp_export_report: Export scan report
        - burp_proxy_intercept: Toggle proxy interception
        - burp_search_responses: Search in HTTP responses
        - burp_get_config: Get Burp configuration
        - burp_set_config: Set Burp configuration

    Author: ThiagoFrag / LEVIATHAN VS
    Version: 1.0.0
================================================================================
"""

import asyncio
import base64
import html
import json
import logging
import os
import sys
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("leviathan-burpsuite-mcp")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-burpsuite-server"

BURP_API_URL = os.environ.get("BURP_API_URL", "http://127.0.0.1:1337")
BURP_API_KEY = os.environ.get("BURP_API_KEY", "")


def _api_request(
    method: str, path: str, data: Optional[Dict] = None, timeout: int = 30
) -> Dict:
    url = f"{BURP_API_URL}/v0.1/{path}"
    if BURP_API_KEY:
        sep = "&" if "?" in url else "?"
        url += f"{sep}apikey={BURP_API_KEY}"
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read().decode("utf-8", errors="replace")
            if content:
                return {"success": True, "data": json.loads(content)}
            return {"success": True, "data": {"status": resp.status}}
    except urllib.error.HTTPError as e:
        body_err = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return {"success": False, "error": f"HTTP {e.code}: {body_err}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


TOOLS = [
    {
        "name": "burp_scan",
        "description": "Inicia active scan em URL alvo via Burp Suite",
        "inputSchema": {
            "type": "object",
            "properties": {
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "URLs alvo",
                },
                "scope_config": {
                    "type": "object",
                    "description": "Configuracao de escopo (opcional)",
                },
            },
            "required": ["urls"],
        },
    },
    {
        "name": "burp_spider",
        "description": "Inicia spider/crawl em URL alvo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "max_depth": {"type": "integer"},
                "max_children": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "burp_sitemap",
        "description": "Obtem conteudo do sitemap",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url_prefix": {
                    "type": "string",
                    "description": "Filtro de URL (opcional)",
                },
                "max_items": {
                    "type": "integer",
                    "description": "Maximo de itens (default: 100)",
                },
            },
        },
    },
    {
        "name": "burp_issues",
        "description": "Obtem issues/vulnerabilidades encontradas",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url_prefix": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["high", "medium", "low", "info"],
                },
                "max_items": {"type": "integer"},
            },
        },
    },
    {
        "name": "burp_proxy_history",
        "description": "Obtem historico do proxy Burp",
        "inputSchema": {
            "type": "object",
            "properties": {
                "max_items": {
                    "type": "integer",
                    "description": "Max items (default: 50)",
                },
                "url_filter": {"type": "string"},
            },
        },
    },
    {
        "name": "burp_intruder_attack",
        "description": "Configura e lanca ataque Intruder",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request": {"type": "string", "description": "HTTP request raw"},
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "use_https": {"type": "boolean"},
                "positions": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Posicoes payload",
                },
                "payloads": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["request", "host"],
        },
    },
    {
        "name": "burp_repeater_send",
        "description": "Envia request via Repeater",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request": {"type": "string", "description": "HTTP request raw"},
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "use_https": {"type": "boolean"},
            },
            "required": ["request", "host"],
        },
    },
    {
        "name": "burp_decoder_encode",
        "description": "Codifica payload (base64, url, html)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "data": {"type": "string"},
                "encoding": {"type": "string", "enum": ["base64", "url", "html"]},
            },
            "required": ["data", "encoding"],
        },
    },
    {
        "name": "burp_decoder_decode",
        "description": "Decodifica payload",
        "inputSchema": {
            "type": "object",
            "properties": {
                "data": {"type": "string"},
                "encoding": {"type": "string", "enum": ["base64", "url", "html"]},
            },
            "required": ["data", "encoding"],
        },
    },
    {
        "name": "burp_target_scope",
        "description": "Gerencia target scope - add/remove/list",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["add", "remove", "list"]},
                "url": {"type": "string"},
            },
            "required": ["action"],
        },
    },
    {
        "name": "burp_export_report",
        "description": "Exporta relatorio de scan",
        "inputSchema": {
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "enum": ["html", "xml"],
                    "description": "Formato do relatorio",
                },
                "output_path": {"type": "string"},
            },
            "required": ["output_path"],
        },
    },
    {
        "name": "burp_proxy_intercept",
        "description": "Liga/desliga interceptação do proxy",
        "inputSchema": {
            "type": "object",
            "properties": {"enabled": {"type": "boolean"}},
            "required": ["enabled"],
        },
    },
    {
        "name": "burp_search_responses",
        "description": "Busca texto em respostas HTTP capturadas",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "regex": {"type": "boolean"},
                "max_results": {"type": "integer"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "burp_get_config",
        "description": "Obtem configuracao do Burp (ou secao especifica)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "section": {
                    "type": "string",
                    "description": "Secao: proxy, scanner, spider, intruder, etc",
                }
            },
        },
    },
    {
        "name": "burp_set_config",
        "description": "Define configuracao do Burp",
        "inputSchema": {
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "description": "Objeto de configuracao JSON",
                }
            },
            "required": ["config"],
        },
    },
]


async def dispatch_tool(name: str, args: Dict) -> str:
    if name == "burp_scan":
        urls = args.get("urls", [])
        scan_config = {"urls": urls}
        scope = args.get("scope_config")
        if scope:
            scan_config["scope"] = scope
        r = _api_request("POST", "scan", scan_config, timeout=60)
        if r["success"]:
            return json.dumps(
                {"status": "scan_started", "urls": urls, "response": r["data"]},
                indent=2,
            )
        return f"ERROR: {r['error']}"

    elif name == "burp_spider":
        url = args["url"]
        spider_data = {"urls": [url]}
        if args.get("max_depth"):
            spider_data["max_link_depth"] = args["max_depth"]
        if args.get("max_children"):
            spider_data["max_children"] = args["max_children"]
        r = _api_request("POST", "scan", spider_data)
        return (
            json.dumps({"status": "spider_started", "url": url}, indent=2)
            if r["success"]
            else f"ERROR: {r['error']}"
        )

    elif name == "burp_sitemap":
        r = _api_request("GET", "sitemap")
        if not r["success"]:
            return f"ERROR: {r['error']}"
        items = (
            r["data"]
            if isinstance(r["data"], list)
            else r["data"].get("items", [r["data"]])
        )
        prefix = args.get("url_prefix", "")
        if prefix:
            items = [i for i in items if prefix.lower() in json.dumps(i).lower()]
        max_items = args.get("max_items", 100)
        return json.dumps(items[:max_items], indent=2)

    elif name == "burp_issues":
        r = _api_request("GET", "scan/issues")
        if not r["success"]:
            r = _api_request("GET", "knowledge_base/issue_definitions")
        if not r["success"]:
            return f"ERROR: {r['error']}"
        issues = (
            r["data"]
            if isinstance(r["data"], list)
            else r["data"].get("issues", [r["data"]])
        )
        prefix = args.get("url_prefix", "")
        severity = args.get("severity", "")
        if prefix:
            issues = [i for i in issues if prefix.lower() in json.dumps(i).lower()]
        if severity:
            issues = [
                i for i in issues if i.get("severity", "").lower() == severity.lower()
            ]
        max_items = args.get("max_items", 100)
        return json.dumps(issues[:max_items], indent=2)

    elif name == "burp_proxy_history":
        r = _api_request("GET", "proxy/history")
        if not r["success"]:
            return f"ERROR: {r['error']}"
        items = r["data"] if isinstance(r["data"], list) else [r["data"]]
        url_filter = args.get("url_filter", "")
        if url_filter:
            items = [i for i in items if url_filter.lower() in json.dumps(i).lower()]
        max_items = args.get("max_items", 50)
        return json.dumps(items[:max_items], indent=2)

    elif name == "burp_intruder_attack":
        payload = {
            "request": args["request"],
            "host": args["host"],
            "port": args.get("port", 443 if args.get("use_https", True) else 80),
            "use_https": args.get("use_https", True),
        }
        if args.get("positions"):
            payload["positions"] = args["positions"]
        if args.get("payloads"):
            payload["payloads"] = args["payloads"]
        r = _api_request("POST", "intruder/attack", payload)
        return json.dumps(r, indent=2)

    elif name == "burp_repeater_send":
        payload = {
            "request": args["request"],
            "host": args["host"],
            "port": args.get("port", 443 if args.get("use_https", True) else 80),
            "use_https": args.get("use_https", True),
        }
        r = _api_request("POST", "repeater/send", payload, timeout=60)
        return json.dumps(r, indent=2)

    elif name == "burp_decoder_encode":
        data = args["data"]
        enc = args["encoding"]
        if enc == "base64":
            return base64.b64encode(data.encode()).decode()
        elif enc == "url":
            return urllib.parse.quote(data, safe="")
        elif enc == "html":
            return html.escape(data)
        return data

    elif name == "burp_decoder_decode":
        data = args["data"]
        enc = args["encoding"]
        if enc == "base64":
            return base64.b64decode(data.encode()).decode("utf-8", errors="replace")
        elif enc == "url":
            return urllib.parse.unquote(data)
        elif enc == "html":
            return html.unescape(data)
        return data

    elif name == "burp_target_scope":
        action = args["action"]
        if action == "add":
            r = _api_request("PUT", "target/scope", {"url": args.get("url", "")})
            return json.dumps(r, indent=2)
        elif action == "remove":
            r = _api_request("DELETE", "target/scope", {"url": args.get("url", "")})
            return json.dumps(r, indent=2)
        else:
            r = _api_request("GET", "target/scope")
            return json.dumps(r, indent=2)

    elif name == "burp_export_report":
        fmt = args.get("format", "html")
        r = _api_request("GET", f"report?format={fmt}")
        if r["success"]:
            output = args["output_path"]
            try:
                content = (
                    r["data"] if isinstance(r["data"], str) else json.dumps(r["data"])
                )
                with open(output, "w", encoding="utf-8") as f:
                    f.write(content)
                return f"Report exported to {output}"
            except Exception as e:
                return f"ERROR saving report: {e}"
        return f"ERROR: {r['error']}"

    elif name == "burp_proxy_intercept":
        enabled = args["enabled"]
        r = _api_request("PUT", "proxy/intercept", {"enabled": enabled})
        state = "enabled" if enabled else "disabled"
        return f"Proxy intercept {state}" if r["success"] else f"ERROR: {r['error']}"

    elif name == "burp_search_responses":
        query = args["query"]
        r = _api_request("GET", f"proxy/history")
        if not r["success"]:
            return f"ERROR: {r['error']}"
        items = r["data"] if isinstance(r["data"], list) else [r["data"]]
        matches = []
        for item in items:
            text = json.dumps(item)
            if query.lower() in text.lower():
                matches.append(item)
        max_results = args.get("max_results", 20)
        return json.dumps(matches[:max_results], indent=2)

    elif name == "burp_get_config":
        section = args.get("section", "")
        path = f"configuration/{section}" if section else "configuration"
        r = _api_request("GET", path)
        return json.dumps(r, indent=2)

    elif name == "burp_set_config":
        r = _api_request("PUT", "configuration", args["config"])
        return json.dumps(r, indent=2)

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
        logger.info(f"{SERVER_NAME} v{VERSION} started (API: {BURP_API_URL})")
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
