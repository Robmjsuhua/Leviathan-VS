#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP Wireshark/TShark Server v1.0

    Network capture & analysis MCP server using tshark CLI.
    JSON-RPC 2.0 over stdio with Content-Length framing.

    Tools:
        - ws_interfaces: List network interfaces
        - ws_capture: Start live capture
        - ws_read: Read pcap file with display filter
        - ws_stats_endpoints: Show endpoint statistics
        - ws_stats_conversations: Show conversation statistics
        - ws_stats_protocol: Protocol hierarchy statistics
        - ws_stats_io: I/O statistics
        - ws_follow_stream: Follow TCP/UDP/HTTP stream
        - ws_extract_fields: Extract specific fields
        - ws_filter: Apply display filter to pcap
        - ws_decode_as: Decode packets as specific protocol
        - ws_export_objects: Export HTTP/SMB/IMF objects
        - ws_find_packets: Find packets matching criteria
        - ws_dns_queries: Extract all DNS queries
        - ws_http_requests: Extract HTTP requests
        - ws_tls_handshakes: Extract TLS handshake info
        - ws_credentials: Search for cleartext credentials
        - ws_expert_info: Show expert info (errors, warnings, notes)
        - ws_rtp_streams: Analyze RTP streams
        - ws_voip_calls: Detect VoIP calls
        - ws_wireless_stats: Wireless/802.11 statistics
        - ws_geo_ip: GeoIP lookup for IPs in pcap
        - ws_packet_lengths: Packet length distribution

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
logger = logging.getLogger("leviathan-wireshark-mcp")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-wireshark-server"


def _find_tshark() -> str:
    candidates = [
        shutil.which("tshark"),
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        r"D:\Program Files\Wireshark\tshark.exe",
    ]
    for c in candidates:
        if c and Path(c).exists():
            return str(c)
    return "tshark"


TSHARK = _find_tshark()
CAPTURES_DIR = r"C:\Users\Kishi\Desktop\Trabalhos\captures"
Path(CAPTURES_DIR).mkdir(parents=True, exist_ok=True)


def _run_tshark(args: List[str], timeout: int = 120) -> Dict:
    cmd = [TSHARK] + args
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
        "name": "ws_interfaces",
        "description": "Lista interfaces de rede disponiveis para captura",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "ws_capture",
        "description": "Inicia captura de pacotes (tempo limitado)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Interface (nome ou numero)",
                },
                "output": {"type": "string", "description": "Arquivo pcap de saida"},
                "duration": {
                    "type": "integer",
                    "description": "Duracao em segundos (max 300)",
                },
                "filter": {
                    "type": "string",
                    "description": "Capture filter (BPF syntax)",
                },
                "count": {"type": "integer", "description": "Max pacotes"},
            },
            "required": ["interface", "output"],
        },
    },
    {
        "name": "ws_read",
        "description": "Le arquivo pcap com filtro de display",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "filter": {"type": "string", "description": "Display filter"},
                "limit": {
                    "type": "integer",
                    "description": "Max pacotes (default 100)",
                },
            },
            "required": ["file"],
        },
    },
    {
        "name": "ws_stats_endpoints",
        "description": "Estatisticas de endpoints do pcap",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "protocol": {
                    "type": "string",
                    "description": "ip, ipv6, tcp, udp, eth",
                },
            },
            "required": ["file"],
        },
    },
    {
        "name": "ws_stats_conversations",
        "description": "Estatisticas de conversas do pcap",
        "inputSchema": {
            "type": "object",
            "properties": {"file": {"type": "string"}, "protocol": {"type": "string"}},
            "required": ["file"],
        },
    },
    {
        "name": "ws_stats_protocol",
        "description": "Hierarquia de protocolos do pcap",
        "inputSchema": {
            "type": "object",
            "properties": {"file": {"type": "string"}},
            "required": ["file"],
        },
    },
    {
        "name": "ws_stats_io",
        "description": "Estatisticas I/O do pcap (pacotes por intervalo)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "interval": {
                    "type": "string",
                    "description": "Intervalo (ex: 1, 0.5, 10)",
                },
            },
            "required": ["file"],
        },
    },
    {
        "name": "ws_follow_stream",
        "description": "Segue stream TCP/UDP/HTTP",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "protocol": {"type": "string", "enum": ["tcp", "udp", "http", "tls"]},
                "index": {"type": "integer", "description": "Stream index"},
            },
            "required": ["file", "protocol", "index"],
        },
    },
    {
        "name": "ws_extract_fields",
        "description": "Extrai campos especificos dos pacotes",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "fields": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Lista de campos (ex: ip.src, tcp.port)",
                },
                "filter": {"type": "string"},
            },
            "required": ["file", "fields"],
        },
    },
    {
        "name": "ws_filter",
        "description": "Aplica display filter e salva resultado",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "filter": {"type": "string"},
                "output": {"type": "string"},
            },
            "required": ["file", "filter", "output"],
        },
    },
    {
        "name": "ws_decode_as",
        "description": "Decodifica pacotes como protocolo especifico",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "selector": {
                    "type": "string",
                    "description": "Ex: tcp.port==8080,http",
                },
                "limit": {"type": "integer"},
            },
            "required": ["file", "selector"],
        },
    },
    {
        "name": "ws_export_objects",
        "description": "Exporta objetos HTTP/SMB/DICOM/IMF/TFTP",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "protocol": {
                    "type": "string",
                    "enum": ["http", "smb", "dicom", "imf", "tftp"],
                },
                "output_dir": {"type": "string"},
            },
            "required": ["file", "protocol", "output_dir"],
        },
    },
    {
        "name": "ws_find_packets",
        "description": "Encontra pacotes por string ou hex pattern",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "pattern": {"type": "string"},
                "mode": {
                    "type": "string",
                    "enum": ["string", "hex"],
                    "description": "Modo de busca",
                },
            },
            "required": ["file", "pattern"],
        },
    },
    {
        "name": "ws_dns_queries",
        "description": "Extrai todas as queries DNS do pcap",
        "inputSchema": {
            "type": "object",
            "properties": {"file": {"type": "string"}},
            "required": ["file"],
        },
    },
    {
        "name": "ws_http_requests",
        "description": "Extrai requests HTTP (method, host, URI, user-agent)",
        "inputSchema": {
            "type": "object",
            "properties": {"file": {"type": "string"}, "filter": {"type": "string"}},
            "required": ["file"],
        },
    },
    {
        "name": "ws_tls_handshakes",
        "description": "Extrai info de TLS handshakes (SNI, cipher, version)",
        "inputSchema": {
            "type": "object",
            "properties": {"file": {"type": "string"}},
            "required": ["file"],
        },
    },
    {
        "name": "ws_credentials",
        "description": "Busca credenciais em texto claro (HTTP Basic, FTP, SMTP, POP3)",
        "inputSchema": {
            "type": "object",
            "properties": {"file": {"type": "string"}},
            "required": ["file"],
        },
    },
    {
        "name": "ws_expert_info",
        "description": "Mostra expert info (erros, warnings, notas)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["error", "warn", "note", "chat"],
                    "description": "Filtro de severidade",
                },
            },
            "required": ["file"],
        },
    },
    {
        "name": "ws_rtp_streams",
        "description": "Analisa streams RTP no pcap",
        "inputSchema": {
            "type": "object",
            "properties": {"file": {"type": "string"}},
            "required": ["file"],
        },
    },
    {
        "name": "ws_voip_calls",
        "description": "Detecta chamadas VoIP (SIP/RTP)",
        "inputSchema": {
            "type": "object",
            "properties": {"file": {"type": "string"}},
            "required": ["file"],
        },
    },
    {
        "name": "ws_wireless_stats",
        "description": "Estatisticas wireless 802.11",
        "inputSchema": {
            "type": "object",
            "properties": {"file": {"type": "string"}},
            "required": ["file"],
        },
    },
    {
        "name": "ws_geo_ip",
        "description": "GeoIP lookup para IPs no pcap",
        "inputSchema": {
            "type": "object",
            "properties": {"file": {"type": "string"}, "limit": {"type": "integer"}},
            "required": ["file"],
        },
    },
    {
        "name": "ws_packet_lengths",
        "description": "Distribuicao de tamanho de pacotes",
        "inputSchema": {
            "type": "object",
            "properties": {"file": {"type": "string"}},
            "required": ["file"],
        },
    },
]


async def dispatch_tool(name: str, args: Dict) -> str:

    if name == "ws_interfaces":
        r = _run_tshark(["-D"])
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "ws_capture":
        cmd = ["-i", args["interface"], "-w", args["output"]]
        duration = min(args.get("duration", 30), 300)
        cmd += ["-a", f"duration:{duration}"]
        if args.get("filter"):
            cmd += ["-f", args["filter"]]
        if args.get("count"):
            cmd += ["-c", str(args["count"])]
        r = _run_tshark(cmd, timeout=duration + 30)
        if Path(args["output"]).exists():
            size = Path(args["output"]).stat().st_size
            return f"Capture saved: {args['output']} ({size} bytes)"
        return r.get("error", r.get("stderr", "Capture failed"))

    elif name == "ws_read":
        limit = args.get("limit", 100)
        cmd = ["-r", args["file"], "-c", str(limit)]
        if args.get("filter"):
            cmd += ["-Y", args["filter"]]
        r = _run_tshark(cmd)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "ws_stats_endpoints":
        proto = args.get("protocol", "ip")
        r = _run_tshark(["-r", args["file"], "-q", "-z", f"endpoints,{proto}"])
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_stats_conversations":
        proto = args.get("protocol", "tcp")
        r = _run_tshark(["-r", args["file"], "-q", "-z", f"conv,{proto}"])
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_stats_protocol":
        r = _run_tshark(["-r", args["file"], "-q", "-z", "io,phs"])
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_stats_io":
        interval = args.get("interval", "1")
        r = _run_tshark(["-r", args["file"], "-q", "-z", f"io,stat,{interval}"])
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_follow_stream":
        proto = args["protocol"]
        idx = args["index"]
        r = _run_tshark(["-r", args["file"], "-q", "-z", f"follow,{proto},ascii,{idx}"])
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_extract_fields":
        cmd = ["-r", args["file"], "-T", "fields"]
        for f in args["fields"]:
            cmd += ["-e", f]
        if args.get("filter"):
            cmd += ["-Y", args["filter"]]
        cmd += ["-E", "header=y", "-E", "separator=\t"]
        r = _run_tshark(cmd)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_filter":
        r = _run_tshark(
            ["-r", args["file"], "-Y", args["filter"], "-w", args["output"]]
        )
        if Path(args["output"]).exists():
            return f"Filtered pcap: {args['output']} ({Path(args['output']).stat().st_size} bytes)"
        return r.get("error", r.get("stderr", "Filter failed"))

    elif name == "ws_decode_as":
        limit = args.get("limit", 50)
        r = _run_tshark(["-r", args["file"], "-d", args["selector"], "-c", str(limit)])
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_export_objects":
        Path(args["output_dir"]).mkdir(parents=True, exist_ok=True)
        r = _run_tshark(
            [
                "-r",
                args["file"],
                "--export-objects",
                f"{args['protocol']},{args['output_dir']}",
            ],
            timeout=180,
        )
        files = (
            list(Path(args["output_dir"]).iterdir())
            if Path(args["output_dir"]).exists()
            else []
        )
        return f"Exported {len(files)} objects to {args['output_dir']}\n" + "\n".join(
            f.name for f in files[:50]
        )

    elif name == "ws_find_packets":
        mode = args.get("mode", "string")
        if mode == "string":
            r = _run_tshark(
                [
                    "-r",
                    args["file"],
                    "-Y",
                    f'frame contains "{args["pattern"]}"',
                    "-c",
                    "50",
                ]
            )
        else:
            hex_pat = args["pattern"].replace(" ", "").lower()
            r = _run_tshark(
                ["-r", args["file"], "-Y", f"frame contains {{{hex_pat}}}", "-c", "50"]
            )
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_dns_queries":
        r = _run_tshark(
            [
                "-r",
                args["file"],
                "-Y",
                "dns.qry.name",
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-e",
                "ip.src",
                "-e",
                "dns.qry.name",
                "-e",
                "dns.qry.type",
                "-e",
                "dns.a",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
            ]
        )
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_http_requests":
        cmd = ["-r", args["file"], "-Y", "http.request"]
        if args.get("filter"):
            cmd[-1] = f"http.request && {args['filter']}"
        cmd += [
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "http.request.method",
            "-e",
            "http.host",
            "-e",
            "http.request.uri",
            "-e",
            "http.user_agent",
            "-E",
            "header=y",
            "-E",
            "separator=\t",
        ]
        r = _run_tshark(cmd)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_tls_handshakes":
        r = _run_tshark(
            [
                "-r",
                args["file"],
                "-Y",
                "tls.handshake.type==1",
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "tls.handshake.extensions_server_name",
                "-e",
                "tls.handshake.version",
                "-e",
                "tls.handshake.ciphersuite",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
            ]
        )
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_credentials":
        results = []
        # HTTP Basic Auth
        r = _run_tshark(
            [
                "-r",
                args["file"],
                "-Y",
                "http.authorization",
                "-T",
                "fields",
                "-e",
                "ip.src",
                "-e",
                "http.host",
                "-e",
                "http.authorization",
                "-c",
                "50",
            ]
        )
        if r["success"] and r["stdout"]:
            results.append("=== HTTP Authorization ===\n" + r["stdout"])
        # FTP credentials
        r = _run_tshark(
            [
                "-r",
                args["file"],
                "-Y",
                "ftp.request.command == USER || ftp.request.command == PASS",
                "-T",
                "fields",
                "-e",
                "ip.src",
                "-e",
                "ftp.request.command",
                "-e",
                "ftp.request.arg",
                "-c",
                "50",
            ]
        )
        if r["success"] and r["stdout"]:
            results.append("=== FTP Credentials ===\n" + r["stdout"])
        # SMTP Auth
        r = _run_tshark(
            ["-r", args["file"], "-Y", "smtp.req.command == AUTH", "-c", "20"]
        )
        if r["success"] and r["stdout"]:
            results.append("=== SMTP Auth ===\n" + r["stdout"])
        # POP3
        r = _run_tshark(
            [
                "-r",
                args["file"],
                "-Y",
                "pop.request.command == USER || pop.request.command == PASS",
                "-T",
                "fields",
                "-e",
                "ip.src",
                "-e",
                "pop.request.command",
                "-e",
                "pop.request.parameter",
                "-c",
                "20",
            ]
        )
        if r["success"] and r["stdout"]:
            results.append("=== POP3 Credentials ===\n" + r["stdout"])
        return "\n\n".join(results) if results else "No cleartext credentials found"

    elif name == "ws_expert_info":
        cmd = ["-r", args["file"], "-z", "expert"]
        if args.get("severity"):
            sev_map = {
                "error": "expert.severity==error",
                "warn": "expert.severity==warn",
                "note": "expert.severity==note",
                "chat": "expert.severity==chat",
            }
            cmd += ["-Y", sev_map.get(args["severity"], "")]
        r = _run_tshark(cmd)
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_rtp_streams":
        r = _run_tshark(["-r", args["file"], "-z", "rtp,streams", "-q"])
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_voip_calls":
        r = _run_tshark(["-r", args["file"], "-z", "sip,stat", "-q"])
        output = r["stdout"] if r["success"] else ""
        r2 = _run_tshark(
            [
                "-r",
                args["file"],
                "-Y",
                "sip.Method",
                "-T",
                "fields",
                "-e",
                "sip.Method",
                "-e",
                "sip.from.addr",
                "-e",
                "sip.to.addr",
                "-c",
                "50",
            ]
        )
        if r2["success"] and r2["stdout"]:
            output += "\n\n=== SIP Methods ===\n" + r2["stdout"]
        return output if output else "No VoIP calls found"

    elif name == "ws_wireless_stats":
        r = _run_tshark(["-r", args["file"], "-z", "wlan,stat", "-q"])
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_geo_ip":
        limit = args.get("limit", 50)
        r = _run_tshark(
            [
                "-r",
                args["file"],
                "-T",
                "fields",
                "-e",
                "ip.src",
                "-e",
                "ip.geoip.src_country",
                "-e",
                "ip.dst",
                "-e",
                "ip.geoip.dst_country",
                "-c",
                str(limit),
            ]
        )
        return r["stdout"] if r["success"] else r.get("error", "")

    elif name == "ws_packet_lengths":
        r = _run_tshark(["-r", args["file"], "-z", "plen,tree", "-q"])
        return r["stdout"] if r["success"] else r.get("error", "")

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
        logger.info(f"{SERVER_NAME} v{VERSION} started (tshark: {TSHARK})")
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
