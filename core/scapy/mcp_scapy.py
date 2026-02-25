#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP Scapy Server v1.0

    Network packet crafting, manipulation and analysis MCP server.
    Uses Scapy for packet-level operations.
    JSON-RPC 2.0 over stdio with Content-Length framing.

    Tools:
        - scapy_craft: Craft custom packet from layers
        - scapy_send: Send crafted packet(s)
        - scapy_sniff: Sniff packets with filter
        - scapy_traceroute: Traceroute to target
        - scapy_arp_scan: ARP scan local network
        - scapy_port_scan: TCP SYN port scan
        - scapy_dns_query: DNS query with custom server
        - scapy_ping: ICMP ping sweep
        - scapy_fuzz: Fuzz protocol fields
        - scapy_read_pcap: Read/analyze PCAP file
        - scapy_write_pcap: Write packets to PCAP
        - scapy_dissect: Dissect raw hex bytes
        - scapy_sr1: Send and receive one packet
        - scapy_tcp_handshake: Perform TCP 3-way handshake
        - scapy_fragment: Fragment packet to evade IDS

    Author: ThiagoFrag / LEVIATHAN VS
    Version: 1.0.0
================================================================================
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("leviathan-scapy-mcp")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-scapy-server"


def _run_scapy_script(script: str, timeout: int = 30) -> Dict:
    """Run a Scapy Python script and capture output."""
    python = sys.executable
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as f:
        full_script = (
            "import warnings\n"
            "warnings.filterwarnings('ignore')\n"
            "import logging\n"
            "logging.getLogger('scapy.runtime').setLevel(logging.ERROR)\n"
            "from scapy.all import *\n"
            "conf.verb = 0\n\n"
            f"{script}\n"
        )
        f.write(full_script)
        f.flush()
        tmppath = f.name

    try:
        proc = subprocess.run(
            [python, tmppath],
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
    finally:
        try:
            os.unlink(tmppath)
        except Exception:
            pass


TOOLS = [
    {
        "name": "scapy_craft",
        "description": "Monta pacote customizado a partir de camadas (Ether/IP/TCP/UDP/ICMP/Raw/DNS/ARP etc). Retorna representacao hex e resumo.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "layers": {
                    "type": "string",
                    "description": "Expressao Scapy do pacote. Ex: IP(dst='8.8.8.8')/TCP(dport=80,flags='S')",
                },
            },
            "required": ["layers"],
        },
    },
    {
        "name": "scapy_send",
        "description": "Envia pacote(s) customizado(s). Layer 3 (send) ou Layer 2 (sendp).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "layers": {
                    "type": "string",
                    "description": "Expressao Scapy do pacote",
                },
                "count": {
                    "type": "integer",
                    "description": "Numero de pacotes (default 1)",
                },
                "inter": {
                    "type": "number",
                    "description": "Intervalo entre pacotes em segundos",
                },
                "layer2": {
                    "type": "boolean",
                    "description": "Usar sendp (Layer 2) ao inves de send (Layer 3)",
                },
                "iface": {"type": "string", "description": "Interface de rede"},
            },
            "required": ["layers"],
        },
    },
    {
        "name": "scapy_sniff",
        "description": "Captura pacotes com filtro BPF e timeout",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": "Filtro BPF (ex: tcp port 80)",
                },
                "count": {"type": "integer", "description": "Numero maximo de pacotes"},
                "timeout": {
                    "type": "integer",
                    "description": "Timeout em segundos (default 10)",
                },
                "iface": {"type": "string", "description": "Interface de rede"},
                "output": {"type": "string", "description": "Salvar em PCAP (caminho)"},
            },
        },
    },
    {
        "name": "scapy_traceroute",
        "description": "Traceroute TCP/UDP/ICMP para host",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Host ou IP alvo"},
                "max_ttl": {
                    "type": "integer",
                    "description": "TTL maximo (default 30)",
                },
                "dport": {
                    "type": "integer",
                    "description": "Porta destino TCP (default 80)",
                },
                "timeout": {"type": "integer", "description": "Timeout por hop"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "scapy_arp_scan",
        "description": "ARP scan na rede local para descobrir hosts",
        "inputSchema": {
            "type": "object",
            "properties": {
                "network": {
                    "type": "string",
                    "description": "CIDR da rede (ex: 192.168.1.0/24)",
                },
                "timeout": {"type": "integer", "description": "Timeout em segundos"},
            },
            "required": ["network"],
        },
    },
    {
        "name": "scapy_port_scan",
        "description": "TCP SYN scan em host. Retorna portas abertas.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP ou hostname alvo"},
                "ports": {
                    "type": "string",
                    "description": "Portas (ex: 1-1024, 80,443,8080)",
                },
                "timeout": {"type": "integer", "description": "Timeout por porta"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "scapy_dns_query",
        "description": "Faz query DNS customizada (A, AAAA, MX, TXT, NS, SOA, CNAME)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Dominio para resolver"},
                "qtype": {
                    "type": "string",
                    "description": "Tipo de query (A, AAAA, MX, TXT, NS, SOA, CNAME)",
                },
                "server": {
                    "type": "string",
                    "description": "Servidor DNS (default 8.8.8.8)",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "scapy_ping",
        "description": "ICMP ping sweep em rede ou host",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Host, IP ou CIDR"},
                "count": {"type": "integer", "description": "Numero de pings por host"},
                "timeout": {"type": "integer", "description": "Timeout por ping"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "scapy_fuzz",
        "description": "Fuzz de campos de protocolo - gera pacotes com valores aleatorios",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP alvo"},
                "protocol": {
                    "type": "string",
                    "description": "Protocolo: TCP, UDP, ICMP, DNS",
                },
                "dport": {"type": "integer", "description": "Porta destino"},
                "count": {
                    "type": "integer",
                    "description": "Numero de pacotes fuzz (default 10)",
                },
            },
            "required": ["target", "protocol"],
        },
    },
    {
        "name": "scapy_read_pcap",
        "description": "Le e analisa arquivo PCAP, retorna resumo dos pacotes",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pcap_path": {
                    "type": "string",
                    "description": "Caminho do arquivo PCAP",
                },
                "count": {
                    "type": "integer",
                    "description": "Numero maximo de pacotes para mostrar",
                },
                "filter": {
                    "type": "string",
                    "description": "Filtro por protocolo ou IP",
                },
            },
            "required": ["pcap_path"],
        },
    },
    {
        "name": "scapy_write_pcap",
        "description": "Cria PCAP a partir de pacotes definidos",
        "inputSchema": {
            "type": "object",
            "properties": {
                "layers": {
                    "type": "string",
                    "description": "Expressao Scapy (pode ser lista)",
                },
                "output": {
                    "type": "string",
                    "description": "Caminho do arquivo PCAP de saida",
                },
            },
            "required": ["layers", "output"],
        },
    },
    {
        "name": "scapy_dissect",
        "description": "Dissecta bytes raw (hex) e mostra camadas do pacote",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hex_bytes": {
                    "type": "string",
                    "description": "Bytes em hexadecimal do pacote",
                },
                "layer": {
                    "type": "string",
                    "description": "Camada base: Ether, IP, TCP (default: Ether)",
                },
            },
            "required": ["hex_bytes"],
        },
    },
    {
        "name": "scapy_sr1",
        "description": "Envia pacote e espera uma resposta (send-receive-1)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "layers": {
                    "type": "string",
                    "description": "Expressao Scapy do pacote",
                },
                "timeout": {"type": "integer", "description": "Timeout em segundos"},
                "iface": {"type": "string", "description": "Interface de rede"},
            },
            "required": ["layers"],
        },
    },
    {
        "name": "scapy_tcp_handshake",
        "description": "Realiza TCP 3-way handshake manual com host:porta",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP alvo"},
                "dport": {"type": "integer", "description": "Porta destino"},
                "timeout": {"type": "integer"},
            },
            "required": ["target", "dport"],
        },
    },
    {
        "name": "scapy_fragment",
        "description": "Fragmenta pacote IP para evasao de IDS/firewall",
        "inputSchema": {
            "type": "object",
            "properties": {
                "layers": {
                    "type": "string",
                    "description": "Expressao Scapy do pacote",
                },
                "fragsize": {
                    "type": "integer",
                    "description": "Tamanho de cada fragmento em bytes (default 8)",
                },
                "send": {
                    "type": "boolean",
                    "description": "Enviar fragmentos (true) ou apenas mostrar (false)",
                },
            },
            "required": ["layers"],
        },
    },
]


async def dispatch_tool(name: str, args: Dict) -> str:
    if name == "scapy_craft":
        script = f"""
pkt = {args['layers']}
print(pkt.summary())
print('---')
pkt.show()
print('---')
print('Hex:', bytes(pkt).hex())
print('Length:', len(pkt), 'bytes')
"""
        r = _run_scapy_script(script)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "scapy_send":
        layers = args["layers"]
        count = args.get("count", 1)
        inter = args.get("inter", 0)
        iface = args.get("iface", "")
        layer2 = args.get("layer2", False)
        func = "sendp" if layer2 else "send"
        iface_arg = f", iface='{iface}'" if iface else ""
        script = f"""
pkt = {layers}
{func}(pkt, count={count}, inter={inter}{iface_arg})
print(f'Sent {count} packet(s) via {func}')
print('Packet:', pkt.summary())
"""
        r = _run_scapy_script(script, timeout=30 + count)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "scapy_sniff":
        bpf = args.get("filter", "")
        count = args.get("count", 50)
        timeout = args.get("timeout", 10)
        iface = args.get("iface", "")
        output = args.get("output", "")
        iface_arg = f", iface='{iface}'" if iface else ""
        filter_arg = f", filter='{bpf}'" if bpf else ""
        script = f"""
pkts = sniff(count={count}, timeout={timeout}{filter_arg}{iface_arg})
print(f'Captured {{len(pkts)}} packets')
print('---')
for i, p in enumerate(pkts[:30]):
    print(f'[{{i+1}}] {{p.summary()}}')
if len(pkts) > 30:
    print(f'... and {{len(pkts) - 30}} more')
"""
        if output:
            script += f"\nwrpcap('{output.replace(chr(92), '/')}', pkts)\nprint(f'Saved to {output}')\n"
        r = _run_scapy_script(script, timeout=timeout + 15)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "scapy_traceroute":
        target = args["target"]
        max_ttl = args.get("max_ttl", 30)
        dport = args.get("dport", 80)
        timeout = args.get("timeout", 2)
        script = f"""
ans, unans = traceroute('{target}', maxttl={max_ttl}, dport={dport}, timeout={timeout})
print(f'Traceroute to {target} (maxttl={max_ttl}, dport={dport})')
print('---')
for snd, rcv in ans:
    print(f'TTL={{snd.ttl:3d}} -> {{rcv.src:20s}} ({{rcv.sprintf("%IP.proto%")}})')
"""
        r = _run_scapy_script(script, timeout=max_ttl * timeout + 15)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "scapy_arp_scan":
        network = args["network"]
        timeout = args.get("timeout", 3)
        script = f"""
ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst='{network}'), timeout={timeout})
print(f'ARP Scan: {network}')
print(f'Found {{len(ans)}} hosts')
print('---')
for snd, rcv in ans:
    print(f'{{rcv.sprintf("%ARP.psrc%"):20s}} {{rcv.sprintf("%Ether.src%")}}')
"""
        r = _run_scapy_script(script, timeout=timeout + 15)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "scapy_port_scan":
        target = args["target"]
        ports = args.get(
            "ports",
            "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443",
        )
        timeout = args.get("timeout", 2)
        # Parse port ranges
        script = f"""
import re
ports_str = '{ports}'
port_list = []
for part in ports_str.split(','):
    part = part.strip()
    if '-' in part:
        a, b = part.split('-', 1)
        port_list.extend(range(int(a), int(b)+1))
    else:
        port_list.append(int(part))

print(f'SYN Scan: {target} ({{len(port_list)}} ports)')
print('---')
open_ports = []
ans, unans = sr(IP(dst='{target}')/TCP(dport=port_list, flags='S'), timeout={timeout})
for snd, rcv in ans:
    if rcv.haslayer(TCP):
        if rcv[TCP].flags == 0x12:  # SYN-ACK
            open_ports.append(snd[TCP].dport)
            print(f'  {{snd[TCP].dport:5d}}/tcp  OPEN')
        elif rcv[TCP].flags == 0x14:  # RST-ACK
            pass  # closed
for snd in unans:
    pass  # filtered

print(f'---')
print(f'Open: {{len(open_ports)}} | Closed: {{len(ans) - len(open_ports)}} | Filtered: {{len(unans)}}')
"""
        r = _run_scapy_script(script, timeout=timeout * 5 + 30)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "scapy_dns_query":
        domain = args["domain"]
        qtype = args.get("qtype", "A")
        server = args.get("server", "8.8.8.8")
        script = f"""
pkt = IP(dst='{server}')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname='{domain}', qtype='{qtype}'))
resp = sr1(pkt, timeout=5)
if resp and resp.haslayer(DNS):
    dns = resp[DNS]
    print(f'DNS Query: {domain} ({qtype}) via {server}')
    print(f'Answers: {{dns.ancount}}')
    print('---')
    for i in range(dns.ancount):
        rr = dns.an[i] if hasattr(dns.an, '__getitem__') else dns.an
        print(f'  {{rr.rrname.decode() if isinstance(rr.rrname, bytes) else rr.rrname}} -> {{rr.rdata}}  TTL={{rr.ttl}}')
        if not hasattr(dns.an, '__getitem__'):
            break
else:
    print('No DNS response received')
"""
        r = _run_scapy_script(script, timeout=10)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "scapy_ping":
        target = args["target"]
        count = args.get("count", 4)
        timeout = args.get("timeout", 2)
        script = f"""
ans, unans = sr(IP(dst='{target}')/ICMP(), timeout={timeout}, retry=0)
print(f'Ping {target}')
print(f'Received: {{len(ans)}} | Lost: {{len(unans)}}')
print('---')
for snd, rcv in ans:
    rtt = (rcv.time - snd.sent_time) * 1000
    print(f'  Reply from {{rcv.src}}: bytes={{len(rcv)}} time={{rtt:.1f}}ms ttl={{rcv.ttl}}')
"""
        r = _run_scapy_script(script, timeout=timeout + 15)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "scapy_fuzz":
        target = args["target"]
        proto = args.get("protocol", "TCP").upper()
        dport = args.get("dport", 80)
        count = args.get("count", 10)
        proto_map = {
            "TCP": f"fuzz(TCP(dport={dport}))",
            "UDP": f"fuzz(UDP(dport={dport}))",
            "ICMP": "fuzz(ICMP())",
            "DNS": f"fuzz(UDP(dport=53)/DNS())",
        }
        fuzz_layer = proto_map.get(proto, f"fuzz(TCP(dport={dport}))")
        script = f"""
print(f'Fuzzing {target} with {proto} x {count} packets')
for i in range({count}):
    pkt = IP(dst='{target}')/{fuzz_layer}
    send(pkt)
    print(f'  [{{i+1}}] Sent: {{pkt.summary()}}')
print('Done')
"""
        r = _run_scapy_script(script, timeout=count * 2 + 15)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "scapy_read_pcap":
        pcap = args["pcap_path"].replace("\\", "/")
        count = args.get("count", 50)
        filt = args.get("filter", "")
        script = f"""
pkts = rdpcap('{pcap}')
print(f'PCAP: {pcap}')
print(f'Total packets: {{len(pkts)}}')
print('---')
shown = 0
for i, p in enumerate(pkts):
    if shown >= {count}:
        break
    summary = p.summary()
"""
        if filt:
            script += (
                f"    if '{filt}'.lower() not in summary.lower():\n        continue\n"
            )
        script += f"""    shown += 1
    print(f'[{{i+1}}] {{summary}}')
if len(pkts) > shown:
    print(f'... showing {{shown}}/{{{{}}}}'.format(len(pkts)))
"""
        r = _run_scapy_script(script, timeout=30)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "scapy_write_pcap":
        layers = args["layers"]
        output = args["output"].replace("\\", "/")
        script = f"""
pkt = {layers}
if isinstance(pkt, Packet):
    pkt = [pkt]
wrpcap('{output}', pkt)
print(f'Written {{len(pkt) if hasattr(pkt, "__len__") else 1}} packet(s) to {output}')
"""
        r = _run_scapy_script(script)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "scapy_dissect":
        hex_bytes = args["hex_bytes"].replace(" ", "").replace(":", "")
        layer = args.get("layer", "Ether")
        script = f"""
raw_bytes = bytes.fromhex('{hex_bytes}')
pkt = {layer}(raw_bytes)
pkt.show()
print('---')
print('Summary:', pkt.summary())
print('Length:', len(pkt), 'bytes')
"""
        r = _run_scapy_script(script)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "scapy_sr1":
        layers = args["layers"]
        timeout = args.get("timeout", 5)
        iface = args.get("iface", "")
        iface_arg = f", iface='{iface}'" if iface else ""
        script = f"""
pkt = {layers}
print('Sending:', pkt.summary())
resp = sr1(pkt, timeout={timeout}{iface_arg})
if resp:
    print('Response:', resp.summary())
    print('---')
    resp.show()
else:
    print('No response received within {timeout}s')
"""
        r = _run_scapy_script(script, timeout=timeout + 10)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "scapy_tcp_handshake":
        target = args["target"]
        dport = args["dport"]
        timeout = args.get("timeout", 5)
        script = f"""
import random
sport = random.randint(1024, 65535)
seq = random.randint(0, 2**32 - 1)

print(f'TCP Handshake: {target}:{dport}')
print(f'  Source port: {{sport}}, Initial seq: {{seq}}')
print('---')

# SYN
syn = IP(dst='{target}')/TCP(sport=sport, dport={dport}, flags='S', seq=seq)
print(f'[1] SYN -> {{syn.summary()}}')
syn_ack = sr1(syn, timeout={timeout})

if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12:
    print(f'[2] SYN-ACK <- {{syn_ack.summary()}}')
    # ACK
    ack = IP(dst='{target}')/TCP(sport=sport, dport={dport}, flags='A',
            seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
    send(ack)
    print(f'[3] ACK -> {{ack.summary()}}')
    print('Handshake COMPLETE')
    # RST to clean up
    rst = IP(dst='{target}')/TCP(sport=sport, dport={dport}, flags='RA',
            seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
    send(rst)
    print('[*] RST sent (cleanup)')
elif syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x14:
    print(f'[2] RST <- Port {dport} is CLOSED')
else:
    print('[2] No response - port may be filtered')
"""
        r = _run_scapy_script(script, timeout=timeout + 15)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "scapy_fragment":
        layers = args["layers"]
        fragsize = args.get("fragsize", 8)
        do_send = args.get("send", False)
        script = f"""
pkt = {layers}
frags = fragment(pkt, fragsize={fragsize})
print(f'Original: {{pkt.summary()}} ({{len(pkt)}} bytes)')
print(f'Fragments: {{len(frags)}} (fragsize={fragsize})')
print('---')
for i, f in enumerate(frags):
    print(f'  [{{i+1}}] offset={{f[IP].frag*8}} flags={{f.sprintf("%IP.flags%")}} len={{len(f)}}')
"""
        if do_send:
            script += """
for f in frags:
    send(f)
print('All fragments sent')
"""
        r = _run_scapy_script(script, timeout=15)
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
