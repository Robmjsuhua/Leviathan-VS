#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - mitmproxy MCP Server v1.0.0
    MITM Proxy Interception & Traffic Manipulation

    Controla mitmproxy/mitmdump para interceptar, modificar e analisar
    trafego HTTPS em tempo real. Complementa Burp Suite com automacao Python.

    Ferramentas: 14
    Autor: ThiagoFrag
    Versao: 1.0.0
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
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stderr)])
logger = logging.getLogger("leviathan-mitmproxy")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-mitmproxy-server"

MITMDUMP = shutil.which("mitmdump") or "mitmdump"
MITMPROXY = shutil.which("mitmproxy") or "mitmproxy"
MITMWEB = shutil.which("mitmweb") or "mitmweb"

TOOLS: List[Dict] = [
    {
        "name": "mitm_start_proxy",
        "description": "Inicia proxy mitmproxy em background (intercepta HTTPS)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "listen_host": {"type": "string", "description": "Host para escutar (default: 0.0.0.0)"},
                "listen_port": {"type": "integer", "description": "Porta do proxy (default: 8080)"},
                "mode": {"type": "string", "enum": ["regular", "transparent", "socks5", "reverse"], "description": "Modo do proxy"},
                "reverse_url": {"type": "string", "description": "URL para modo reverse (ex: https://api.target.com)"},
                "save_file": {"type": "string", "description": "Salvar fluxo em arquivo (.flow)"},
                "script": {"type": "string", "description": "Script Python mitmproxy para carregar"},
                "ssl_insecure": {"type": "boolean", "description": "Ignorar erros SSL do upstream"},
            },
            "required": [],
        },
    },
    {
        "name": "mitm_stop_proxy",
        "description": "Para o proxy mitmproxy em execucao",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "mitm_dump_traffic",
        "description": "Captura trafego por tempo determinado e retorna resumo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "duration": {"type": "integer", "description": "Segundos para capturar (default: 30)"},
                "filter": {"type": "string", "description": "Filtro de fluxo mitmproxy (ex: ~d api.target.com)"},
                "port": {"type": "integer", "description": "Porta do proxy (default: 8080)"},
                "output_file": {"type": "string", "description": "Salvar captura em arquivo"},
            },
            "required": [],
        },
    },
    {
        "name": "mitm_read_flow",
        "description": "Le e analisa arquivo de fluxo .flow salvo anteriormente",
        "inputSchema": {
            "type": "object",
            "properties": {
                "flow_file": {"type": "string", "description": "Caminho do arquivo .flow"},
                "filter": {"type": "string", "description": "Filtro para aplicar (opcional)"},
                "format": {"type": "string", "enum": ["summary", "detail", "har"], "description": "Formato de saida"},
            },
            "required": ["flow_file"],
        },
    },
    {
        "name": "mitm_create_script",
        "description": "Gera script Python para mitmproxy (interceptar, modificar, replay)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["intercept", "modify_header", "modify_body", "block", "redirect", "log", "inject_js", "replace_response", "custom"], "description": "Tipo de script"},
                "target_domain": {"type": "string", "description": "Dominio alvo (opcional)"},
                "target_path": {"type": "string", "description": "Path regex alvo (opcional)"},
                "header_name": {"type": "string", "description": "Nome do header para modify_header"},
                "header_value": {"type": "string", "description": "Valor do header"},
                "find": {"type": "string", "description": "Texto para encontrar no body (modify_body)"},
                "replace": {"type": "string", "description": "Texto de substituicao (modify_body)"},
                "redirect_url": {"type": "string", "description": "URL de redirecionamento"},
                "js_code": {"type": "string", "description": "Codigo JS para injetar (inject_js)"},
                "custom_code": {"type": "string", "description": "Codigo Python customizado"},
                "output_path": {"type": "string", "description": "Onde salvar o script"},
            },
            "required": ["type"],
        },
    },
    {
        "name": "mitm_replay",
        "description": "Replay de requests capturados (client ou server replay)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "flow_file": {"type": "string", "description": "Arquivo .flow com requests para replay"},
                "mode": {"type": "string", "enum": ["client", "server"], "description": "Client replay (re-envia) ou server replay (serve respostas)"},
                "count": {"type": "integer", "description": "Numero de vezes para replay (default: 1)"},
            },
            "required": ["flow_file"],
        },
    },
    {
        "name": "mitm_export_har",
        "description": "Exporta fluxo capturado para formato HAR (HTTP Archive)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "flow_file": {"type": "string", "description": "Arquivo .flow para converter"},
                "output_file": {"type": "string", "description": "Arquivo HAR de saida"},
            },
            "required": ["flow_file"],
        },
    },
    {
        "name": "mitm_install_cert",
        "description": "Gera e instrui instalacao do certificado CA do mitmproxy",
        "inputSchema": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Device ADB para push do cert (opcional)"},
                "format": {"type": "string", "enum": ["pem", "p12", "der"], "description": "Formato do certificado"},
            },
            "required": [],
        },
    },
    {
        "name": "mitm_extract_credentials",
        "description": "Extrai credenciais (tokens, cookies, auth headers) do fluxo capturado",
        "inputSchema": {
            "type": "object",
            "properties": {
                "flow_file": {"type": "string", "description": "Arquivo .flow para analisar"},
                "types": {"type": "array", "items": {"type": "string"}, "description": "Tipos: bearer, cookie, basic, api_key, custom"},
            },
            "required": ["flow_file"],
        },
    },
    {
        "name": "mitm_modify_live",
        "description": "Injeta regra de modificacao no proxy ativo (header/body/status)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["add_header", "remove_header", "modify_body", "set_status", "inject_cookie"], "description": "Acao de modificacao"},
                "domain_filter": {"type": "string", "description": "Dominio alvo"},
                "key": {"type": "string", "description": "Nome do header/cookie"},
                "value": {"type": "string", "description": "Valor"},
            },
            "required": ["action"],
        },
    },
    {
        "name": "mitm_map_endpoints",
        "description": "Mapeia todos endpoints unicos do fluxo capturado (API discovery)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "flow_file": {"type": "string", "description": "Arquivo .flow para mapear"},
                "domain_filter": {"type": "string", "description": "Filtrar por dominio"},
                "include_params": {"type": "boolean", "description": "Incluir parametros na listagem"},
            },
            "required": ["flow_file"],
        },
    },
    {
        "name": "mitm_diff_responses",
        "description": "Compara respostas de dois fluxos (detectar mudancas de comportamento)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "flow_a": {"type": "string", "description": "Primeiro arquivo .flow"},
                "flow_b": {"type": "string", "description": "Segundo arquivo .flow"},
                "url_filter": {"type": "string", "description": "Filtrar por URL"},
            },
            "required": ["flow_a", "flow_b"],
        },
    },
    {
        "name": "mitm_generate_curl",
        "description": "Converte requests capturados para comandos curl reprodutiveis",
        "inputSchema": {
            "type": "object",
            "properties": {
                "flow_file": {"type": "string", "description": "Arquivo .flow"},
                "filter": {"type": "string", "description": "Filtro de fluxo"},
                "max_requests": {"type": "integer", "description": "Max requests para converter (default: 20)"},
            },
            "required": ["flow_file"],
        },
    },
    {
        "name": "mitm_status",
        "description": "Verifica status do mitmproxy (rodando, portas, versao)",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
]


_proxy_process: Optional[subprocess.Popen] = None


def _run_cmd(args: List[str], timeout: int = 60) -> Dict:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
        return {"success": r.returncode == 0, "stdout": r.stdout[:8000], "stderr": r.stderr[:4000], "returncode": r.returncode}
    except subprocess.TimeoutExpired:
        return {"success": False, "stdout": "", "stderr": f"Timeout apos {timeout}s", "returncode": -1}
    except FileNotFoundError:
        return {"success": False, "stdout": "", "stderr": f"Comando nao encontrado: {args[0]}", "returncode": -1}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e), "returncode": -1}


def _generate_mitm_script(stype: str, args: Dict) -> str:
    """Gera codigo Python para mitmproxy addon."""
    domain = args.get("target_domain", "")
    path_regex = args.get("target_path", "")
    domain_check = f'    if "{domain}" not in flow.request.pretty_host:\n            return' if domain else ""

    if stype == "intercept":
        return f'''from mitmproxy import http
import json, datetime

class Interceptor:
    def __init__(self):
        self.log = []

    def request(self, flow: http.HTTPFlow):
{domain_check}
        entry = {{
            "timestamp": str(datetime.datetime.now()),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": dict(flow.request.headers),
            "body": flow.request.get_text()[:2000] if flow.request.content else None,
        }}
        self.log.append(entry)
        print(f"[INTERCEPT] {{flow.request.method}} {{flow.request.pretty_url}}")

    def response(self, flow: http.HTTPFlow):
{domain_check}
        print(f"[RESPONSE] {{flow.response.status_code}} {{flow.request.pretty_url}}")

addons = [Interceptor()]
'''
    elif stype == "modify_header":
        hname = args.get("header_name", "X-Custom")
        hval = args.get("header_value", "modified")
        return f'''from mitmproxy import http

class HeaderModifier:
    def request(self, flow: http.HTTPFlow):
{domain_check}
        flow.request.headers["{hname}"] = "{hval}"
        print(f"[MOD] Added header {hname} to {{flow.request.pretty_url}}")

    def response(self, flow: http.HTTPFlow):
{domain_check}
        flow.response.headers["{hname}"] = "{hval}"

addons = [HeaderModifier()]
'''
    elif stype == "modify_body":
        find = args.get("find", "")
        replace = args.get("replace", "")
        return f'''from mitmproxy import http

class BodyModifier:
    def response(self, flow: http.HTTPFlow):
{domain_check}
        if flow.response.content:
            original = flow.response.get_text()
            modified = original.replace("{find}", "{replace}")
            if original != modified:
                flow.response.set_text(modified)
                print(f"[MOD] Modified body of {{flow.request.pretty_url}}")

addons = [BodyModifier()]
'''
    elif stype == "block":
        return f'''from mitmproxy import http

class Blocker:
    def request(self, flow: http.HTTPFlow):
{domain_check}
        flow.response = http.Response.make(403, b"Blocked by Leviathan", {{"Content-Type": "text/plain"}})
        print(f"[BLOCK] {{flow.request.pretty_url}}")

addons = [Blocker()]
'''
    elif stype == "redirect":
        rurl = args.get("redirect_url", "https://example.com")
        return f'''from mitmproxy import http

class Redirector:
    def request(self, flow: http.HTTPFlow):
{domain_check}
        flow.response = http.Response.make(302, b"", {{"Location": "{rurl}"}})
        print(f"[REDIRECT] {{flow.request.pretty_url}} -> {rurl}")

addons = [Redirector()]
'''
    elif stype == "log":
        return f'''from mitmproxy import http
import json
from pathlib import Path

class Logger:
    def __init__(self):
        self.log_file = Path("mitm_log.jsonl")

    def request(self, flow: http.HTTPFlow):
{domain_check}
        entry = {{
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": dict(flow.request.headers),
        }}
        with self.log_file.open("a") as f:
            f.write(json.dumps(entry) + "\\n")

    def response(self, flow: http.HTTPFlow):
{domain_check}
        entry = {{
            "url": flow.request.pretty_url,
            "status": flow.response.status_code,
            "size": len(flow.response.content) if flow.response.content else 0,
        }}
        with self.log_file.open("a") as f:
            f.write(json.dumps(entry) + "\\n")

addons = [Logger()]
'''
    elif stype == "inject_js":
        js = args.get("js_code", "alert('injected')")
        return f'''from mitmproxy import http

class JSInjector:
    def response(self, flow: http.HTTPFlow):
{domain_check}
        if "text/html" in (flow.response.headers.get("content-type", "")):
            html = flow.response.get_text()
            inject = '<script>{js}</script>'
            html = html.replace("</body>", inject + "</body>")
            flow.response.set_text(html)
            print(f"[INJECT] JS injected into {{flow.request.pretty_url}}")

addons = [JSInjector()]
'''
    elif stype == "replace_response":
        return f'''from mitmproxy import http

class ResponseReplacer:
    def response(self, flow: http.HTTPFlow):
{domain_check}
        # Customize replacement logic
        flow.response = http.Response.make(200, b'{{"status":"modified","by":"leviathan"}}', {{"Content-Type":"application/json"}})
        print(f"[REPLACE] {{flow.request.pretty_url}}")

addons = [ResponseReplacer()]
'''
    else:
        return args.get("custom_code", "# Custom mitmproxy addon\nfrom mitmproxy import http\n\nclass Custom:\n    def request(self, flow: http.HTTPFlow):\n        pass\n\naddons = [Custom()]\n")


async def dispatch_tool(name: str, args: Dict) -> str:
    global _proxy_process

    if name == "mitm_start_proxy":
        if _proxy_process and _proxy_process.poll() is None:
            return json.dumps({"success": False, "error": "Proxy ja rodando. Use mitm_stop_proxy primeiro."})
        cmd = [MITMDUMP]
        host = args.get("listen_host", "0.0.0.0")
        port = args.get("listen_port", 8080)
        cmd += ["--listen-host", host, "--listen-port", str(port)]
        mode = args.get("mode", "regular")
        if mode == "transparent":
            cmd += ["--mode", "transparent"]
        elif mode == "socks5":
            cmd += ["--mode", "socks5"]
        elif mode == "reverse":
            cmd += ["--mode", f"reverse:{args.get('reverse_url', 'https://localhost')}"]
        if args.get("save_file"):
            cmd += ["-w", args["save_file"]]
        if args.get("script"):
            cmd += ["-s", args["script"]]
        if args.get("ssl_insecure"):
            cmd += ["--ssl-insecure"]
        try:
            _proxy_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            await asyncio.sleep(1)
            if _proxy_process.poll() is not None:
                err = _proxy_process.stderr.read().decode("utf-8", errors="replace")[:2000]
                return json.dumps({"success": False, "error": f"Proxy falhou: {err}"})
            return json.dumps({"success": True, "pid": _proxy_process.pid, "host": host, "port": port, "mode": mode})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    elif name == "mitm_stop_proxy":
        if _proxy_process and _proxy_process.poll() is None:
            _proxy_process.terminate()
            _proxy_process.wait(timeout=5)
            _proxy_process = None
            return json.dumps({"success": True, "message": "Proxy parado"})
        return json.dumps({"success": False, "message": "Nenhum proxy rodando"})

    elif name == "mitm_dump_traffic":
        duration = args.get("duration", 30)
        cmd = [MITMDUMP, "--listen-port", str(args.get("port", 8080))]
        if args.get("filter"):
            cmd += [args["filter"]]
        if args.get("output_file"):
            cmd += ["-w", args["output_file"]]
        r = _run_cmd(cmd, timeout=duration + 5)
        return json.dumps(r, indent=2)

    elif name == "mitm_read_flow":
        cmd = [MITMDUMP, "-n", "-r", args["flow_file"]]
        if args.get("filter"):
            cmd += [args["filter"]]
        fmt = args.get("format", "summary")
        if fmt == "detail":
            cmd += ["--flow-detail", "3"]
        elif fmt == "har":
            cmd += ["--set", "hardump=output.har"]
        r = _run_cmd(cmd, timeout=60)
        return json.dumps(r, indent=2)

    elif name == "mitm_create_script":
        code = _generate_mitm_script(args["type"], args)
        output = args.get("output_path")
        if output:
            Path(output).write_text(code, encoding="utf-8")
            return json.dumps({"success": True, "script_path": output, "type": args["type"], "lines": code.count("\n") + 1})
        return json.dumps({"success": True, "script": code, "type": args["type"]})

    elif name == "mitm_replay":
        mode = args.get("mode", "client")
        cmd = [MITMDUMP, "-n"]
        if mode == "client":
            cmd += ["--client-replay", args["flow_file"]]
        else:
            cmd += ["--server-replay", args["flow_file"]]
        r = _run_cmd(cmd, timeout=60)
        return json.dumps(r, indent=2)

    elif name == "mitm_export_har":
        out = args.get("output_file", args["flow_file"].replace(".flow", ".har"))
        cmd = [MITMDUMP, "-n", "-r", args["flow_file"], "--set", f"hardump={out}"]
        r = _run_cmd(cmd, timeout=60)
        return json.dumps({**r, "output": out}, indent=2)

    elif name == "mitm_install_cert":
        cert_dir = Path.home() / ".mitmproxy"
        cert_pem = cert_dir / "mitmproxy-ca-cert.pem"
        if not cert_pem.exists():
            return json.dumps({"success": False, "error": "Certificado nao encontrado. Inicie o mitmproxy uma vez para gerar."})
        result = {"cert_path": str(cert_pem), "instructions": []}
        device = args.get("device")
        if device:
            # Push para Android
            adb = shutil.which("adb") or "adb"
            r = _run_cmd([adb, "-s", device, "push", str(cert_pem), "/sdcard/Download/mitmproxy-ca-cert.pem"])
            result["adb_push"] = r
            result["instructions"].append("No Android: Settings > Security > Install from storage > selecionar o cert")
        else:
            result["instructions"] = [
                f"Certificado em: {cert_pem}",
                "Android: adb push cert /sdcard/ > Settings > Security > Install",
                "iOS: navegar para mitm.it no browser > instalar perfil",
                "Windows: certutil -addstore Root cert.pem",
                "Browser: importar em chrome://settings/certificates",
            ]
        return json.dumps(result, indent=2)

    elif name == "mitm_extract_credentials":
        cmd = [MITMDUMP, "-n", "-r", args["flow_file"], "--flow-detail", "2"]
        r = _run_cmd(cmd, timeout=60)
        if not r["success"]:
            return json.dumps(r)
        creds = {"bearer": [], "cookies": [], "basic": [], "api_keys": [], "custom": []}
        import re
        for line in r["stdout"].splitlines():
            ll = line.lower()
            if "authorization: bearer" in ll:
                creds["bearer"].append(line.strip())
            elif "cookie:" in ll:
                creds["cookies"].append(line.strip()[:500])
            elif "authorization: basic" in ll:
                creds["basic"].append(line.strip())
            elif any(k in ll for k in ["x-api-key", "api-key", "apikey"]):
                creds["api_keys"].append(line.strip())
        return json.dumps(creds, indent=2)

    elif name == "mitm_modify_live":
        # Gera script one-shot e avisa para recarregar
        return json.dumps({"success": True, "note": "Use mitm_create_script + reiniciar proxy com -s script.py para modificacoes live"})

    elif name == "mitm_map_endpoints":
        cmd = [MITMDUMP, "-n", "-r", args["flow_file"], "--flow-detail", "0"]
        r = _run_cmd(cmd, timeout=60)
        if not r["success"]:
            return json.dumps(r)
        endpoints = set()
        for line in r["stdout"].splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0] in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                url = parts[1]
                domain_filter = args.get("domain_filter", "")
                if domain_filter and domain_filter not in url:
                    continue
                if not args.get("include_params"):
                    url = url.split("?")[0]
                endpoints.add(f"{parts[0]} {url}")
        return json.dumps({"total": len(endpoints), "endpoints": sorted(endpoints)[:200]}, indent=2)

    elif name == "mitm_diff_responses":
        def read_flow(f):
            r = _run_cmd([MITMDUMP, "-n", "-r", f, "--flow-detail", "1"], timeout=60)
            return r.get("stdout", "")
        a = read_flow(args["flow_a"])
        b = read_flow(args["flow_b"])
        lines_a = set(a.splitlines())
        lines_b = set(b.splitlines())
        return json.dumps({"only_in_a": sorted(lines_a - lines_b)[:50], "only_in_b": sorted(lines_b - lines_a)[:50], "common": len(lines_a & lines_b)}, indent=2)

    elif name == "mitm_generate_curl":
        cmd = [MITMDUMP, "-n", "-r", args["flow_file"], "--flow-detail", "2"]
        if args.get("filter"):
            cmd += [args["filter"]]
        r = _run_cmd(cmd, timeout=60)
        return json.dumps({"note": "Parse stdout for request details to generate curl commands", **r}, indent=2)

    elif name == "mitm_status":
        ver = _run_cmd([MITMDUMP, "--version"], timeout=5)
        proxy_running = _proxy_process is not None and _proxy_process.poll() is None
        return json.dumps({
            "installed": ver["success"],
            "version": ver.get("stdout", "").strip(),
            "proxy_running": proxy_running,
            "proxy_pid": _proxy_process.pid if proxy_running else None,
            "paths": {"mitmdump": MITMDUMP, "mitmproxy": MITMPROXY, "mitmweb": MITMWEB},
        }, indent=2)

    return f"Ferramenta desconhecida: {name}"


class MCPServer:
    def __init__(self):
        self.running = True

    async def handle_request(self, request: Dict) -> Optional[Dict]:
        method = request.get("method", "")
        params = request.get("params", {})
        rid = request.get("id")

        if method == "initialize":
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": SERVER_NAME, "version": VERSION},
                "capabilities": {"tools": {"listChanged": True}, "resources": {"subscribe": False, "listChanged": True}, "prompts": {"listChanged": True}},
            }}
        elif method == "initialized":
            return None
        elif method == "shutdown":
            self.running = False
            return {"jsonrpc": "2.0", "id": rid, "result": None}
        elif method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
        elif method == "tools/call":
            nm = params.get("name", "")
            arguments = params.get("arguments", {})
            try:
                result = await dispatch_tool(nm, arguments)
                return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": result}]}}
            except Exception as e:
                return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": f"ERRO: {e}"}], "isError": True}}
        elif method == "resources/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"resources": []}}
        elif method == "prompts/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"prompts": []}}
        elif method.startswith("notifications/"):
            return None
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Method not found: {method}"}}

    async def run(self):
        logger.info(f"{SERVER_NAME} v{VERSION} iniciado ({len(TOOLS)} tools)")
        if sys.platform == "win32":
            import msvcrt
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)
        while self.running:
            try:
                header = await reader.readline()
                if not header:
                    break
                if header.strip().startswith(b"Content-Length:"):
                    length = int(header.strip().split(b":")[1])
                    await reader.readline()
                    data = await reader.readexactly(length)
                    request = json.loads(data.decode("utf-8"))
                    response = await self.handle_request(request)
                    if response:
                        body = json.dumps(response).encode("utf-8")
                        msg = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8") + body
                        sys.stdout.buffer.write(msg)
                        sys.stdout.buffer.flush()
            except Exception as e:
                logger.error(f"Erro no loop: {e}")
                continue


if __name__ == "__main__":
    asyncio.run(MCPServer().run())
