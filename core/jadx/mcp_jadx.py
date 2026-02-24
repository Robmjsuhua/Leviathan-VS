#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP Jadx Server v1.0

    Standalone Jadx MCP server for APK decompilation and analysis.
    JSON-RPC 2.0 over stdio with Content-Length framing.

    Tools:
        - jadx_decompile: Decompile APK/DEX to Java source
        - jadx_search_class: Search for class by name pattern
        - jadx_search_string: Search for string in decompiled source
        - jadx_search_method: Search for method calls
        - jadx_list_classes: List all classes in package
        - jadx_get_source: Get decompiled source of specific class
        - jadx_get_manifest: Extract AndroidManifest.xml
        - jadx_get_resources: List resources (strings.xml, etc)
        - jadx_get_permissions: Extract permissions from manifest
        - jadx_get_activities: List all activities/services/receivers
        - jadx_get_native_libs: List native libraries (.so files)
        - jadx_search_crypto: Search for crypto-related code
        - jadx_search_urls: Search for hardcoded URLs/IPs
        - jadx_search_keys: Search for potential API keys/secrets
        - jadx_export_smali: Export smali disassembly
        - jadx_diff: Compare two APKs

    Author: ThiagoFrag / LEVIATHAN VS
    Version: 1.0.0
================================================================================
"""

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("leviathan-jadx-mcp")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-jadx-server"
OUTPUT_BASE = Path(r"C:\Users\Kishi\Desktop\Trabalhos\jadx_output")


def _find_jadx() -> str:
    candidates = [
        shutil.which("jadx"),
        r"C:\Tools\jadx\bin\jadx.bat",
        r"C:\jadx\bin\jadx.bat",
        r"C:\Users\Kishi\Tools\jadx\bin\jadx.bat",
        r"C:\Program Files\jadx\bin\jadx.bat",
    ]
    for c in candidates:
        if c and Path(c).exists():
            return str(c)
    return "jadx"


JADX = _find_jadx()


def _run_jadx(args: List[str], timeout: int = 300) -> Dict:
    cmd = [JADX] + args
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


def _get_output_dir(apk_path: str) -> Path:
    name = Path(apk_path).stem
    return OUTPUT_BASE / name


def _search_in_dir(directory: Path, pattern: str, max_results: int = 100) -> List[Dict]:
    results = []
    if not directory.exists():
        return results
    pat = re.compile(pattern, re.IGNORECASE)
    for f in directory.rglob("*.java"):
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(content.splitlines(), 1):
                if pat.search(line):
                    results.append(
                        {
                            "file": str(f.relative_to(directory)),
                            "line": i,
                            "content": line.strip()[:200],
                        }
                    )
                    if len(results) >= max_results:
                        return results
        except Exception:
            continue
    return results


TOOLS = [
    {
        "name": "jadx_decompile",
        "description": "Decompila APK/DEX para codigo Java. Salva em diretorio de output",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK ou DEX"},
                "deobf": {
                    "type": "boolean",
                    "description": "Ativar deobfuscation (default true)",
                },
                "show_bad_code": {
                    "type": "boolean",
                    "description": "Mostrar codigo com falha de decompilacao",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "jadx_search_class",
        "description": "Busca classes por padrao de nome no APK decompilado",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "pattern": {
                    "type": "string",
                    "description": "Regex para nome de classe",
                },
            },
            "required": ["apk_path", "pattern"],
        },
    },
    {
        "name": "jadx_search_string",
        "description": "Busca string no codigo fonte decompilado",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "pattern": {
                    "type": "string",
                    "description": "Regex para buscar no codigo",
                },
                "max_results": {"type": "integer"},
            },
            "required": ["apk_path", "pattern"],
        },
    },
    {
        "name": "jadx_search_method",
        "description": "Busca chamadas de metodo no codigo decompilado",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "method_name": {"type": "string"},
            },
            "required": ["apk_path", "method_name"],
        },
    },
    {
        "name": "jadx_list_classes",
        "description": "Lista todas as classes em um pacote",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "package": {
                    "type": "string",
                    "description": "Nome do pacote (ex: com.game)",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "jadx_get_source",
        "description": "Obtem codigo fonte de uma classe especifica",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "class_path": {
                    "type": "string",
                    "description": "Path relativo da classe (ex: com/game/Main.java)",
                },
            },
            "required": ["apk_path", "class_path"],
        },
    },
    {
        "name": "jadx_get_manifest",
        "description": "Extrai e retorna AndroidManifest.xml decodificado",
        "inputSchema": {
            "type": "object",
            "properties": {"apk_path": {"type": "string"}},
            "required": ["apk_path"],
        },
    },
    {
        "name": "jadx_get_permissions",
        "description": "Extrai todas as permissoes do AndroidManifest",
        "inputSchema": {
            "type": "object",
            "properties": {"apk_path": {"type": "string"}},
            "required": ["apk_path"],
        },
    },
    {
        "name": "jadx_get_activities",
        "description": "Lista activities, services, receivers e providers do manifest",
        "inputSchema": {
            "type": "object",
            "properties": {"apk_path": {"type": "string"}},
            "required": ["apk_path"],
        },
    },
    {
        "name": "jadx_get_native_libs",
        "description": "Lista bibliotecas nativas (.so) do APK",
        "inputSchema": {
            "type": "object",
            "properties": {"apk_path": {"type": "string"}},
            "required": ["apk_path"],
        },
    },
    {
        "name": "jadx_search_crypto",
        "description": "Busca codigo relacionado a criptografia (AES, DES, XXTEA, RSA, MD5, SHA, etc)",
        "inputSchema": {
            "type": "object",
            "properties": {"apk_path": {"type": "string"}},
            "required": ["apk_path"],
        },
    },
    {
        "name": "jadx_search_urls",
        "description": "Busca URLs e IPs hardcoded no codigo",
        "inputSchema": {
            "type": "object",
            "properties": {"apk_path": {"type": "string"}},
            "required": ["apk_path"],
        },
    },
    {
        "name": "jadx_search_keys",
        "description": "Busca potenciais API keys, secrets, tokens hardcoded",
        "inputSchema": {
            "type": "object",
            "properties": {"apk_path": {"type": "string"}},
            "required": ["apk_path"],
        },
    },
    {
        "name": "jadx_get_resources",
        "description": "Lista recursos (strings.xml, arrays.xml, etc)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "resource_type": {
                    "type": "string",
                    "description": "Tipo: strings, arrays, styles, colors, dimens (default: strings)",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "jadx_export_smali",
        "description": "Exporta smali disassembly do APK (baksmali output)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "jadx_diff",
        "description": "Compara duas versoes de APK (classes adicionadas/removidas/modificadas)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path_a": {
                    "type": "string",
                    "description": "Caminho do APK versao A",
                },
                "apk_path_b": {
                    "type": "string",
                    "description": "Caminho do APK versao B",
                },
            },
            "required": ["apk_path_a", "apk_path_b"],
        },
    },
]


async def dispatch_tool(name: str, args: Dict) -> str:
    apk_path = args.get("apk_path", "")
    output_dir = _get_output_dir(apk_path) if apk_path else None
    sources_dir = output_dir / "sources" if output_dir else None
    resources_dir = output_dir / "resources" if output_dir else None

    if name == "jadx_decompile":
        OUTPUT_BASE.mkdir(parents=True, exist_ok=True)
        cmd_args = ["-d", str(output_dir)]
        if args.get("deobf", True):
            cmd_args.append("--deobf")
        if args.get("show_bad_code"):
            cmd_args.append("--show-bad-code")
        cmd_args.extend(["--threads-count", "4", apk_path])
        r = _run_jadx(cmd_args, timeout=600)
        if r["success"]:
            # Count files
            java_count = (
                len(list(output_dir.rglob("*.java"))) if output_dir.exists() else 0
            )
            return f"Decompiled successfully to {output_dir}\nJava files: {java_count}\n{r.get('stderr', '')}"
        return f"Failed: {r.get('error', r.get('stderr', ''))}"

    elif name == "jadx_search_class":
        if not sources_dir or not sources_dir.exists():
            return f"Sources not found. Run jadx_decompile first on {apk_path}"
        pattern = args["pattern"]
        results = []
        pat = re.compile(pattern, re.IGNORECASE)
        for f in sources_dir.rglob("*.java"):
            if pat.search(f.name) or pat.search(str(f.relative_to(sources_dir))):
                results.append(str(f.relative_to(sources_dir)))
        return "\n".join(results[:200]) if results else "No classes found"

    elif name == "jadx_search_string":
        if not sources_dir or not sources_dir.exists():
            return f"Sources not found. Run jadx_decompile first"
        results = _search_in_dir(
            sources_dir, args["pattern"], args.get("max_results", 100)
        )
        lines = [f"{r['file']}:{r['line']}: {r['content']}" for r in results]
        return "\n".join(lines) if lines else "No matches found"

    elif name == "jadx_search_method":
        if not sources_dir or not sources_dir.exists():
            return f"Sources not found"
        results = _search_in_dir(
            sources_dir, rf"\b{re.escape(args['method_name'])}\s*\(", 100
        )
        lines = [f"{r['file']}:{r['line']}: {r['content']}" for r in results]
        return "\n".join(lines) if lines else "No matches found"

    elif name == "jadx_list_classes":
        if not sources_dir or not sources_dir.exists():
            return "Sources not found"
        pkg = args.get("package", "").replace(".", os.sep)
        target = sources_dir / pkg if pkg else sources_dir
        if not target.exists():
            return f"Package not found: {args.get('package', '')}"
        files = sorted(f.relative_to(sources_dir) for f in target.rglob("*.java"))
        return "\n".join(str(f) for f in files[:500])

    elif name == "jadx_get_source":
        if not sources_dir or not sources_dir.exists():
            return "Sources not found"
        class_file = sources_dir / args["class_path"]
        if not class_file.exists():
            # Try with different separators
            alt = sources_dir / args["class_path"].replace("/", os.sep)
            if alt.exists():
                class_file = alt
            else:
                return f"File not found: {args['class_path']}"
        content = class_file.read_text(encoding="utf-8", errors="replace")
        return content[:100000]

    elif name == "jadx_get_manifest":
        manifest = resources_dir / "AndroidManifest.xml" if resources_dir else None
        if manifest and manifest.exists():
            return manifest.read_text(encoding="utf-8", errors="replace")
        # Try direct extraction from APK
        try:
            with zipfile.ZipFile(apk_path) as z:
                if "AndroidManifest.xml" in z.namelist():
                    return "Binary manifest found. Use jadx_decompile first for decoded version."
        except Exception:
            pass
        return "Manifest not found. Run jadx_decompile first."

    elif name == "jadx_get_permissions":
        manifest = resources_dir / "AndroidManifest.xml" if resources_dir else None
        if not manifest or not manifest.exists():
            return "Manifest not found. Run jadx_decompile first."
        content = manifest.read_text(encoding="utf-8", errors="replace")
        perms = re.findall(r'uses-permission\s+android:name="([^"]+)"', content)
        return "\n".join(sorted(set(perms))) if perms else "No permissions found"

    elif name == "jadx_get_activities":
        manifest = resources_dir / "AndroidManifest.xml" if resources_dir else None
        if not manifest or not manifest.exists():
            return "Manifest not found"
        content = manifest.read_text(encoding="utf-8", errors="replace")
        components = {
            "activities": re.findall(r'<activity[^>]*android:name="([^"]+)"', content),
            "services": re.findall(r'<service[^>]*android:name="([^"]+)"', content),
            "receivers": re.findall(r'<receiver[^>]*android:name="([^"]+)"', content),
            "providers": re.findall(r'<provider[^>]*android:name="([^"]+)"', content),
        }
        lines = []
        for comp_type, items in components.items():
            if items:
                lines.append(f"\n== {comp_type.upper()} ({len(items)}) ==")
                lines.extend(f"  {item}" for item in items)
        return "\n".join(lines) if lines else "No components found"

    elif name == "jadx_get_native_libs":
        try:
            with zipfile.ZipFile(apk_path) as z:
                libs = [
                    n
                    for n in z.namelist()
                    if n.startswith("lib/") and n.endswith(".so")
                ]
                if libs:
                    lines = []
                    for lib in sorted(libs):
                        info = z.getinfo(lib)
                        lines.append(f"{lib} ({info.file_size:,} bytes)")
                    return "\n".join(lines)
                return "No native libs found"
        except Exception as e:
            return f"Error reading APK: {e}"

    elif name == "jadx_search_crypto":
        if not sources_dir or not sources_dir.exists():
            return "Sources not found"
        pattern = r"(javax\.crypto|Cipher|SecretKey|AES|DES|RSA|MD5|SHA|HMAC|xxtea|XXTEA|MessageDigest|KeyGenerator|KeyPairGenerator|Mac\.getInstance|IvParameterSpec|GCMParameterSpec|PBEKeySpec)"
        results = _search_in_dir(sources_dir, pattern, 200)
        lines = [f"{r['file']}:{r['line']}: {r['content']}" for r in results]
        return "\n".join(lines) if lines else "No crypto-related code found"

    elif name == "jadx_search_urls":
        if not sources_dir or not sources_dir.exists():
            return "Sources not found"
        pattern = r'(https?://[^\s"\'<>]+|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?)'
        results = _search_in_dir(sources_dir, pattern, 200)
        lines = [f"{r['file']}:{r['line']}: {r['content']}" for r in results]
        return "\n".join(lines) if lines else "No URLs/IPs found"

    elif name == "jadx_search_keys":
        if not sources_dir or not sources_dir.exists():
            return "Sources not found"
        pattern = r'(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|apikey|app[_-]?secret|client[_-]?secret)\s*[=:]\s*["\'][^"\']{8,}'
        results = _search_in_dir(sources_dir, pattern, 100)
        lines = [f"{r['file']}:{r['line']}: {r['content']}" for r in results]
        return "\n".join(lines) if lines else "No hardcoded keys found"

    elif name == "jadx_get_resources":
        if not resources_dir or not resources_dir.exists():
            return "Resources not found"
        res_type = args.get("resource_type", "strings")
        target = resources_dir / "res" / "values" / f"{res_type}.xml"
        if target.exists():
            return target.read_text(encoding="utf-8", errors="replace")[:50000]
        # Try all values dirs
        results = (
            list((resources_dir / "res").rglob(f"{res_type}.xml"))
            if (resources_dir / "res").exists()
            else []
        )
        if results:
            return results[0].read_text(encoding="utf-8", errors="replace")[:50000]
        return f"Resource file not found: {res_type}.xml"

    elif name == "jadx_export_smali":
        OUTPUT_BASE.mkdir(parents=True, exist_ok=True)
        smali_dir = output_dir.parent / (output_dir.name + "_smali")
        cmd_args = ["-d", str(smali_dir), "--export-smali", apk_path]
        r = _run_jadx(cmd_args, timeout=600)
        if r["success"] or smali_dir.exists():
            smali_count = (
                len(list(smali_dir.rglob("*.smali"))) if smali_dir.exists() else 0
            )
            return f"Smali exported to {smali_dir}\nSmali files: {smali_count}\n{r.get('stderr', '')}"
        # Fallback: extract classes.dex manually and try baksmali
        try:
            with zipfile.ZipFile(apk_path) as z:
                dex_files = [n for n in z.namelist() if n.endswith(".dex")]
                smali_dir.mkdir(parents=True, exist_ok=True)
                for dex in dex_files:
                    z.extract(dex, str(smali_dir))
                return f"DEX files extracted to {smali_dir}: {', '.join(dex_files)}\n(Use baksmali for full disassembly)"
        except Exception as e:
            return (
                f"Failed: {r.get('error', r.get('stderr', ''))} | Fallback error: {e}"
            )

    elif name == "jadx_diff":
        apk_a = args["apk_path_a"]
        apk_b = args["apk_path_b"]
        dir_a = _get_output_dir(apk_a)
        dir_b = _get_output_dir(apk_b)
        src_a = dir_a / "sources"
        src_b = dir_b / "sources"
        if not src_a.exists():
            return f"Sources for APK A not found. Run jadx_decompile on {apk_a} first."
        if not src_b.exists():
            return f"Sources for APK B not found. Run jadx_decompile on {apk_b} first."
        files_a = {str(f.relative_to(src_a)) for f in src_a.rglob("*.java")}
        files_b = {str(f.relative_to(src_b)) for f in src_b.rglob("*.java")}
        added = sorted(files_b - files_a)
        removed = sorted(files_a - files_b)
        common = files_a & files_b
        modified = []
        for f in sorted(common):
            try:
                content_a = (src_a / f).read_text(encoding="utf-8", errors="replace")
                content_b = (src_b / f).read_text(encoding="utf-8", errors="replace")
                if content_a != content_b:
                    modified.append(f)
            except Exception:
                pass
        lines = [f"== APK Diff ==", f"A: {apk_a}", f"B: {apk_b}", ""]
        lines.append(f"Added in B ({len(added)}):")
        lines.extend(f"  + {f}" for f in added[:100])
        lines.append(f"\nRemoved from A ({len(removed)}):")
        lines.extend(f"  - {f}" for f in removed[:100])
        lines.append(f"\nModified ({len(modified)}):")
        lines.extend(f"  ~ {f}" for f in modified[:100])
        lines.append(
            f"\nTotal: {len(files_a)} -> {len(files_b)} files, {len(modified)} modified"
        )
        return "\n".join(lines)

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
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            try:
                result = await dispatch_tool(tool_name, tool_args)
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

        logger.info(f"{SERVER_NAME} v{VERSION} started (JADX: {JADX})")
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
