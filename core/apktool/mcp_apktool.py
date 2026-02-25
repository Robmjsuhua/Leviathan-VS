#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - APKTool MCP Server v1.0.0
    APK Rebuild, Repackage & Signing

    Decompila, modifica smali, recompila e assina APKs.
    Complementa o JADX (somente leitura) com capacidade de rebuild.

    Ferramentas: 12
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("leviathan-apktool")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-apktool-server"

# Descobrir apktool
APKTOOL = shutil.which("apktool") or shutil.which("apktool.bat")
KEYTOOL = shutil.which("keytool") or "keytool"
JARSIGNER = shutil.which("jarsigner") or "jarsigner"
APKSIGNER = shutil.which("apksigner") or shutil.which("apksigner.bat")
ZIPALIGN = shutil.which("zipalign") or "zipalign"

TOOLS: List[Dict] = [
    {
        "name": "apktool_decode",
        "description": "Decompila APK para smali, resources e AndroidManifest.xml editaveis",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {
                    "type": "string",
                    "description": "Caminho do APK para decompilar",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Diretorio de saida (opcional)",
                },
                "no_src": {
                    "type": "boolean",
                    "description": "Pular decompilacao de smali (so resources)",
                },
                "no_res": {
                    "type": "boolean",
                    "description": "Pular decompilacao de resources (so smali)",
                },
                "force": {
                    "type": "boolean",
                    "description": "Sobrescrever diretorio existente",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "apktool_build",
        "description": "Recompila diretorio decompilado de volta para APK",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_dir": {
                    "type": "string",
                    "description": "Diretorio decompilado para recompilar",
                },
                "output_apk": {
                    "type": "string",
                    "description": "Caminho do APK de saida (opcional)",
                },
                "use_aapt2": {
                    "type": "boolean",
                    "description": "Usar aapt2 (mais moderno)",
                },
            },
            "required": ["source_dir"],
        },
    },
    {
        "name": "apktool_sign",
        "description": "Assina APK com keystore (cria debug keystore se necessario)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "APK para assinar"},
                "keystore": {
                    "type": "string",
                    "description": "Caminho do keystore (opcional, usa debug)",
                },
                "key_alias": {
                    "type": "string",
                    "description": "Alias da chave (default: debug)",
                },
                "store_pass": {
                    "type": "string",
                    "description": "Senha do keystore (default: android)",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "apktool_zipalign",
        "description": "Otimiza alinhamento do APK (necessario antes de instalar)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "APK para alinhar"},
                "output_apk": {
                    "type": "string",
                    "description": "APK de saida alinhado (opcional)",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "apktool_patch_smali",
        "description": "Aplica patch em arquivo smali (find & replace ou insercao)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "smali_path": {
                    "type": "string",
                    "description": "Caminho do arquivo .smali",
                },
                "find": {"type": "string", "description": "Texto para encontrar"},
                "replace": {"type": "string", "description": "Texto de substituicao"},
                "insert_after": {
                    "type": "string",
                    "description": "Inserir apos esta linha (alternativa a find/replace)",
                },
                "insert_text": {"type": "string", "description": "Texto para inserir"},
            },
            "required": ["smali_path"],
        },
    },
    {
        "name": "apktool_patch_manifest",
        "description": "Modifica AndroidManifest.xml (adicionar permissoes, debuggable, network-security)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest_path": {
                    "type": "string",
                    "description": "Caminho do AndroidManifest.xml",
                },
                "add_permissions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Permissoes para adicionar",
                },
                "set_debuggable": {
                    "type": "boolean",
                    "description": "Setar android:debuggable=true",
                },
                "allow_cleartext": {
                    "type": "boolean",
                    "description": "Permitir trafego HTTP cleartext",
                },
                "set_network_config": {
                    "type": "boolean",
                    "description": "Adicionar network-security-config para aceitar certs custom",
                },
            },
            "required": ["manifest_path"],
        },
    },
    {
        "name": "apktool_search_smali",
        "description": "Busca padrao em todos arquivos smali do projeto",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_dir": {
                    "type": "string",
                    "description": "Diretorio do projeto decompilado",
                },
                "pattern": {
                    "type": "string",
                    "description": "Padrao regex para buscar",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximo de resultados (default: 50)",
                },
            },
            "required": ["project_dir", "pattern"],
        },
    },
    {
        "name": "apktool_list_smali_classes",
        "description": "Lista todas as classes smali do projeto",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_dir": {
                    "type": "string",
                    "description": "Diretorio do projeto decompilado",
                },
                "filter": {
                    "type": "string",
                    "description": "Filtro por nome (opcional)",
                },
            },
            "required": ["project_dir"],
        },
    },
    {
        "name": "apktool_full_rebuild",
        "description": "Pipeline completo: build + zipalign + sign (pronto para instalar)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_dir": {
                    "type": "string",
                    "description": "Diretorio decompilado",
                },
                "output_apk": {"type": "string", "description": "APK final de saida"},
            },
            "required": ["source_dir"],
        },
    },
    {
        "name": "apktool_inject_smali",
        "description": "Injeta codigo smali customizado em um metodo existente",
        "inputSchema": {
            "type": "object",
            "properties": {
                "smali_path": {"type": "string", "description": "Arquivo smali alvo"},
                "method_name": {
                    "type": "string",
                    "description": "Nome do metodo para injetar",
                },
                "smali_code": {
                    "type": "string",
                    "description": "Codigo smali para injetar no inicio do metodo",
                },
            },
            "required": ["smali_path", "method_name", "smali_code"],
        },
    },
    {
        "name": "apktool_diff",
        "description": "Compara dois diretorios decompilados (diff de smali/resources)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "dir_a": {
                    "type": "string",
                    "description": "Primeiro diretorio decompilado",
                },
                "dir_b": {
                    "type": "string",
                    "description": "Segundo diretorio decompilado",
                },
                "smali_only": {
                    "type": "boolean",
                    "description": "Comparar somente arquivos smali",
                },
            },
            "required": ["dir_a", "dir_b"],
        },
    },
    {
        "name": "apktool_create_keystore",
        "description": "Cria keystore customizado para assinatura de APK",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keystore_path": {
                    "type": "string",
                    "description": "Caminho para salvar o keystore",
                },
                "alias": {
                    "type": "string",
                    "description": "Alias da chave (default: leviathan)",
                },
                "password": {
                    "type": "string",
                    "description": "Senha (default: leviathan)",
                },
                "validity": {
                    "type": "integer",
                    "description": "Validade em dias (default: 10000)",
                },
            },
            "required": ["keystore_path"],
        },
    },
]


def _run_cmd(args: List[str], timeout: int = 120) -> Dict:
    """Executa comando e retorna resultado."""
    try:
        r = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return {
            "success": r.returncode == 0,
            "stdout": r.stdout[:8000],
            "stderr": r.stderr[:4000],
            "returncode": r.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Timeout apos {timeout}s",
            "returncode": -1,
        }
    except FileNotFoundError:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Comando nao encontrado: {args[0]}",
            "returncode": -1,
        }
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e), "returncode": -1}


def _ensure_debug_keystore() -> str:
    """Garante que existe um keystore debug."""
    ks = Path.home() / ".android" / "debug.keystore"
    if ks.exists():
        return str(ks)
    ks.parent.mkdir(parents=True, exist_ok=True)
    _run_cmd(
        [
            KEYTOOL,
            "-genkey",
            "-v",
            "-keystore",
            str(ks),
            "-storepass",
            "android",
            "-alias",
            "androiddebugkey",
            "-keypass",
            "android",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "10000",
            "-dname",
            "CN=Debug,O=Android,C=US",
        ]
    )
    return str(ks)


import re as _re


async def dispatch_tool(name: str, args: Dict) -> str:
    """Despacha chamada de ferramenta."""

    if name == "apktool_decode":
        if not APKTOOL:
            return "ERRO: apktool nao encontrado no PATH. Instale: https://apktool.org/"
        cmd = [APKTOOL, "d", args["apk_path"]]
        if args.get("output_dir"):
            cmd += ["-o", args["output_dir"]]
        if args.get("no_src"):
            cmd += ["-s"]
        if args.get("no_res"):
            cmd += ["-r"]
        if args.get("force"):
            cmd += ["-f"]
        r = _run_cmd(cmd, timeout=300)
        return json.dumps(r, indent=2)

    elif name == "apktool_build":
        if not APKTOOL:
            return "ERRO: apktool nao encontrado no PATH"
        cmd = [APKTOOL, "b", args["source_dir"]]
        if args.get("output_apk"):
            cmd += ["-o", args["output_apk"]]
        if args.get("use_aapt2"):
            cmd += ["--use-aapt2"]
        r = _run_cmd(cmd, timeout=300)
        return json.dumps(r, indent=2)

    elif name == "apktool_sign":
        apk = args["apk_path"]
        ks = args.get("keystore") or _ensure_debug_keystore()
        alias = args.get("key_alias", "androiddebugkey")
        pw = args.get("store_pass", "android")
        if APKSIGNER:
            cmd = [
                APKSIGNER,
                "sign",
                "--ks",
                ks,
                "--ks-key-alias",
                alias,
                "--ks-pass",
                f"pass:{pw}",
                apk,
            ]
        else:
            cmd = [
                JARSIGNER,
                "-verbose",
                "-sigalg",
                "SHA256withRSA",
                "-digestalg",
                "SHA-256",
                "-keystore",
                ks,
                "-storepass",
                pw,
                apk,
                alias,
            ]
        r = _run_cmd(cmd)
        return json.dumps(r, indent=2)

    elif name == "apktool_zipalign":
        apk = args["apk_path"]
        out = args.get("output_apk", apk.replace(".apk", "_aligned.apk"))
        r = _run_cmd([ZIPALIGN, "-v", "4", apk, out])
        return json.dumps(r, indent=2)

    elif name == "apktool_patch_smali":
        path = Path(args["smali_path"])
        if not path.exists():
            return f"ERRO: Arquivo nao encontrado: {path}"
        content = path.read_text(encoding="utf-8")
        if args.get("find") and args.get("replace") is not None:
            new_content = content.replace(args["find"], args["replace"])
            count = content.count(args["find"])
            path.write_text(new_content, encoding="utf-8")
            return json.dumps(
                {"success": True, "replacements": count, "file": str(path)}
            )
        elif args.get("insert_after") and args.get("insert_text"):
            if args["insert_after"] in content:
                new_content = content.replace(
                    args["insert_after"],
                    args["insert_after"] + "\n" + args["insert_text"],
                )
                path.write_text(new_content, encoding="utf-8")
                return json.dumps(
                    {"success": True, "inserted": True, "file": str(path)}
                )
            return json.dumps(
                {"success": False, "error": "Texto de referencia nao encontrado"}
            )
        return json.dumps(
            {
                "success": False,
                "error": "Fornecer find+replace ou insert_after+insert_text",
            }
        )

    elif name == "apktool_patch_manifest":
        path = Path(args["manifest_path"])
        if not path.exists():
            return f"ERRO: Manifest nao encontrado: {path}"
        content = path.read_text(encoding="utf-8")
        changes = []
        if args.get("add_permissions"):
            for perm in args["add_permissions"]:
                perm_line = f'    <uses-permission android:name="{perm}"/>'
                if perm not in content:
                    content = content.replace(
                        "</manifest>", f"{perm_line}\n</manifest>"
                    )
                    changes.append(f"Added: {perm}")
        if args.get("set_debuggable"):
            if 'android:debuggable="true"' not in content:
                content = content.replace(
                    "<application", '<application android:debuggable="true"', 1
                )
                changes.append("Set debuggable=true")
        if args.get("allow_cleartext"):
            if "android:usesCleartextTraffic" not in content:
                content = content.replace(
                    "<application",
                    '<application android:usesCleartextTraffic="true"',
                    1,
                )
                changes.append("Allowed cleartext traffic")
        if args.get("set_network_config"):
            if "android:networkSecurityConfig" not in content:
                content = content.replace(
                    "<application",
                    '<application android:networkSecurityConfig="@xml/network_security_config"',
                    1,
                )
                changes.append("Added network security config reference")
                res_xml = path.parent / "res" / "xml"
                res_xml.mkdir(parents=True, exist_ok=True)
                nsc = res_xml / "network_security_config.xml"
                if not nsc.exists():
                    nsc.write_text(
                        '<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n    <base-config cleartextTrafficPermitted="true">\n        <trust-anchors>\n            <certificates src="system"/>\n            <certificates src="user"/>\n        </trust-anchors>\n    </base-config>\n</network-security-config>\n',
                        encoding="utf-8",
                    )
                    changes.append("Created network_security_config.xml")
        path.write_text(content, encoding="utf-8")
        return json.dumps({"success": True, "changes": changes})

    elif name == "apktool_search_smali":
        project = Path(args["project_dir"])
        pattern = _re.compile(args["pattern"], _re.IGNORECASE)
        max_r = args.get("max_results", 50)
        results = []
        for smali_file in project.rglob("*.smali"):
            try:
                text = smali_file.read_text(encoding="utf-8", errors="replace")
                for i, line in enumerate(text.splitlines(), 1):
                    if pattern.search(line):
                        results.append(
                            {
                                "file": str(smali_file.relative_to(project)),
                                "line": i,
                                "content": line.strip()[:200],
                            }
                        )
                        if len(results) >= max_r:
                            break
            except Exception:
                continue
            if len(results) >= max_r:
                break
        return json.dumps({"total": len(results), "results": results}, indent=2)

    elif name == "apktool_list_smali_classes":
        project = Path(args["project_dir"])
        filt = args.get("filter", "").lower()
        classes = []
        for f in project.rglob("*.smali"):
            rel = str(f.relative_to(project)).replace("\\", "/")
            cls_name = (
                rel.replace("smali/", "")
                .replace("smali_classes2/", "")
                .replace("smali_classes3/", "")
                .replace("/", ".")
                .replace(".smali", "")
            )
            if not filt or filt in cls_name.lower():
                classes.append(cls_name)
        classes.sort()
        return json.dumps({"total": len(classes), "classes": classes[:500]}, indent=2)

    elif name == "apktool_full_rebuild":
        src = args["source_dir"]
        out = args.get("output_apk", str(Path(src) / "dist" / "rebuilt_signed.apk"))
        steps = []
        # Build
        build_apk = str(Path(src) / "dist" / Path(src).name + ".apk")
        r = _run_cmd(
            [APKTOOL, "b", src] if APKTOOL else ["echo", "apktool not found"],
            timeout=300,
        )
        steps.append({"step": "build", **r})
        if not r["success"]:
            return json.dumps({"success": False, "steps": steps})
        # Find built APK
        dist = Path(src) / "dist"
        apks = list(dist.glob("*.apk"))
        if not apks:
            return json.dumps({"success": False, "error": "APK nao gerado no dist/"})
        built = str(apks[0])
        # Zipalign
        aligned = built.replace(".apk", "_aligned.apk")
        if ZIPALIGN:
            r = _run_cmd([ZIPALIGN, "-f", "4", built, aligned])
            steps.append({"step": "zipalign", **r})
            if r["success"]:
                built = aligned
        # Sign
        ks = _ensure_debug_keystore()
        if APKSIGNER:
            r = _run_cmd(
                [
                    APKSIGNER,
                    "sign",
                    "--ks",
                    ks,
                    "--ks-key-alias",
                    "androiddebugkey",
                    "--ks-pass",
                    "pass:android",
                    built,
                ]
            )
        else:
            r = _run_cmd(
                [
                    JARSIGNER,
                    "-sigalg",
                    "SHA256withRSA",
                    "-digestalg",
                    "SHA-256",
                    "-keystore",
                    ks,
                    "-storepass",
                    "android",
                    built,
                    "androiddebugkey",
                ]
            )
        steps.append({"step": "sign", **r})
        if out != built:
            shutil.copy2(built, out)
        return json.dumps({"success": True, "output": out, "steps": steps}, indent=2)

    elif name == "apktool_inject_smali":
        path = Path(args["smali_path"])
        if not path.exists():
            return f"ERRO: {path} nao encontrado"
        content = path.read_text(encoding="utf-8")
        method_sig = args["method_name"]
        # Encontrar .method e inserir apos .locals ou .registers
        idx = content.find(method_sig)
        if idx == -1:
            return json.dumps(
                {"success": False, "error": f"Metodo '{method_sig}' nao encontrado"}
            )
        # Achar proxima linha .locals ou .registers
        after_method = content[idx:]
        for marker in [".locals", ".registers"]:
            m_idx = after_method.find(marker)
            if m_idx != -1:
                eol = after_method.find("\n", m_idx)
                if eol != -1:
                    insert_pos = idx + eol + 1
                    new_content = (
                        content[:insert_pos]
                        + "\n    "
                        + args["smali_code"].replace("\n", "\n    ")
                        + "\n"
                        + content[insert_pos:]
                    )
                    path.write_text(new_content, encoding="utf-8")
                    return json.dumps(
                        {
                            "success": True,
                            "injected_at": insert_pos,
                            "method": method_sig,
                        }
                    )
        return json.dumps(
            {
                "success": False,
                "error": "Nao encontrou .locals/.registers apos o metodo",
            }
        )

    elif name == "apktool_diff":
        dir_a, dir_b = Path(args["dir_a"]), Path(args["dir_b"])
        ext_filter = "*.smali" if args.get("smali_only") else "*"
        files_a = {
            str(f.relative_to(dir_a)) for f in dir_a.rglob(ext_filter) if f.is_file()
        }
        files_b = {
            str(f.relative_to(dir_b)) for f in dir_b.rglob(ext_filter) if f.is_file()
        }
        only_a = sorted(files_a - files_b)
        only_b = sorted(files_b - files_a)
        common = files_a & files_b
        modified = []
        for f in sorted(common):
            try:
                ca = (dir_a / f).read_bytes()
                cb = (dir_b / f).read_bytes()
                if ca != cb:
                    modified.append(f)
            except Exception:
                pass
        return json.dumps(
            {
                "only_in_a": only_a[:100],
                "only_in_b": only_b[:100],
                "modified": modified[:200],
                "stats": {
                    "only_a": len(only_a),
                    "only_b": len(only_b),
                    "modified": len(modified),
                    "identical": len(common) - len(modified),
                },
            },
            indent=2,
        )

    elif name == "apktool_create_keystore":
        ks = args["keystore_path"]
        alias = args.get("alias", "leviathan")
        pw = args.get("password", "leviathan")
        validity = args.get("validity", 10000)
        r = _run_cmd(
            [
                KEYTOOL,
                "-genkey",
                "-v",
                "-keystore",
                ks,
                "-storepass",
                pw,
                "-alias",
                alias,
                "-keypass",
                pw,
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                str(validity),
                "-dname",
                "CN=Leviathan,O=Security,C=BR",
            ]
        )
        return json.dumps(r, indent=2)

    return f"Ferramenta desconhecida: {name}"


# ============================================================================
# MCP SERVER
# ============================================================================


class MCPServer:
    def __init__(self):
        self.running = True

    async def handle_request(self, request: Dict) -> Optional[Dict]:
        method = request.get("method", "")
        params = request.get("params", {})
        rid = request.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": SERVER_NAME, "version": VERSION},
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "resources": {"subscribe": False, "listChanged": True},
                        "prompts": {"listChanged": True},
                    },
                },
            }
        elif method == "initialized":
            return None
        elif method == "shutdown":
            self.running = False
            return {"jsonrpc": "2.0", "id": rid, "result": None}
        elif method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
        elif method == "tools/call":
            name = params.get("name", "")
            arguments = params.get("arguments", {})
            try:
                result = await dispatch_tool(name, arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {"content": [{"type": "text", "text": result}]},
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "content": [{"type": "text", "text": f"ERRO: {e}"}],
                        "isError": True,
                    },
                }
        elif method == "resources/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"resources": []}}
        elif method == "prompts/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"prompts": []}}
        elif method.startswith("notifications/"):
            return None
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    async def run(self):
        logger.info(f"{SERVER_NAME} v{VERSION} iniciado ({len(TOOLS)} tools)")
        if sys.platform == "win32":
            import msvcrt

            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(
            lambda: protocol, sys.stdin.buffer
        )

        while self.running:
            try:
                header = await reader.readline()
                if not header:
                    break
                if header.strip().startswith(b"Content-Length:"):
                    length = int(header.strip().split(b":")[1])
                    await reader.readline()  # empty line
                    data = await reader.readexactly(length)
                    request = json.loads(data.decode("utf-8"))
                    response = await self.handle_request(request)
                    if response:
                        body = json.dumps(response).encode("utf-8")
                        msg = (
                            f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
                            + body
                        )
                        sys.stdout.buffer.write(msg)
                        sys.stdout.buffer.flush()
            except Exception as e:
                logger.error(f"Erro no loop: {e}")
                continue


if __name__ == "__main__":
    asyncio.run(MCPServer().run())
