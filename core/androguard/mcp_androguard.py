#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - Androguard MCP Server v1.0.0
    Python-Native APK Static Analysis

    Analise estatica profunda de APK via androguard (Python).
    DEX parsing, call graphs, permission mapping, string analysis,
    certificate info, component enumeration, API call detection.

    Ferramentas: 15
    Autor: ThiagoFrag
    Versao: 1.0.0
================================================================================
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("leviathan-androguard")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-androguard-server"

# Tentar importar androguard
try:
    from androguard.core.bytecodes.apk import APK
    from androguard.misc import AnalyzeAPK

    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False
    logger.warning("androguard nao instalado. pip install androguard")

TOOLS: List[Dict] = [
    {
        "name": "ag_analyze",
        "description": "Analise completa do APK (permissoes, activities, services, receivers, providers, libs nativas)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"}
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "ag_permissions",
        "description": "Lista permissoes do APK com nivel de perigo e descricao",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"}
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "ag_components",
        "description": "Lista activities, services, receivers e providers com intent-filters",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"},
                "type": {
                    "type": "string",
                    "enum": ["activities", "services", "receivers", "providers", "all"],
                    "description": "Tipo de componente",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "ag_strings",
        "description": "Extrai todas strings do DEX (URLs, IPs, keys, paths, emails)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"},
                "filter": {
                    "type": "string",
                    "description": "Regex para filtrar strings (opcional)",
                },
                "min_length": {
                    "type": "integer",
                    "description": "Tamanho minimo da string (default: 5)",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "ag_certificate",
        "description": "Analisa certificado de assinatura do APK (issuer, validity, fingerprint)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"}
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "ag_classes",
        "description": "Lista todas classes do DEX com hierarquia de heranca",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"},
                "filter": {
                    "type": "string",
                    "description": "Filtro por nome (ex: com.game)",
                },
                "show_methods": {
                    "type": "boolean",
                    "description": "Incluir metodos de cada classe",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "ag_methods",
        "description": "Lista metodos de uma classe especifica com parametros e retorno",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"},
                "class_name": {
                    "type": "string",
                    "description": "Nome completo da classe (ex: Lcom/game/Main;)",
                },
            },
            "required": ["apk_path", "class_name"],
        },
    },
    {
        "name": "ag_api_calls",
        "description": "Detecta chamadas de API sensiveis (crypto, network, reflection, exec, file I/O)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"},
                "category": {
                    "type": "string",
                    "enum": [
                        "crypto",
                        "network",
                        "reflection",
                        "exec",
                        "file_io",
                        "sms",
                        "phone",
                        "location",
                        "camera",
                        "all",
                    ],
                    "description": "Categoria de API",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "ag_native_libs",
        "description": "Lista bibliotecas nativas (.so) com arquiteturas e tamanhos",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"}
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "ag_xrefs",
        "description": "Cross-references: quem chama um metodo/classe e quem ele chama",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"},
                "class_name": {"type": "string", "description": "Classe alvo"},
                "method_name": {
                    "type": "string",
                    "description": "Metodo alvo (opcional, senao mostra xrefs da classe)",
                },
            },
            "required": ["apk_path", "class_name"],
        },
    },
    {
        "name": "ag_search_code",
        "description": "Busca padrao no bytecode de todas classes (smali-level search)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"},
                "pattern": {
                    "type": "string",
                    "description": "Padrao para buscar (nome de metodo, string, classe)",
                },
            },
            "required": ["apk_path", "pattern"],
        },
    },
    {
        "name": "ag_intent_filters",
        "description": "Lista todos intent-filters (deeplinks, schemes, custom intents)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"}
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "ag_compare",
        "description": "Compara dois APKs (diff de permissoes, classes, components, strings)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_a": {"type": "string", "description": "Primeiro APK"},
                "apk_b": {"type": "string", "description": "Segundo APK"},
            },
            "required": ["apk_a", "apk_b"],
        },
    },
    {
        "name": "ag_exported_components",
        "description": "Lista componentes exportados (superficie de ataque IPC)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"}
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "ag_security_audit",
        "description": "Auditoria de seguranca automatica (permissoes perigosas, components expostos, crypto fraca, hardcoded secrets)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Caminho do APK"}
            },
            "required": ["apk_path"],
        },
    },
]

# Cache de APKs analisados
_cache: Dict[str, Any] = {}


def _get_apk(path: str):
    """Carrega APK com cache."""
    if path in _cache:
        return _cache[path]
    if not ANDROGUARD_AVAILABLE:
        return None
    try:
        a, d, dx = AnalyzeAPK(path)
        _cache[path] = (a, d, dx)
        return (a, d, dx)
    except Exception as e:
        logger.error(f"Erro ao analisar APK: {e}")
        return None


DANGEROUS_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.READ_PHONE_NUMBERS",
}

SENSITIVE_APIS = {
    "crypto": [
        "Ljavax/crypto/",
        "Ljava/security/",
        "Lorg/bouncycastle/",
        "xxtea",
        "AES",
        "DES",
        "RSA",
        "MD5",
        "SHA",
    ],
    "network": [
        "Ljava/net/URL",
        "Lokhttp3/",
        "Lorg/apache/http",
        "HttpURLConnection",
        "WebView",
        "loadUrl",
    ],
    "reflection": ["Ljava/lang/reflect/", "Class.forName", "getMethod", "invoke"],
    "exec": ["Runtime.getRuntime", "ProcessBuilder", "exec("],
    "file_io": [
        "FileInputStream",
        "FileOutputStream",
        "SharedPreferences",
        "SQLiteDatabase",
    ],
    "sms": ["SmsManager", "sendTextMessage", "READ_SMS"],
    "phone": ["TelephonyManager", "getDeviceId", "getLine1Number"],
    "location": ["LocationManager", "getLastKnownLocation", "requestLocationUpdates"],
    "camera": ["Camera", "CameraManager", "takePicture"],
}


async def dispatch_tool(name: str, args: Dict) -> str:
    if not ANDROGUARD_AVAILABLE:
        return json.dumps(
            {"error": "androguard nao instalado. Execute: pip install androguard"}
        )

    if name == "ag_analyze":
        result = _get_apk(args["apk_path"])
        if not result:
            return json.dumps({"error": "Falha ao analisar APK"})
        a, d, dx = result
        return json.dumps(
            {
                "package": a.get_package(),
                "app_name": a.get_app_name(),
                "version_name": a.get_androidversion_name(),
                "version_code": a.get_androidversion_code(),
                "min_sdk": a.get_min_sdk_version(),
                "target_sdk": a.get_target_sdk_version(),
                "permissions": a.get_permissions(),
                "activities": a.get_activities(),
                "services": a.get_services(),
                "receivers": a.get_receivers(),
                "providers": a.get_providers(),
                "main_activity": a.get_main_activity(),
                "is_signed": a.is_signed(),
                "native_libs": [f for f in a.get_files() if f.endswith(".so")],
                "dex_count": len(d) if isinstance(d, list) else 1,
            },
            indent=2,
            default=str,
        )

    elif name == "ag_permissions":
        result = _get_apk(args["apk_path"])
        if not result:
            return json.dumps({"error": "Falha ao analisar"})
        a, _, _ = result
        perms = a.get_permissions()
        classified = []
        for p in perms:
            classified.append(
                {
                    "permission": p,
                    "dangerous": p in DANGEROUS_PERMS,
                    "level": "dangerous" if p in DANGEROUS_PERMS else "normal",
                }
            )
        return json.dumps(
            {
                "total": len(perms),
                "dangerous": sum(1 for c in classified if c["dangerous"]),
                "permissions": classified,
            },
            indent=2,
        )

    elif name == "ag_components":
        result = _get_apk(args["apk_path"])
        if not result:
            return json.dumps({"error": "Falha"})
        a, _, _ = result
        ctype = args.get("type", "all")
        data = {}
        if ctype in ("activities", "all"):
            data["activities"] = a.get_activities()
        if ctype in ("services", "all"):
            data["services"] = a.get_services()
        if ctype in ("receivers", "all"):
            data["receivers"] = a.get_receivers()
        if ctype in ("providers", "all"):
            data["providers"] = a.get_providers()
        return json.dumps(data, indent=2, default=str)

    elif name == "ag_strings":
        result = _get_apk(args["apk_path"])
        if not result:
            return json.dumps({"error": "Falha"})
        _, d_list, _ = result
        min_len = args.get("min_length", 5)
        filt = args.get("filter", "")
        import re

        pattern = re.compile(filt, re.IGNORECASE) if filt else None
        strings = set()
        dexes = d_list if isinstance(d_list, list) else [d_list]
        for d in dexes:
            for s in d.get_strings():
                if len(s) >= min_len:
                    if not pattern or pattern.search(s):
                        strings.add(s)
        sorted_strings = sorted(strings)[:1000]
        # Classify
        urls = [
            s
            for s in sorted_strings
            if s.startswith("http://") or s.startswith("https://")
        ]
        ips = [s for s in sorted_strings if re.match(r"\d+\.\d+\.\d+\.\d+", s)]
        return json.dumps(
            {
                "total": len(strings),
                "urls": urls[:100],
                "ips": ips[:50],
                "strings": sorted_strings[:500],
            },
            indent=2,
        )

    elif name == "ag_certificate":
        result = _get_apk(args["apk_path"])
        if not result:
            return json.dumps({"error": "Falha"})
        a, _, _ = result
        certs = []
        for cert in a.get_certificates():
            certs.append(
                {
                    "issuer": str(cert.issuer),
                    "subject": str(cert.subject),
                    "serial": str(cert.serial_number),
                    "not_before": str(cert.not_valid_before),
                    "not_after": str(cert.not_valid_after),
                    "sha256": (
                        cert.sha256_fingerprint
                        if hasattr(cert, "sha256_fingerprint")
                        else "N/A"
                    ),
                }
            )
        return json.dumps({"certificates": certs}, indent=2, default=str)

    elif name == "ag_classes":
        result = _get_apk(args["apk_path"])
        if not result:
            return json.dumps({"error": "Falha"})
        _, d_list, dx = result
        filt = args.get("filter", "").lower()
        show_methods = args.get("show_methods", False)
        classes = []
        for cls in dx.get_classes():
            cname = str(cls.name)
            if filt and filt not in cname.lower():
                continue
            entry = {"name": cname}
            if show_methods:
                entry["methods"] = [str(m.name) for m in cls.get_methods()][:50]
            classes.append(entry)
            if len(classes) >= 500:
                break
        return json.dumps({"total": len(classes), "classes": classes}, indent=2)

    elif name == "ag_methods":
        result = _get_apk(args["apk_path"])
        if not result:
            return json.dumps({"error": "Falha"})
        _, _, dx = result
        target = args["class_name"]
        methods = []
        for cls in dx.get_classes():
            if str(cls.name) == target:
                for m in cls.get_methods():
                    methods.append(
                        {
                            "name": str(m.name),
                            "descriptor": (
                                str(m.descriptor) if hasattr(m, "descriptor") else ""
                            ),
                            "access": str(m.access) if hasattr(m, "access") else "",
                        }
                    )
                break
        return json.dumps(
            {"class": target, "total": len(methods), "methods": methods}, indent=2
        )

    elif name == "ag_api_calls":
        result = _get_apk(args["apk_path"])
        if not result:
            return json.dumps({"error": "Falha"})
        _, d_list, dx = result
        cat = args.get("category", "all")
        categories = [cat] if cat != "all" else list(SENSITIVE_APIS.keys())
        findings = {}
        dexes = d_list if isinstance(d_list, list) else [d_list]
        all_strings = set()
        for d in dexes:
            all_strings.update(d.get_strings())
        for c in categories:
            findings[c] = []
            for api in SENSITIVE_APIS.get(c, []):
                matches = [s for s in all_strings if api.lower() in s.lower()]
                if matches:
                    findings[c].extend(matches[:20])
        return json.dumps(findings, indent=2)

    elif name == "ag_native_libs":
        result = _get_apk(args["apk_path"])
        if not result:
            return json.dumps({"error": "Falha"})
        a, _, _ = result
        libs = []
        for f in a.get_files():
            if f.endswith(".so"):
                data = a.get_file(f)
                arch = "unknown"
                if "/armeabi-v7a/" in f:
                    arch = "armeabi-v7a"
                elif "/arm64-v8a/" in f:
                    arch = "arm64-v8a"
                elif "/x86_64/" in f:
                    arch = "x86_64"
                elif "/x86/" in f:
                    arch = "x86"
                libs.append(
                    {
                        "path": f,
                        "arch": arch,
                        "size": len(data) if data else 0,
                        "name": Path(f).name,
                    }
                )
        return json.dumps({"total": len(libs), "libs": libs}, indent=2)

    elif name == "ag_xrefs":
        result = _get_apk(args["apk_path"])
        if not result:
            return json.dumps({"error": "Falha"})
        _, _, dx = result
        target_class = args["class_name"]
        target_method = args.get("method_name")
        xrefs_to = []
        xrefs_from = []
        for cls in dx.get_classes():
            if str(cls.name) == target_class:
                for m in cls.get_methods():
                    if target_method and str(m.name) != target_method:
                        continue
                    meth = m.get_method()
                    if meth:
                        for _, call, _ in meth.get_xref_to():
                            xrefs_to.append(f"{call.class_name}->{call.name}")
                        for _, call, _ in meth.get_xref_from():
                            xrefs_from.append(f"{call.class_name}->{call.name}")
                break
        return json.dumps(
            {"xrefs_to": xrefs_to[:100], "xrefs_from": xrefs_from[:100]},
            indent=2,
            default=str,
        )

    elif name == "ag_search_code":
        result = _get_apk(args["apk_path"])
        if not result:
            return json.dumps({"error": "Falha"})
        _, d_list, dx = result
        pattern = args["pattern"].lower()
        matches = []
        for cls in dx.get_classes():
            cname = str(cls.name)
            if pattern in cname.lower():
                matches.append({"type": "class", "name": cname})
            for m in cls.get_methods():
                mname = str(m.name)
                if pattern in mname.lower():
                    matches.append({"type": "method", "class": cname, "name": mname})
            if len(matches) >= 200:
                break
        return json.dumps({"total": len(matches), "matches": matches[:200]}, indent=2)

    elif name == "ag_intent_filters":
        result = _get_apk(args["apk_path"])
        if not result:
            return json.dumps({"error": "Falha"})
        a, _, _ = result
        filters = []
        # Activities com intent filters from XML
        xml = a.get_android_manifest_xml()
        if xml is not None:
            for act in xml.findall(".//activity"):
                act_name = act.get(
                    "{http://schemas.android.com/apk/res/android}name", ""
                )
                for if_elem in act.findall("intent-filter"):
                    actions = [
                        a_el.get("{http://schemas.android.com/apk/res/android}name", "")
                        for a_el in if_elem.findall("action")
                    ]
                    categories = [
                        c_el.get("{http://schemas.android.com/apk/res/android}name", "")
                        for c_el in if_elem.findall("category")
                    ]
                    data_elems = []
                    for d_el in if_elem.findall("data"):
                        data_elems.append(
                            {k.split("}")[-1]: v for k, v in d_el.attrib.items()}
                        )
                    filters.append(
                        {
                            "component": act_name,
                            "type": "activity",
                            "actions": actions,
                            "categories": categories,
                            "data": data_elems,
                        }
                    )
        return json.dumps({"total": len(filters), "filters": filters}, indent=2)

    elif name == "ag_compare":
        r_a = _get_apk(args["apk_a"])
        r_b = _get_apk(args["apk_b"])
        if not r_a or not r_b:
            return json.dumps({"error": "Falha ao analisar um dos APKs"})
        a_a, _, _ = r_a
        a_b, _, _ = r_b
        perms_a, perms_b = set(a_a.get_permissions()), set(a_b.get_permissions())
        acts_a, acts_b = set(a_a.get_activities()), set(a_b.get_activities())
        return json.dumps(
            {
                "apk_a": {
                    "package": a_a.get_package(),
                    "version": a_a.get_androidversion_name(),
                },
                "apk_b": {
                    "package": a_b.get_package(),
                    "version": a_b.get_androidversion_name(),
                },
                "permissions": {
                    "added": sorted(perms_b - perms_a),
                    "removed": sorted(perms_a - perms_b),
                    "common": len(perms_a & perms_b),
                },
                "activities": {
                    "added": sorted(acts_b - acts_a)[:50],
                    "removed": sorted(acts_a - acts_b)[:50],
                },
            },
            indent=2,
        )

    elif name == "ag_exported_components":
        result = _get_apk(args["apk_path"])
        if not result:
            return json.dumps({"error": "Falha"})
        a, _, _ = result
        exported = {"activities": [], "services": [], "receivers": [], "providers": []}
        xml = a.get_android_manifest_xml()
        if xml is not None:
            for tag, key in [
                ("activity", "activities"),
                ("service", "services"),
                ("receiver", "receivers"),
                ("provider", "providers"),
            ]:
                for elem in xml.findall(f".//{tag}"):
                    exp = elem.get(
                        "{http://schemas.android.com/apk/res/android}exported", ""
                    )
                    name_attr = elem.get(
                        "{http://schemas.android.com/apk/res/android}name", ""
                    )
                    has_filter = len(elem.findall("intent-filter")) > 0
                    if exp == "true" or (exp == "" and has_filter):
                        exported[key].append(
                            {
                                "name": name_attr,
                                "explicit_export": exp == "true",
                                "has_intent_filter": has_filter,
                            }
                        )
        total = sum(len(v) for v in exported.values())
        return json.dumps({"total_exported": total, **exported}, indent=2)

    elif name == "ag_security_audit":
        result = _get_apk(args["apk_path"])
        if not result:
            return json.dumps({"error": "Falha"})
        a, d_list, dx = result
        findings = []
        risk_score = 0
        # Dangerous permissions
        perms = a.get_permissions()
        dangerous = [p for p in perms if p in DANGEROUS_PERMS]
        if dangerous:
            findings.append(
                {
                    "severity": "HIGH",
                    "type": "dangerous_permissions",
                    "details": dangerous,
                }
            )
            risk_score += len(dangerous) * 5
        # Debuggable
        if a.get_element("application", "debuggable") == "true":
            findings.append(
                {
                    "severity": "CRITICAL",
                    "type": "debuggable",
                    "details": "android:debuggable=true",
                }
            )
            risk_score += 30
        # Backup allowed
        if a.get_element("application", "allowBackup") != "false":
            findings.append(
                {
                    "severity": "MEDIUM",
                    "type": "backup_allowed",
                    "details": "android:allowBackup nao desabilitado",
                }
            )
            risk_score += 10
        # Exported components
        xml = a.get_android_manifest_xml()
        exp_count = 0
        if xml is not None:
            for tag in ["activity", "service", "receiver", "provider"]:
                for elem in xml.findall(f".//{tag}"):
                    exp = elem.get(
                        "{http://schemas.android.com/apk/res/android}exported", ""
                    )
                    if exp == "true" or (
                        exp == "" and len(elem.findall("intent-filter")) > 0
                    ):
                        exp_count += 1
        if exp_count > 5:
            findings.append(
                {
                    "severity": "HIGH",
                    "type": "many_exported_components",
                    "details": f"{exp_count} componentes exportados",
                }
            )
            risk_score += exp_count * 3
        # Cleartext traffic
        if a.get_element("application", "usesCleartextTraffic") == "true":
            findings.append(
                {
                    "severity": "MEDIUM",
                    "type": "cleartext_traffic",
                    "details": "Permite trafego HTTP nao criptografado",
                }
            )
            risk_score += 15
        # Native libs
        native = [f for f in a.get_files() if f.endswith(".so")]
        if native:
            findings.append(
                {
                    "severity": "INFO",
                    "type": "native_code",
                    "details": f"{len(native)} bibliotecas nativas encontradas",
                }
            )

        risk_level = (
            "CRITICAL"
            if risk_score >= 50
            else "HIGH" if risk_score >= 30 else "MEDIUM" if risk_score >= 15 else "LOW"
        )
        return json.dumps(
            {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "findings_count": len(findings),
                "findings": findings,
                "package": a.get_package(),
                "version": a.get_androidversion_name(),
            },
            indent=2,
        )

    return f"Ferramenta desconhecida: {name}"


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
            nm = params.get("name", "")
            arguments = params.get("arguments", {})
            try:
                result = await dispatch_tool(nm, arguments)
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
                    await reader.readline()
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
