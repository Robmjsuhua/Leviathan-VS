#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP Ghidra Server v1.0

    Ghidra headless analysis MCP server.
    Uses analyzeHeadless for automated binary analysis.
    JSON-RPC 2.0 over stdio with Content-Length framing.

    Tools:
        - ghidra_analyze: Full headless analysis of binary
        - ghidra_list_functions: List all functions in binary
        - ghidra_decompile: Decompile specific function to C
        - ghidra_search_strings: Search strings in binary
        - ghidra_list_exports: List exported symbols
        - ghidra_list_imports: List imported symbols
        - ghidra_xrefs_to: Find cross-references to address/function
        - ghidra_xrefs_from: Find cross-references from function
        - ghidra_get_sections: List binary sections
        - ghidra_search_bytes: Search byte pattern in binary
        - ghidra_get_entry_points: Get entry points
        - ghidra_list_classes: List C++ classes (vtable analysis)
        - ghidra_get_data_types: List data types
        - ghidra_run_script: Execute GhidraScript (.java/.py)
        - ghidra_get_info: Get binary metadata (arch, format, etc)

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
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("leviathan-ghidra-mcp")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-ghidra-server"
PROJECT_DIR = Path(r"C:\Users\Kishi\Desktop\Trabalhos\ghidra_projects")
SCRIPTS_DIR = Path(__file__).parent / "scripts"


def _find_ghidra() -> str:
    candidates = [
        r"C:\ghidra\support\analyzeHeadless.bat",
        r"C:\Tools\ghidra\support\analyzeHeadless.bat",
        r"C:\Users\Kishi\Tools\ghidra\support\analyzeHeadless.bat",
        r"C:\Program Files\ghidra\support\analyzeHeadless.bat",
        r"C:\ghidra_11.0\support\analyzeHeadless.bat",
        r"C:\ghidra_11.1\support\analyzeHeadless.bat",
        r"C:\ghidra_11.2\support\analyzeHeadless.bat",
        r"C:\ghidra_11.3\support\analyzeHeadless.bat",
    ]
    # Also search in PATH
    which = shutil.which("analyzeHeadless")
    if which:
        candidates.insert(0, which)
    for c in candidates:
        if c and Path(c).exists():
            return str(c)
    # Search in common parent dirs
    for base in [r"C:\\", r"C:\Tools", r"C:\Users\Kishi"]:
        p = Path(base)
        if p.exists():
            for d in p.iterdir():
                if d.is_dir() and "ghidra" in d.name.lower():
                    ah = d / "support" / "analyzeHeadless.bat"
                    if ah.exists():
                        return str(ah)
    return "analyzeHeadless"


GHIDRA = _find_ghidra()


def _run_ghidra(
    project_name: str,
    binary_path: str,
    script_name: str = "",
    script_args: List[str] = None,
    extra_args: List[str] = None,
    timeout: int = 300,
) -> Dict:
    PROJECT_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [GHIDRA, str(PROJECT_DIR), project_name]
    if binary_path:
        cmd.extend(["-import", binary_path])
    else:
        cmd.extend(["-process", project_name])
    cmd.extend(["-overwrite", "-analysisTimeoutPerFile", "120"])
    if script_name:
        cmd.extend(["-postScript", script_name])
        if script_args:
            cmd.extend(script_args)
    if extra_args:
        cmd.extend(extra_args)
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
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Timeout after {timeout}s"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _create_ghidra_script(script_content: str, name: str = "LeviathanScript.py") -> str:
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    script_path = SCRIPTS_DIR / name
    script_path.write_text(script_content, encoding="utf-8")
    return str(script_path)


# ── GhidraScript templates (Python/Jython) ──
SCRIPT_LIST_FUNCTIONS = """
# @category Leviathan
from ghidra.program.model.listing import *
fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True)
for f in funcs:
    print("FUNC|{}|{}|{}".format(f.getName(), f.getEntryPoint(), f.getBody().getNumAddresses()))
"""

SCRIPT_DECOMPILE = """
# @category Leviathan
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import *
import sys
target_name = getScriptArgs()[0] if len(getScriptArgs()) > 0 else ""
decomp = DecompInterface()
decomp.openProgram(currentProgram)
fm = currentProgram.getFunctionManager()
for f in fm.getFunctions(True):
    if target_name and target_name.lower() not in f.getName().lower():
        continue
    result = decomp.decompileFunction(f, 30, monitor)
    if result.depiledFunction():
        print("DECOMPILE|{}|{}".format(f.getName(), f.getEntryPoint()))
        print(result.getDecompiledFunction().getC())
        if target_name:
            break
"""

SCRIPT_SEARCH_STRINGS = """
# @category Leviathan
from ghidra.program.model.data import *
listing = currentProgram.getListing()
mem = currentProgram.getMemory()
dt = currentProgram.getDataTypeManager()
data_iter = listing.getDefinedData(True)
for d in data_iter:
    if d.hasStringValue():
        val = d.getValue()
        if val:
            print("STR|{}|{}".format(d.getAddress(), str(val)[:200]))
"""

SCRIPT_LIST_EXPORTS = """
# @category Leviathan
st = currentProgram.getSymbolTable()
symbols = st.getExternalSymbols()
for s in st.getAllSymbols(True):
    if s.isExternalEntryPoint():
        print("EXPORT|{}|{}|{}".format(s.getName(), s.getAddress(), s.getSymbolType()))
"""

SCRIPT_LIST_IMPORTS = """
# @category Leviathan
st = currentProgram.getSymbolTable()
for s in st.getAllSymbols(True):
    if s.isExternal():
        print("IMPORT|{}|{}".format(s.getName(), s.getAddress()))
"""

SCRIPT_XREFS_TO = """
# @category Leviathan
from ghidra.program.model.symbol import *
target = getScriptArgs()[0] if len(getScriptArgs()) > 0 else ""
st = currentProgram.getSymbolTable()
rm = currentProgram.getReferenceManager()
for s in st.getAllSymbols(True):
    if target.lower() in s.getName().lower():
        refs = rm.getReferencesTo(s.getAddress())
        for ref in refs:
            print("XREF_TO|{}|{}|{}|{}".format(s.getName(), s.getAddress(), ref.getFromAddress(), ref.getReferenceType()))
"""

SCRIPT_GET_SECTIONS = """
# @category Leviathan
mem = currentProgram.getMemory()
for block in mem.getBlocks():
    print("SECTION|{}|{}|{}|{}|r={},w={},x={}".format(
        block.getName(), block.getStart(), block.getEnd(), block.getSize(),
        block.isRead(), block.isWrite(), block.isExecute()))
"""

SCRIPT_GET_INFO = """
# @category Leviathan
prog = currentProgram
lang = prog.getLanguage()
print("Name: " + prog.getName())
print("Format: " + prog.getExecutableFormat())
print("Path: " + prog.getExecutablePath())
print("Language: " + str(lang.getLanguageID()))
print("Processor: " + str(lang.getProcessor()))
print("Endian: " + str(lang.isBigEndian()))
print("Address Size: " + str(lang.getDefaultSpace().getSize()))
print("Compiler: " + str(prog.getCompilerSpec().getCompilerSpecID()))
fm = prog.getFunctionManager()
print("Functions: " + str(fm.getFunctionCount()))
st = prog.getSymbolTable()
print("Symbols: " + str(st.getNumSymbols()))
mem = prog.getMemory()
print("Memory Blocks: " + str(mem.getNumAddresses()))
"""

SCRIPT_XREFS_FROM = """
# @category Leviathan
from ghidra.program.model.symbol import *
target = getScriptArgs()[0] if len(getScriptArgs()) > 0 else ""
fm = currentProgram.getFunctionManager()
rm = currentProgram.getReferenceManager()
for func in fm.getFunctions(True):
    if target.lower() in func.getName().lower():
        body = func.getBody()
        addr_iter = body.getAddresses(True)
        while addr_iter.hasNext():
            addr = addr_iter.next()
            refs = rm.getReferencesFrom(addr)
            for ref in refs:
                print("XREF_FROM|{}|{}|{}|{}".format(func.getName(), addr, ref.getToAddress(), ref.getReferenceType()))
"""

SCRIPT_SEARCH_BYTES = """
# @category Leviathan
from ghidra.program.model.mem import MemoryAccessException
pattern = getScriptArgs()[0] if len(getScriptArgs()) > 0 else "DE AD BE EF"
mem = currentProgram.getMemory()
addr = mem.getMinAddress()
count = 0
while addr is not None and count < 200:
    addr = mem.findBytes(addr, pattern.decode("hex") if hasattr(pattern, "decode") else bytes.fromhex(pattern.replace(" ", "")), None, True, monitor)
    if addr is not None:
        print("BYTES|{}".format(addr))
        count += 1
        addr = addr.add(1)
"""

SCRIPT_GET_ENTRY_POINTS = """
# @category Leviathan
from ghidra.program.model.symbol import SymbolType
st = currentProgram.getSymbolTable()
for s in st.getAllSymbols(True):
    if s.getSymbolType() == SymbolType.FUNCTION and s.isExternalEntryPoint():
        print("ENTRY|{}|{}".format(s.getName(), s.getAddress()))
# Also check program entry point
ep = currentProgram.getMinAddress()
if currentProgram.getExecutableFormat():
    listing = currentProgram.getListing()
    funcs = currentProgram.getFunctionManager()
    for func in funcs.getFunctions(True):
        if func.isThunk() == False and "entry" in func.getName().lower():
            print("ENTRY|{}|{}".format(func.getName(), func.getEntryPoint()))
"""

SCRIPT_LIST_CLASSES = """
# @category Leviathan
from ghidra.program.model.symbol import SymbolType, Namespace
ns_mgr = currentProgram.getNamespaceManager()
st = currentProgram.getSymbolTable()
classes = set()
for s in st.getAllSymbols(True):
    parent = s.getParentNamespace()
    if parent and parent.getName() != "Global":
        classes.add((parent.getName(), str(parent.getID())))
for cls_name, cls_id in sorted(classes):
    print("CLASS|{}|{}".format(cls_name, cls_id))
"""

SCRIPT_GET_DATA_TYPES = """
# @category Leviathan
filter_str = getScriptArgs()[0] if len(getScriptArgs()) > 0 else ""
dtm = currentProgram.getDataTypeManager()
count = 0
for dt in dtm.getAllDataTypes():
    name = dt.getName()
    if filter_str and filter_str.lower() not in name.lower():
        continue
    print("DTYPE|{}|{}|{}".format(name, dt.getLength(), dt.getCategoryPath()))
    count += 1
    if count >= 500:
        break
"""


TOOLS = [
    {
        "name": "ghidra_analyze",
        "description": "Analise headless completa de binario (ELF, PE, Mach-O, .so, .dll)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Caminho do binario"},
                "timeout": {
                    "type": "integer",
                    "description": "Timeout em segundos (default 300)",
                },
            },
            "required": ["binary_path"],
        },
    },
    {
        "name": "ghidra_get_info",
        "description": "Obtem metadados do binario (arch, formato, endian, funcoes, simbolos)",
        "inputSchema": {
            "type": "object",
            "properties": {"binary_path": {"type": "string"}},
            "required": ["binary_path"],
        },
    },
    {
        "name": "ghidra_list_functions",
        "description": "Lista todas as funcoes encontradas com endereco e tamanho",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "filter": {
                    "type": "string",
                    "description": "Filtro por nome de funcao",
                },
            },
            "required": ["binary_path"],
        },
    },
    {
        "name": "ghidra_decompile",
        "description": "Decompila funcao para codigo C pseudo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "function_name": {
                    "type": "string",
                    "description": "Nome da funcao (ou parte dele)",
                },
            },
            "required": ["binary_path", "function_name"],
        },
    },
    {
        "name": "ghidra_search_strings",
        "description": "Lista todas as strings encontradas no binario",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "filter": {"type": "string"},
            },
            "required": ["binary_path"],
        },
    },
    {
        "name": "ghidra_list_exports",
        "description": "Lista simbolos exportados",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "filter": {"type": "string"},
            },
            "required": ["binary_path"],
        },
    },
    {
        "name": "ghidra_list_imports",
        "description": "Lista simbolos importados",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "filter": {"type": "string"},
            },
            "required": ["binary_path"],
        },
    },
    {
        "name": "ghidra_xrefs_to",
        "description": "Encontra cross-references para funcao/simbolo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "target": {
                    "type": "string",
                    "description": "Nome da funcao/simbolo alvo",
                },
            },
            "required": ["binary_path", "target"],
        },
    },
    {
        "name": "ghidra_get_sections",
        "description": "Lista secoes do binario com permissoes",
        "inputSchema": {
            "type": "object",
            "properties": {"binary_path": {"type": "string"}},
            "required": ["binary_path"],
        },
    },
    {
        "name": "ghidra_run_script",
        "description": "Executa GhidraScript customizado (Python/Jython)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "script_content": {
                    "type": "string",
                    "description": "Conteudo do script Python/Jython",
                },
                "script_args": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["binary_path", "script_content"],
        },
    },
    {
        "name": "ghidra_xrefs_from",
        "description": "Encontra cross-references de uma funcao (o que ela chama)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "function_name": {
                    "type": "string",
                    "description": "Nome da funcao de origem",
                },
            },
            "required": ["binary_path", "function_name"],
        },
    },
    {
        "name": "ghidra_search_bytes",
        "description": "Busca padrao de bytes hex no binario",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "pattern": {
                    "type": "string",
                    "description": "Pattern hex (ex: 'DEADBEEF' ou 'DE AD BE EF')",
                },
            },
            "required": ["binary_path", "pattern"],
        },
    },
    {
        "name": "ghidra_get_entry_points",
        "description": "Lista entry points do binario",
        "inputSchema": {
            "type": "object",
            "properties": {"binary_path": {"type": "string"}},
            "required": ["binary_path"],
        },
    },
    {
        "name": "ghidra_list_classes",
        "description": "Lista classes C++ (via analise de namespaces/vtables)",
        "inputSchema": {
            "type": "object",
            "properties": {"binary_path": {"type": "string"}},
            "required": ["binary_path"],
        },
    },
    {
        "name": "ghidra_get_data_types",
        "description": "Lista data types definidos no binario",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "filter": {"type": "string", "description": "Filtro por nome"},
            },
            "required": ["binary_path"],
        },
    },
]


async def dispatch_tool(name: str, args: Dict) -> str:
    binary_path = args.get("binary_path", "")
    project_name = Path(binary_path).stem if binary_path else "temp"
    filt = args.get("filter", "")

    if name == "ghidra_analyze":
        timeout = args.get("timeout", 300)
        r = _run_ghidra(project_name, binary_path, timeout=timeout)
        if r["success"]:
            # Extract key info from output
            output = r.get("stdout", "") + "\n" + r.get("stderr", "")
            return f"Analysis complete for {binary_path}\n{output[-5000:]}"
        return f"Analysis failed: {r.get('error', r.get('stderr', ''))}"

    elif name == "ghidra_get_info":
        script_path = _create_ghidra_script(SCRIPT_GET_INFO, "get_info.py")
        r = _run_ghidra(project_name, binary_path, script_path)
        output = r.get("stdout", "") + r.get("stderr", "")
        lines = [
            l
            for l in output.splitlines()
            if any(
                l.startswith(p)
                for p in [
                    "Name:",
                    "Format:",
                    "Path:",
                    "Language:",
                    "Processor:",
                    "Endian:",
                    "Address Size:",
                    "Compiler:",
                    "Functions:",
                    "Symbols:",
                    "Memory",
                ]
            )
        ]
        return "\n".join(lines) if lines else output[-3000:]

    elif name == "ghidra_list_functions":
        script_path = _create_ghidra_script(SCRIPT_LIST_FUNCTIONS, "list_funcs.py")
        r = _run_ghidra(project_name, binary_path, script_path)
        output = r.get("stdout", "")
        funcs = [l for l in output.splitlines() if l.startswith("FUNC|")]
        if filt:
            funcs = [f for f in funcs if filt.lower() in f.lower()]
        result = []
        for f in funcs[:500]:
            parts = f.split("|")
            if len(parts) >= 4:
                result.append(f"{parts[1]:40s} @ {parts[2]:12s} ({parts[3]} bytes)")
        return "\n".join(result) if result else "No functions found"

    elif name == "ghidra_decompile":
        script_path = _create_ghidra_script(SCRIPT_DECOMPILE, "decompile.py")
        r = _run_ghidra(
            project_name, binary_path, script_path, script_args=[args["function_name"]]
        )
        output = r.get("stdout", "")
        # Extract decompiled code
        lines = output.splitlines()
        in_decomp = False
        result = []
        for line in lines:
            if line.startswith("DECOMPILE|"):
                in_decomp = True
                name_addr = line.split("|")
                result.append(f"// Function: {name_addr[1]} @ {name_addr[2]}")
                continue
            if in_decomp:
                result.append(line)
        return (
            "\n".join(result)
            if result
            else f"Could not decompile. Full output:\n{output[-3000:]}"
        )

    elif name == "ghidra_search_strings":
        script_path = _create_ghidra_script(SCRIPT_SEARCH_STRINGS, "strings.py")
        r = _run_ghidra(project_name, binary_path, script_path)
        output = r.get("stdout", "")
        strings = [l for l in output.splitlines() if l.startswith("STR|")]
        if filt:
            strings = [s for s in strings if filt.lower() in s.lower()]
        result = []
        for s in strings[:500]:
            parts = s.split("|", 2)
            if len(parts) >= 3:
                result.append(f"{parts[1]:12s}: {parts[2]}")
        return "\n".join(result) if result else "No strings found"

    elif name == "ghidra_list_exports":
        script_path = _create_ghidra_script(SCRIPT_LIST_EXPORTS, "exports.py")
        r = _run_ghidra(project_name, binary_path, script_path)
        output = r.get("stdout", "")
        exports = [l for l in output.splitlines() if l.startswith("EXPORT|")]
        if filt:
            exports = [e for e in exports if filt.lower() in e.lower()]
        result = []
        for e in exports[:500]:
            parts = e.split("|")
            if len(parts) >= 4:
                result.append(f"{parts[1]:40s} @ {parts[2]} [{parts[3]}]")
        return "\n".join(result) if result else "No exports found"

    elif name == "ghidra_list_imports":
        script_path = _create_ghidra_script(SCRIPT_LIST_IMPORTS, "imports.py")
        r = _run_ghidra(project_name, binary_path, script_path)
        output = r.get("stdout", "")
        imports = [l for l in output.splitlines() if l.startswith("IMPORT|")]
        if filt:
            imports = [i for i in imports if filt.lower() in i.lower()]
        result = [
            f"{i.split('|')[1]:40s} @ {i.split('|')[2]}"
            for i in imports[:500]
            if len(i.split("|")) >= 3
        ]
        return "\n".join(result) if result else "No imports found"

    elif name == "ghidra_xrefs_to":
        script_path = _create_ghidra_script(SCRIPT_XREFS_TO, "xrefs.py")
        r = _run_ghidra(
            project_name, binary_path, script_path, script_args=[args["target"]]
        )
        output = r.get("stdout", "")
        xrefs = [l for l in output.splitlines() if l.startswith("XREF_TO|")]
        result = []
        for x in xrefs[:200]:
            parts = x.split("|")
            if len(parts) >= 5:
                result.append(f"{parts[3]} -> {parts[1]} @ {parts[2]} [{parts[4]}]")
        return "\n".join(result) if result else "No xrefs found"

    elif name == "ghidra_get_sections":
        script_path = _create_ghidra_script(SCRIPT_GET_SECTIONS, "sections.py")
        r = _run_ghidra(project_name, binary_path, script_path)
        output = r.get("stdout", "")
        sections = [l for l in output.splitlines() if l.startswith("SECTION|")]
        result = []
        for s in sections:
            parts = s.split("|")
            if len(parts) >= 7:
                result.append(
                    f"{parts[1]:20s} {parts[2]}-{parts[3]} ({parts[4]} bytes) {parts[5]}"
                )
        return "\n".join(result) if result else "No sections found"

    elif name == "ghidra_run_script":
        script_path = _create_ghidra_script(args["script_content"], "custom_script.py")
        script_args = args.get("script_args", [])
        r = _run_ghidra(project_name, binary_path, script_path, script_args=script_args)
        output = r.get("stdout", "") + "\n" + r.get("stderr", "")
        return output[-10000:]

    elif name == "ghidra_xrefs_from":
        script_path = _create_ghidra_script(SCRIPT_XREFS_FROM, "xrefs_from.py")
        r = _run_ghidra(
            project_name, binary_path, script_path, script_args=[args["function_name"]]
        )
        output = r.get("stdout", "")
        xrefs = [l for l in output.splitlines() if l.startswith("XREF_FROM|")]
        result = []
        for x in xrefs[:200]:
            parts = x.split("|")
            if len(parts) >= 5:
                result.append(f"{parts[1]} @ {parts[2]} -> {parts[3]} [{parts[4]}]")
        return "\n".join(result) if result else "No outgoing xrefs found"

    elif name == "ghidra_search_bytes":
        pattern = args["pattern"].replace(" ", "")
        script_path = _create_ghidra_script(SCRIPT_SEARCH_BYTES, "search_bytes.py")
        r = _run_ghidra(project_name, binary_path, script_path, script_args=[pattern])
        output = r.get("stdout", "")
        matches = [l for l in output.splitlines() if l.startswith("BYTES|")]
        result = [m.split("|")[1] for m in matches if len(m.split("|")) >= 2]
        return (
            f"Found {len(result)} matches:\n" + "\n".join(result[:200])
            if result
            else "Pattern not found"
        )

    elif name == "ghidra_get_entry_points":
        script_path = _create_ghidra_script(SCRIPT_GET_ENTRY_POINTS, "entry_points.py")
        r = _run_ghidra(project_name, binary_path, script_path)
        output = r.get("stdout", "")
        entries = [l for l in output.splitlines() if l.startswith("ENTRY|")]
        result = []
        for e in entries[:100]:
            parts = e.split("|")
            if len(parts) >= 3:
                result.append(f"{parts[1]:40s} @ {parts[2]}")
        return "\n".join(result) if result else "No entry points found"

    elif name == "ghidra_list_classes":
        script_path = _create_ghidra_script(SCRIPT_LIST_CLASSES, "list_classes.py")
        r = _run_ghidra(project_name, binary_path, script_path)
        output = r.get("stdout", "")
        classes = [l for l in output.splitlines() if l.startswith("CLASS|")]
        result = [c.split("|")[1] for c in classes if len(c.split("|")) >= 2]
        return (
            f"Classes ({len(result)}):\n" + "\n".join(sorted(result)[:500])
            if result
            else "No classes found"
        )

    elif name == "ghidra_get_data_types":
        filt = args.get("filter", "")
        script_path = _create_ghidra_script(SCRIPT_GET_DATA_TYPES, "data_types.py")
        r = _run_ghidra(project_name, binary_path, script_path, script_args=[filt])
        output = r.get("stdout", "")
        dtypes = [l for l in output.splitlines() if l.startswith("DTYPE|")]
        result = []
        for d in dtypes[:500]:
            parts = d.split("|")
            if len(parts) >= 4:
                result.append(f"{parts[1]:40s} ({parts[2]} bytes) {parts[3]}")
        return "\n".join(result) if result else "No data types found"

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

        logger.info(f"{SERVER_NAME} v{VERSION} started (Ghidra: {GHIDRA})")
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
