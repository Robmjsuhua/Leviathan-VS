#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP Hashcat Server v1.0

    Password cracking and hash analysis MCP server.
    Uses hashcat CLI + john (optional) for hash operations.
    JSON-RPC 2.0 over stdio with Content-Length framing.

    Tools:
        - hash_identify: Identify hash type(s) from hash string
        - hash_crack: Crack hash with hashcat (dictionary/brute/rule)
        - hash_benchmark: Run hashcat benchmark for hash type
        - hash_status: Check status of running crack session
        - hash_show: Show cracked hashes from potfile
        - hash_generate_wordlist: Generate wordlist from patterns
        - hash_generate_rule: Generate hashcat rule file
        - hash_combinator: Combine two wordlists
        - hash_mask_attack: Mask/brute-force attack
        - hash_john_crack: Crack with John the Ripper
        - hash_convert: Convert hash formats (hash-identifier)
        - hash_analyze_potfile: Analyze cracked passwords stats

    Author: ThiagoFrag / LEVIATHAN VS
    Version: 1.0.0
================================================================================
"""

import asyncio
import hashlib
import json
import logging
import os
import re
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
logger = logging.getLogger("leviathan-hashcat-mcp")

VERSION = "1.0.0"
SERVER_NAME = "leviathan-hashcat-server"

OUTPUT_DIR = Path(r"C:\Users\Kishi\Desktop\Trabalhos\hashcat_output")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _find_hashcat() -> str:
    candidates = [
        shutil.which("hashcat"),
        r"C:\hashcat\hashcat.exe",
        r"C:\Tools\hashcat\hashcat.exe",
        r"C:\Program Files\hashcat\hashcat.exe",
        r"C:\Users\Kishi\Desktop\Trabalhos\hashcat\hashcat.exe",
    ]
    for c in candidates:
        if c and Path(c).exists():
            return str(c)
    return "hashcat"


def _find_john() -> str:
    candidates = [
        shutil.which("john"),
        r"C:\john\run\john.exe",
        r"C:\Tools\john\run\john.exe",
        r"C:\Program Files\john\run\john.exe",
    ]
    for c in candidates:
        if c and Path(c).exists():
            return str(c)
    return "john"


HASHCAT = _find_hashcat()
JOHN = _find_john()

# Common hash types by length and pattern
HASH_SIGNATURES = {
    32: [
        (r"^[a-f0-9]{32}$", "MD5", 0),
        (r"^[a-f0-9]{32}$", "NTLM", 1000),
        (r"^[a-f0-9]{32}$", "LM", 3000),
    ],
    40: [
        (r"^[a-f0-9]{40}$", "SHA-1", 100),
        (r"^[a-f0-9]{40}$", "MySQL4.1/5", 300),
    ],
    56: [(r"^[a-f0-9]{56}$", "SHA-224", 1300)],
    64: [
        (r"^[a-f0-9]{64}$", "SHA-256", 1400),
        (r"^[a-f0-9]{64}$", "Keccak-256", 17800),
    ],
    96: [(r"^[a-f0-9]{96}$", "SHA-384", 10800)],
    128: [
        (r"^[a-f0-9]{128}$", "SHA-512", 1700),
        (r"^[a-f0-9]{128}$", "Whirlpool", 6100),
    ],
}

HASH_PATTERNS = [
    (r"^\$2[aby]?\$\d{2}\$", "bcrypt", 3200),
    (r"^\$6\$", "sha512crypt", 1800),
    (r"^\$5\$", "sha256crypt", 7400),
    (r"^\$1\$", "md5crypt", 500),
    (r"^\$apr1\$", "Apache APR1", 1600),
    (r"^\$P\$", "phpass", 400),
    (r"^\$H\$", "phpass", 400),
    (r"^sha1\$", "Django SHA-1", 124),
    (r"^pbkdf2_sha256\$", "Django PBKDF2-SHA256", 10000),
    (r"^[a-f0-9]{32}:[a-f0-9]+$", "MD5 with salt", 10),
    (r"^[a-f0-9]{64}:[a-f0-9]+$", "SHA-256 with salt", 1410),
    (r"^\{SHA\}", "LDAP SHA-1", 101),
    (r"^\{SSHA\}", "LDAP SSHA", 111),
]


def _run_cmd(cmd: List[str], timeout: int = 60) -> Dict:
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


TOOLS = [
    {
        "name": "hash_identify",
        "description": "Identifica tipo(s) possiveis de um hash. Retorna nome, modo hashcat e probabilidade.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash": {"type": "string", "description": "Hash para identificar"},
            },
            "required": ["hash"],
        },
    },
    {
        "name": "hash_crack",
        "description": "Cracka hash com hashcat. Suporta dictionary, brute-force, rule-based.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_value": {
                    "type": "string",
                    "description": "Hash ou arquivo de hashes",
                },
                "hash_type": {
                    "type": "integer",
                    "description": "Modo hashcat (0=MD5, 100=SHA1, 1000=NTLM, etc)",
                },
                "attack_mode": {
                    "type": "integer",
                    "description": "0=dictionary, 1=combination, 3=brute-force, 6=hybrid dict+mask, 7=hybrid mask+dict",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Caminho da wordlist (para attack_mode 0/1/6)",
                },
                "mask": {
                    "type": "string",
                    "description": "Mascara para brute-force (?a?a?a?a?a?a para 6 chars all)",
                },
                "rules": {"type": "string", "description": "Arquivo de regras hashcat"},
                "extra_args": {
                    "type": "string",
                    "description": "Argumentos extras para hashcat",
                },
                "timeout": {"type": "integer", "description": "Timeout em segundos"},
            },
            "required": ["hash_value", "hash_type"],
        },
    },
    {
        "name": "hash_benchmark",
        "description": "Benchmark hashcat para tipo de hash especifico (performance do GPU/CPU)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_type": {
                    "type": "integer",
                    "description": "Modo hashcat para benchmark",
                },
            },
            "required": ["hash_type"],
        },
    },
    {
        "name": "hash_status",
        "description": "Status da sessao de crack (restore/status)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session": {
                    "type": "string",
                    "description": "Nome da sessao (default: default)",
                },
            },
        },
    },
    {
        "name": "hash_show",
        "description": "Mostra hashes ja crackados do potfile",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_value": {
                    "type": "string",
                    "description": "Hash ou arquivo de hashes",
                },
                "hash_type": {"type": "integer", "description": "Modo hashcat"},
            },
            "required": ["hash_value", "hash_type"],
        },
    },
    {
        "name": "hash_generate_wordlist",
        "description": "Gera wordlist customizada a partir de padroes/palavras base",
        "inputSchema": {
            "type": "object",
            "properties": {
                "base_words": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Palavras base para gerar variantes",
                },
                "output": {"type": "string", "description": "Arquivo de saida"},
                "mutations": {
                    "type": "boolean",
                    "description": "Aplicar mutacoes comuns (leet speak, capitalize, etc)",
                },
                "append_numbers": {
                    "type": "boolean",
                    "description": "Adicionar numeros 0-999",
                },
                "append_special": {
                    "type": "boolean",
                    "description": "Adicionar caracteres especiais",
                },
            },
            "required": ["base_words", "output"],
        },
    },
    {
        "name": "hash_generate_rule",
        "description": "Gera arquivo de regras hashcat para transformacoes comuns",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output": {"type": "string", "description": "Arquivo de saida"},
                "type": {
                    "type": "string",
                    "enum": ["basic", "leet", "aggressive", "custom"],
                    "description": "Tipo de ruleset",
                },
                "custom_rules": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Regras customizadas (quando type=custom)",
                },
            },
            "required": ["output"],
        },
    },
    {
        "name": "hash_combinator",
        "description": "Combina duas wordlists (cada palavra de W1 + cada palavra de W2)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "wordlist1": {"type": "string"},
                "wordlist2": {"type": "string"},
                "output": {"type": "string"},
            },
            "required": ["wordlist1", "wordlist2", "output"],
        },
    },
    {
        "name": "hash_mask_attack",
        "description": "Ataque de mascara puro. ?l=lower ?u=upper ?d=digit ?s=special ?a=all",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_value": {"type": "string"},
                "hash_type": {"type": "integer"},
                "mask": {
                    "type": "string",
                    "description": "Mascara (ex: ?u?l?l?l?d?d?d?d)",
                },
                "increment": {"type": "boolean", "description": "Incrementar tamanho"},
                "increment_min": {"type": "integer"},
                "increment_max": {"type": "integer"},
                "timeout": {"type": "integer"},
            },
            "required": ["hash_value", "hash_type", "mask"],
        },
    },
    {
        "name": "hash_john_crack",
        "description": "Cracka hash com John the Ripper (alternativa ao hashcat)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string", "description": "Arquivo com hash(es)"},
                "format": {
                    "type": "string",
                    "description": "Formato do hash (raw-md5, raw-sha1, bcrypt, etc)",
                },
                "wordlist": {"type": "string", "description": "Wordlist (opcional)"},
                "rules": {
                    "type": "string",
                    "description": "Nome das rules (single, wordlist, jumbo, all)",
                },
                "timeout": {"type": "integer"},
            },
            "required": ["hash_file"],
        },
    },
    {
        "name": "hash_convert",
        "description": "Converte valor entre formatos de hash (gera hash de plaintext)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "plaintext": {"type": "string", "description": "Texto para gerar hash"},
                "algorithms": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Algoritmos: md5, sha1, sha256, sha512, ntlm",
                },
            },
            "required": ["plaintext"],
        },
    },
    {
        "name": "hash_analyze_potfile",
        "description": "Analisa potfile de hashcat - estatisticas de senhas crackadas",
        "inputSchema": {
            "type": "object",
            "properties": {
                "potfile": {
                    "type": "string",
                    "description": "Caminho do potfile (ou default)",
                },
            },
        },
    },
]


async def dispatch_tool(name: str, args: Dict) -> str:
    if name == "hash_identify":
        h = args["hash"].strip()
        results = []

        # Check pattern-based hashes first
        for pattern, hash_name, mode in HASH_PATTERNS:
            if re.match(pattern, h, re.IGNORECASE):
                results.append(f"  [{mode:5d}] {hash_name}")

        # Check length-based hashes
        clean = h.lower().strip()
        hlen = len(clean)
        if hlen in HASH_SIGNATURES:
            for pattern, hash_name, mode in HASH_SIGNATURES[hlen]:
                if re.match(pattern, clean):
                    results.append(f"  [{mode:5d}] {hash_name}")

        if not results:
            return f"Hash: {h}\nLength: {hlen}\nNo known hash type identified."

        return f"Hash: {h}\nLength: {hlen}\nPossible types:\n" + "\n".join(results)

    elif name == "hash_crack":
        h = args["hash_value"]
        htype = args["hash_type"]
        attack = args.get("attack_mode", 0)
        wordlist = args.get("wordlist", "")
        mask = args.get("mask", "")
        rules = args.get("rules", "")
        extra = args.get("extra_args", "")
        timeout = args.get("timeout", 300)

        # Write hash to temp file if not a file path
        hash_file = h
        tmp_hash = None
        if not Path(h).exists():
            import tempfile

            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".hash", delete=False, dir=str(OUTPUT_DIR)
            )
            tmp.write(h + "\n")
            tmp.close()
            hash_file = tmp.name
            tmp_hash = tmp.name

        cmd = [HASHCAT, "-m", str(htype), "-a", str(attack), "--force"]
        cmd.append(hash_file)

        if attack == 0 and wordlist:
            cmd.append(wordlist)
            if rules:
                cmd.extend(["-r", rules])
        elif attack == 3:
            cmd.append(mask or "?a?a?a?a?a?a")
        elif attack == 1 and wordlist:
            parts = wordlist.split(",")
            cmd.extend(parts[:2])

        if extra:
            cmd.extend(extra.split())

        cmd.extend(
            [
                "-o",
                str(OUTPUT_DIR / "cracked.txt"),
                "--potfile-path",
                str(OUTPUT_DIR / "hashcat.potfile"),
            ]
        )

        r = _run_cmd(cmd, timeout=timeout)

        if tmp_hash:
            try:
                os.unlink(tmp_hash)
            except Exception:
                pass

        output = r.get("stdout", "") + "\n" + r.get("stderr", "")

        # Check potfile for result
        cracked = OUTPUT_DIR / "cracked.txt"
        if cracked.exists():
            content = cracked.read_text(encoding="utf-8", errors="replace").strip()
            if content:
                output += f"\n\nCRACKED:\n{content}"

        return output

    elif name == "hash_benchmark":
        htype = args["hash_type"]
        r = _run_cmd([HASHCAT, "-b", "-m", str(htype), "--force"], timeout=120)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "hash_status":
        session = args.get("session", "default")
        r = _run_cmd([HASHCAT, "--session", session, "--status"], timeout=10)
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "hash_show":
        h = args["hash_value"]
        htype = args["hash_type"]
        hash_file = h
        tmp_hash = None
        if not Path(h).exists():
            import tempfile

            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".hash", delete=False, dir=str(OUTPUT_DIR)
            )
            tmp.write(h + "\n")
            tmp.close()
            hash_file = tmp.name
            tmp_hash = tmp.name

        r = _run_cmd(
            [
                HASHCAT,
                "-m",
                str(htype),
                "--show",
                "--force",
                "--potfile-path",
                str(OUTPUT_DIR / "hashcat.potfile"),
                hash_file,
            ],
            timeout=15,
        )
        if tmp_hash:
            try:
                os.unlink(tmp_hash)
            except Exception:
                pass
        return r["stdout"] if r["success"] else r.get("error", r.get("stderr", ""))

    elif name == "hash_generate_wordlist":
        words = args["base_words"]
        output = args["output"]
        mutations = args.get("mutations", True)
        append_nums = args.get("append_numbers", True)
        append_special = args.get("append_special", False)

        generated = set()
        for w in words:
            generated.add(w)
            generated.add(w.lower())
            generated.add(w.upper())
            generated.add(w.capitalize())

            if mutations:
                # Leet speak
                leet = (
                    w.replace("a", "@")
                    .replace("e", "3")
                    .replace("i", "1")
                    .replace("o", "0")
                    .replace("s", "$")
                )
                generated.add(leet)
                generated.add(leet.capitalize())
                # Reverse
                generated.add(w[::-1])
                # Double
                generated.add(w + w)

            if append_nums:
                for n in (
                    list(range(10))
                    + list(range(100, 1000, 100))
                    + [123, 1234, 12345, 2024, 2025]
                ):
                    generated.add(f"{w}{n}")
                    generated.add(f"{w.capitalize()}{n}")

            if append_special:
                for s in ["!", "@", "#", "$", ".", "*", "!!", "123!"]:
                    generated.add(f"{w}{s}")
                    generated.add(f"{w.capitalize()}{s}")

        Path(output).write_text("\n".join(sorted(generated)), encoding="utf-8")
        return f"Generated {len(generated)} entries -> {output}"

    elif name == "hash_generate_rule":
        output = args["output"]
        rtype = args.get("type", "basic")
        custom = args.get("custom_rules", [])

        rules_map = {
            "basic": [
                ":",
                "l",
                "u",
                "c",
                "t",
                "r",
                "$1",
                "$2",
                "$3",
                "$!",
                "$@",
                "$$",
                "^1",
                "^!",
                "^@",
                "d",
                "f",
                "sa@",
                "se3",
                "si1",
                "so0",
                "ss$",
            ],
            "leet": [
                "sa@",
                "se3",
                "si1",
                "so0",
                "ss$",
                "st7",
                "sa@ se3",
                "sa@ se3 si1",
                "sa@ se3 si1 so0",
                "sa@ se3 si1 so0 ss$",
                "sa4",
                "se3 si!",
                "c sa@ se3",
                "c sa@ se3 si1 so0",
                "u sa@ se3 si1 so0 ss$",
            ],
            "aggressive": [
                ":",
                "l",
                "u",
                "c",
                "t",
                "r",
                "d",
                "f",
                "$1",
                "$2",
                "$3",
                "$!",
                "$@",
                "$$",
                "$#",
                "$1 $2 $3",
                "$! $@",
                "$1 $2 $3 $!",
                "^1",
                "^!",
                "^@",
                "^# ^1",
                "sa@",
                "se3",
                "si1",
                "so0",
                "ss$",
                "st7",
                "sa@ se3 si1 so0 ss$ st7",
                "c $1",
                "c $!",
                "c $1 $2 $3",
                "c sa@ se3",
                "c sa@ $!",
                "u $1",
                "u $!",
                "l $1 $2 $3",
                "D0",
                "D1",
                "]",
                "[",
                "} } }",
                "{ { {",
                "k",
                "K",
            ],
            "custom": custom,
        }

        rules = rules_map.get(rtype, rules_map["basic"])
        Path(output).write_text("\n".join(rules), encoding="utf-8")
        return f"Generated {len(rules)} rules ({rtype}) -> {output}"

    elif name == "hash_combinator":
        w1 = args["wordlist1"]
        w2 = args["wordlist2"]
        output = args["output"]

        lines1 = Path(w1).read_text(encoding="utf-8", errors="replace").splitlines()
        lines2 = Path(w2).read_text(encoding="utf-8", errors="replace").splitlines()

        count = 0
        with open(output, "w", encoding="utf-8") as f:
            for a in lines1:
                for b in lines2:
                    f.write(f"{a.strip()}{b.strip()}\n")
                    count += 1

        return f"Combined {len(lines1)} x {len(lines2)} = {count} entries -> {output}"

    elif name == "hash_mask_attack":
        h = args["hash_value"]
        htype = args["hash_type"]
        mask = args["mask"]
        inc = args.get("increment", False)
        inc_min = args.get("increment_min", 1)
        inc_max = args.get("increment_max", 8)
        timeout = args.get("timeout", 300)

        hash_file = h
        tmp_hash = None
        if not Path(h).exists():
            import tempfile

            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".hash", delete=False, dir=str(OUTPUT_DIR)
            )
            tmp.write(h + "\n")
            tmp.close()
            hash_file = tmp.name
            tmp_hash = tmp.name

        cmd = [HASHCAT, "-m", str(htype), "-a", "3", "--force", hash_file, mask]
        if inc:
            cmd.extend(
                [
                    "--increment",
                    f"--increment-min={inc_min}",
                    f"--increment-max={inc_max}",
                ]
            )
        cmd.extend(
            [
                "-o",
                str(OUTPUT_DIR / "cracked.txt"),
                "--potfile-path",
                str(OUTPUT_DIR / "hashcat.potfile"),
            ]
        )

        r = _run_cmd(cmd, timeout=timeout)

        if tmp_hash:
            try:
                os.unlink(tmp_hash)
            except Exception:
                pass

        return r.get("stdout", "") + "\n" + r.get("stderr", "")

    elif name == "hash_john_crack":
        hash_file = args["hash_file"]
        fmt = args.get("format", "")
        wordlist = args.get("wordlist", "")
        rules = args.get("rules", "")
        timeout = args.get("timeout", 300)

        cmd = [JOHN]
        if fmt:
            cmd.append(f"--format={fmt}")
        if wordlist:
            cmd.append(f"--wordlist={wordlist}")
        if rules:
            cmd.append(f"--rules={rules}")
        cmd.append(hash_file)

        r = _run_cmd(cmd, timeout=timeout)
        output = r.get("stdout", "") + "\n" + r.get("stderr", "")

        # Show results
        show = _run_cmd(
            [JOHN, "--show", hash_file] + ([f"--format={fmt}"] if fmt else []),
            timeout=10,
        )
        if show.get("stdout"):
            output += f"\n\nCracked:\n{show['stdout']}"

        return output

    elif name == "hash_convert":
        pt = args["plaintext"]
        algos = args.get("algorithms", ["md5", "sha1", "sha256", "sha512", "ntlm"])
        results = [f"Plaintext: {pt}", "---"]

        for algo in algos:
            algo_lower = algo.lower()
            if algo_lower == "md5":
                h = hashlib.md5(pt.encode()).hexdigest()
            elif algo_lower == "sha1":
                h = hashlib.sha1(pt.encode()).hexdigest()
            elif algo_lower == "sha256":
                h = hashlib.sha256(pt.encode()).hexdigest()
            elif algo_lower == "sha512":
                h = hashlib.sha512(pt.encode()).hexdigest()
            elif algo_lower == "sha384":
                h = hashlib.sha384(pt.encode()).hexdigest()
            elif algo_lower == "sha224":
                h = hashlib.sha224(pt.encode()).hexdigest()
            elif algo_lower == "ntlm":
                h = hashlib.new("md4", pt.encode("utf-16le")).hexdigest()
            elif algo_lower == "md4":
                h = hashlib.new("md4", pt.encode()).hexdigest()
            else:
                h = f"(unsupported algorithm: {algo})"
            results.append(f"  {algo_lower:10s} : {h}")

        return "\n".join(results)

    elif name == "hash_analyze_potfile":
        potfile = args.get("potfile", str(OUTPUT_DIR / "hashcat.potfile"))
        if not Path(potfile).exists():
            return f"Potfile not found: {potfile}"

        lines = Path(potfile).read_text(encoding="utf-8", errors="replace").splitlines()
        passwords = []
        for line in lines:
            if ":" in line:
                pw = line.split(":", 1)[1]
                passwords.append(pw)

        if not passwords:
            return "No cracked passwords in potfile."

        lengths = [len(p) for p in passwords]
        has_upper = sum(1 for p in passwords if any(c.isupper() for c in p))
        has_lower = sum(1 for p in passwords if any(c.islower() for c in p))
        has_digit = sum(1 for p in passwords if any(c.isdigit() for c in p))
        has_special = sum(1 for p in passwords if any(not c.isalnum() for c in p))

        # Most common passwords
        from collections import Counter

        common = Counter(passwords).most_common(20)

        result = [
            f"Potfile: {potfile}",
            f"Total cracked: {len(passwords)}",
            f"---",
            f"Length: min={min(lengths)} max={max(lengths)} avg={sum(lengths)/len(lengths):.1f}",
            f"Has uppercase: {has_upper}/{len(passwords)} ({has_upper*100//len(passwords)}%)",
            f"Has lowercase: {has_lower}/{len(passwords)} ({has_lower*100//len(passwords)}%)",
            f"Has digits: {has_digit}/{len(passwords)} ({has_digit*100//len(passwords)}%)",
            f"Has special: {has_special}/{len(passwords)} ({has_special*100//len(passwords)}%)",
            f"---",
            f"Top 20 passwords:",
        ]
        for pw, cnt in common:
            result.append(f"  {cnt:4d}x {pw}")

        return "\n".join(result)

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
