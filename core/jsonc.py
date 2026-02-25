#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS — Shared JSONC Utilities

    Parse JSONC (JSON with Comments) files commonly used by VS Code.
    Handles // comments, /* */ block comments, and invalid backslash
    escapes found in VS Code tasks.json PowerShell commands.

    Usage:
        from jsonc import load_jsonc, strip_jsonc_comments
================================================================================
"""

import json
import re
from pathlib import Path
from typing import Any


def strip_jsonc_comments(text: str) -> str:
    """Remove // and /* */ comments from JSONC, preserving strings.

    Walks the text character by character to avoid stripping comment
    sequences that appear inside quoted strings.
    """
    result = []
    i = 0
    in_string = False
    length = len(text)

    while i < length:
        ch = text[i]

        # Handle string boundaries
        if ch == '"' and (i == 0 or text[i - 1] != "\\"):
            in_string = not in_string
            result.append(ch)
            i += 1
            continue

        if in_string:
            result.append(ch)
            i += 1
            continue

        # Block comment /* ... */
        if ch == "/" and i + 1 < length and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            if end == -1:
                break
            i = end + 2
            continue

        # Line comment // ...
        if ch == "/" and i + 1 < length and text[i + 1] == "/":
            end = text.find("\n", i)
            if end == -1:
                break
            i = end
            continue

        result.append(ch)
        i += 1

    return "".join(result)


def sanitize_json_escapes(text: str) -> str:
    r"""Fix invalid backslash escapes inside JSON strings.

    VS Code configs (e.g. tasks.json) often embed PowerShell commands
    containing literal sequences like \e[ (ANSI escape) that are invalid
    in strict JSON.  This doubles any backslash inside a quoted string
    that is NOT followed by a valid JSON escape character.

    Valid JSON escapes: \" \\ \/ \b \f \n \r \t \uXXXX
    """
    valid_escapes = set('"\\/bfnrtu')
    result = []
    i = 0
    in_string = False
    length = len(text)

    while i < length:
        ch = text[i]

        if ch == '"' and (i == 0 or text[i - 1] != "\\"):
            in_string = not in_string
            result.append(ch)
            i += 1
            continue

        if in_string and ch == "\\" and i + 1 < length:
            next_ch = text[i + 1]
            if next_ch not in valid_escapes:
                result.append("\\\\")
            else:
                result.append(ch)
            i += 1
            continue

        result.append(ch)
        i += 1

    return "".join(result)


def load_jsonc(path: Path) -> Any:
    """Load a JSONC file, stripping comments and fixing invalid escapes."""
    raw = path.read_text(encoding="utf-8")
    cleaned = strip_jsonc_comments(raw)
    cleaned = sanitize_json_escapes(cleaned)
    return json.loads(cleaned)
