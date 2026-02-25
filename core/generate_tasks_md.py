#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - Generate TASKS.md from .vscode/tasks.json

    Reads all tasks and generates a searchable Markdown reference.

    Usage:
        python core/generate_tasks_md.py              # stdout
        python core/generate_tasks_md.py -o docs/TASKS.md   # to file
================================================================================
"""

import json
import re
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()
PROJECT_DIR = BASE_DIR.parent
TASKS_JSON = PROJECT_DIR / ".vscode" / "tasks.json"


def _strip_jsonc(text: str) -> str:
    """Strip JSONC comments and sanitize invalid escapes."""
    result = []
    i = 0
    in_string = False
    while i < len(text):
        ch = text[i]
        if in_string:
            result.append(ch)
            if ch == "\\" and i + 1 < len(text):
                result.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            result.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < len(text):
            if text[i + 1] == "/":
                while i < len(text) and text[i] != "\n":
                    i += 1
                continue
            if text[i + 1] == "*":
                i += 2
                while i + 1 < len(text) and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i += 2
                continue
        result.append(ch)
        i += 1
    stripped = "".join(result)
    # Sanitize invalid JSON escapes inside strings
    valid_escapes = set('"\\bfnrtu/')
    sanitized = []
    j = 0
    in_str = False
    while j < len(stripped):
        c = stripped[j]
        if in_str:
            if c == "\\" and j + 1 < len(stripped):
                nxt = stripped[j + 1]
                if nxt in valid_escapes:
                    sanitized.append(c)
                    sanitized.append(nxt)
                else:
                    sanitized.append(nxt)  # drop backslash
                j += 2
                continue
            if c == '"':
                in_str = False
            sanitized.append(c)
            j += 1
            continue
        if c == '"':
            in_str = True
        sanitized.append(c)
        j += 1
    return "".join(sanitized)


def load_tasks():
    """Load tasks from tasks.json."""
    text = TASKS_JSON.read_text(encoding="utf-8")
    clean = _strip_jsonc(text)
    data = json.loads(clean)
    return data.get("tasks", [])


def categorize_tasks(tasks):
    """Group tasks by prefix category (e.g., [LEVIATHAN], [ADB], [FRIDA])."""
    categories = {}
    for task in tasks:
        label = task.get("label", "")
        match = re.match(r"\[([^\]]+)\]", label)
        cat = match.group(1) if match else "OTHER"
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(
            {
                "label": label,
                "detail": task.get("detail", ""),
                "type": task.get("type", "shell"),
            }
        )
    return categories


def generate_markdown(categories):
    """Generate Markdown from categorized tasks."""
    total = sum(len(v) for v in categories.values())
    now = datetime.now().strftime("%Y-%m-%d")

    lines = [
        f"# LEVIATHAN VS — Task Reference (v14.2.0)",
        "",
        f"> Auto-generated from `.vscode/tasks.json`.",
        f"> Total: **{total} tasks** across **{len(categories)} categories**.",
        f"> Last updated: {now}",
        "",
        "---",
        "",
        "## Table of Contents",
        "",
    ]

    for cat in sorted(categories.keys()):
        anchor = cat.lower().replace(" ", "-").replace("/", "-")
        count = len(categories[cat])
        lines.append(f"- [{cat} ({count})](#category-{anchor})")

    lines.extend(["", "---", ""])

    for cat in sorted(categories.keys()):
        anchor = cat.lower().replace(" ", "-").replace("/", "-")
        tasks = categories[cat]
        lines.append(f"## Category: {cat}")
        lines.append(f"**{len(tasks)} tasks**")
        lines.append("")
        lines.append("| Task | Description |")
        lines.append("|------|-------------|")
        for t in tasks:
            label = t["label"].replace("|", "\\|")
            detail = t["detail"].replace("|", "\\|") if t["detail"] else "*—*"
            lines.append(f"| `{label}` | {detail} |")
        lines.extend(["", "---", ""])

    return "\n".join(lines)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Generate TASKS.md from tasks.json")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    args = parser.parse_args()

    tasks = load_tasks()
    categories = categorize_tasks(tasks)
    md = generate_markdown(categories)

    if args.output:
        Path(args.output).write_text(md, encoding="utf-8")
        print(
            f"Generated {args.output} ({sum(len(v) for v in categories.values())} tasks)"
        )
    else:
        print(md)


if __name__ == "__main__":
    main()
