#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS — Shared ANSI Color Definitions

    Centralized terminal color codes used across all Leviathan modules.
    Import this instead of redefining Colors in every file.

    Usage:
        from colors import Colors
        print(f"{Colors.GREEN}Success{Colors.RESET}")
================================================================================
"""

import os


class Colors:
    """ANSI escape codes for terminal colors."""

    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[35m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


def enable_ansi():
    """Enable ANSI escape sequences on Windows."""
    if os.name == "nt":
        os.system("")


def colorize(text: str, color: str) -> str:
    """Wrap text in the given ANSI color code."""
    return f"{color}{text}{Colors.RESET}"
