"""
================================================================================
    LEVIATHAN VS - LDPlayer Control Module v4.0
    Complete MCP Server for LDPlayer Administration

    ADB + Frida + LDConsole + Protection Bypass + Script Library

    Modules:
        adb_manager       - ADB wrapper (connect, shell, apps, files, input, network, logcat)
        frida_engine      - Frida instrumentation (attach, hook, intercept, memory, trace)
        ldconsole         - LDPlayer CLI wrapper (instances, hardware, snapshots, profiles)
        protection_bypass - Universal protection bypass (SSL, root, emu, frida, integrity)
        mcp_ldplayer      - MCP Server (JSON-RPC 2.0 stdio, 90+ tools, Content-Length framing)

    Frida Scripts (frida_scripts/):
        ssl_bypass.js, root_bypass.js, emulator_bypass.js, frida_bypass.js,
        network_interceptor.js, crypto_interceptor.js, universal_bypass.js,
        game_inspector.js

    Autor: ThiagoFrag / LEVIATHAN VS
    Versao: 4.0.0
================================================================================
"""

__version__ = "4.0.0"
__author__ = "ThiagoFrag"
__all__ = [
    "adb_manager",
    "frida_engine",
    "ldconsole",
    "protection_bypass",
    "orchestrator",
    "leviathan_cli",
    "mcp_ldplayer",
]


# Lazy imports for convenience
def get_server(config_path=None):
    """Create and return a configured MCPLDPlayerServer instance."""
    from .mcp_ldplayer import MCPLDPlayerServer

    return MCPLDPlayerServer(config_path=config_path)


def get_adb(**kwargs):
    """Create and return an ADBManager instance."""
    from .adb_manager import ADBManager

    return ADBManager(**kwargs)


def get_frida(**kwargs):
    """Create and return a FridaEngine instance."""
    from .frida_engine import FridaEngine

    return FridaEngine(**kwargs)


def get_ldconsole(**kwargs):
    """Create and return an LDConsole instance."""
    from .ldconsole import LDConsole

    return LDConsole(**kwargs)


def get_orchestrator(config_path=None):
    """Create and return an Orchestrator instance."""
    from .orchestrator import Orchestrator

    return Orchestrator(config_path=config_path)
