#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for LEVIATHAN VS — MCP Plugin Base Class.

Run:
    python -m pytest tests/test_mcp_plugin_base.py -v
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Dict

import pytest

# Add core/ to path so we can import
CORE_DIR = Path(__file__).parent.parent / "core"
sys.path.insert(0, str(CORE_DIR))

from mcp_plugin_base import MCPPluginBase


def _run(coro):
    """Helper: run async coroutine synchronously (Python 3.10+)."""
    return asyncio.run(coro)


# ============================================================================
# TEST PLUGIN
# ============================================================================


class DummyPlugin(MCPPluginBase):
    """Minimal concrete plugin for testing."""

    server_name = "test-dummy-server"
    version = "1.0.0"
    tools = [
        {
            "name": "echo",
            "description": "Echoes input text",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to echo"}
                },
                "required": ["text"],
            },
        },
        {
            "name": "add",
            "description": "Adds two numbers",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "a": {"type": "number"},
                    "b": {"type": "number"},
                },
                "required": ["a", "b"],
            },
        },
    ]

    def __init__(self):
        super().__init__()
        self.initialized = False
        self.shutdown_called = False

    async def on_initialize(self, params):
        self.initialized = True

    async def on_shutdown(self):
        self.shutdown_called = True

    async def dispatch_tool(self, name: str, args: Dict) -> str:
        if name == "echo":
            return args.get("text", "")
        elif name == "add":
            return str(args.get("a", 0) + args.get("b", 0))
        return f"Unknown tool: {name}"


# ============================================================================
# TESTS
# ============================================================================


class TestPluginBase:
    """Test the base class core functionality."""

    def test_response_helper(self):
        resp = MCPPluginBase._response(1, {"key": "val"})
        assert resp == {"jsonrpc": "2.0", "id": 1, "result": {"key": "val"}}

    def test_error_helper(self):
        resp = MCPPluginBase._error(2, -32601, "Not found")
        assert resp == {
            "jsonrpc": "2.0",
            "id": 2,
            "error": {"code": -32601, "message": "Not found"},
        }

    def test_response_with_none_id(self):
        resp = MCPPluginBase._response(None, "ok")
        assert resp["id"] is None

    def test_unimplemented_dispatch_raises(self):
        """Base class dispatch_tool must raise NotImplementedError."""
        base = MCPPluginBase()
        with pytest.raises(NotImplementedError):
            _run(base.dispatch_tool("anything", {}))


class TestInitializeShutdown:
    """Test MCP lifecycle methods."""

    @pytest.fixture
    def plugin(self):
        return DummyPlugin()

    def test_initialize(self, plugin):
        req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        resp = _run(plugin.handle(req))
        assert resp["id"] == 1
        result = resp["result"]
        assert result["protocolVersion"] == "2024-11-05"
        assert result["serverInfo"]["name"] == "test-dummy-server"
        assert result["serverInfo"]["version"] == "1.0.0"
        assert "tools" in result["capabilities"]
        assert plugin.initialized is True

    def test_initialized_notification(self, plugin):
        req = {"jsonrpc": "2.0", "method": "initialized"}
        resp = _run(plugin.handle(req))
        assert resp is None

    def test_shutdown(self, plugin):
        req = {"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": {}}
        resp = _run(plugin.handle(req))
        assert resp["result"] is None
        assert plugin.running is False
        assert plugin.shutdown_called is True


class TestToolsList:
    """Test tools/list method."""

    def test_tools_list(self):
        plugin = DummyPlugin()
        req = {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}
        resp = _run(plugin.handle(req))
        tools = resp["result"]["tools"]
        assert len(tools) == 2
        names = [t["name"] for t in tools]
        assert "echo" in names
        assert "add" in names


class TestToolCall:
    """Test tools/call method."""

    @pytest.fixture
    def plugin(self):
        return DummyPlugin()

    def test_echo_tool(self, plugin):
        req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "hello world"}},
        }
        resp = _run(plugin.handle(req))
        content = resp["result"]["content"]
        assert len(content) == 1
        assert content[0]["type"] == "text"
        assert content[0]["text"] == "hello world"

    def test_add_tool(self, plugin):
        req = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "add", "arguments": {"a": 3, "b": 7}},
        }
        resp = _run(plugin.handle(req))
        assert resp["result"]["content"][0]["text"] == "10"

    def test_unknown_tool(self, plugin):
        req = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "nonexistent", "arguments": {}},
        }
        resp = _run(plugin.handle(req))
        assert "Unknown tool" in resp["result"]["content"][0]["text"]

    def test_tool_exception_returns_error(self):
        """Tool that raises should return isError: True."""

        class BrokenPlugin(MCPPluginBase):
            server_name = "broken"
            version = "0.0.1"
            tools = [
                {
                    "name": "crash",
                    "description": "crashes",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]

            async def dispatch_tool(self, name, args):
                raise RuntimeError("boom")

        plugin = BrokenPlugin()
        req = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "crash", "arguments": {}},
        }
        resp = _run(plugin.handle(req))
        assert resp["result"]["isError"] is True
        assert "boom" in resp["result"]["content"][0]["text"]


class TestResourcesAndPrompts:
    """Test resources/list and prompts/list methods."""

    def test_empty_resources(self):
        plugin = DummyPlugin()
        req = {"jsonrpc": "2.0", "id": 8, "method": "resources/list", "params": {}}
        resp = _run(plugin.handle(req))
        assert resp["result"]["resources"] == []

    def test_empty_prompts(self):
        plugin = DummyPlugin()
        req = {"jsonrpc": "2.0", "id": 9, "method": "prompts/list", "params": {}}
        resp = _run(plugin.handle(req))
        assert resp["result"]["prompts"] == []

    def test_custom_resources(self):
        class WithResources(MCPPluginBase):
            server_name = "res-test"
            version = "1.0.0"
            tools = []
            resources = [{"uri": "test://foo", "name": "Foo"}]

            async def dispatch_tool(self, name, args):
                return ""

        plugin = WithResources()
        req = {"jsonrpc": "2.0", "id": 10, "method": "resources/list", "params": {}}
        resp = _run(plugin.handle(req))
        assert len(resp["result"]["resources"]) == 1


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_unknown_method(self):
        plugin = DummyPlugin()
        req = {"jsonrpc": "2.0", "id": 11, "method": "foo/bar", "params": {}}
        resp = _run(plugin.handle(req))
        assert resp["error"]["code"] == -32601

    def test_notification_returns_none(self):
        plugin = DummyPlugin()
        req = {"jsonrpc": "2.0", "method": "notifications/cancelled"}
        resp = _run(plugin.handle(req))
        assert resp is None

    def test_missing_params(self):
        """Request without params should default to empty dict."""
        plugin = DummyPlugin()
        req = {"jsonrpc": "2.0", "id": 12, "method": "tools/list"}
        resp = _run(plugin.handle(req))
        assert "tools" in resp["result"]

    def test_main_classmethod_exists(self):
        """Verify main() is a classmethod."""
        assert hasattr(DummyPlugin, "main")
        assert callable(DummyPlugin.main)
