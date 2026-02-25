#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - MCP Plugin Base Class v14.2.0

    Abstract base class for MCP (Model Context Protocol) plugin servers.
    Handles all JSON-RPC 2.0 boilerplate, Content-Length framing, and
    stdio transport so plugin authors only define tools and dispatch logic.

    Usage (minimal plugin):
        from core.mcp_plugin_base import MCPPluginBase

        class MyPlugin(MCPPluginBase):
            server_name = "leviathan-my-server"
            version = "1.0.0"
            tools = [
                {
                    "name": "my_tool",
                    "description": "Does something useful",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "input": {"type": "string", "description": "Input text"}
                        },
                        "required": ["input"]
                    }
                }
            ]

            async def dispatch_tool(self, name: str, args: dict) -> str:
                if name == "my_tool":
                    return f"Result: {args.get('input', '')}"
                return f"Unknown tool: {name}"

        if __name__ == "__main__":
            MyPlugin.main()

    Protocol:
        - JSON-RPC 2.0 over stdio
        - Content-Length framing (MCP standard)
        - Binary mode on Windows (msvcrt)

    Author: ThiagoFrag / LEVIATHAN VS
    Version: 14.1.0
================================================================================
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger("leviathan-mcp-base")


class MCPPluginBase:
    """Abstract base class for Leviathan MCP plugin servers.

    Subclasses MUST define:
        - server_name: str      — Unique server identifier
        - version: str          — Semantic version string
        - tools: List[Dict]     — MCP tool definitions
        - dispatch_tool()       — Tool call handler

    Subclasses MAY override:
        - resources: List[Dict] — MCP resource definitions (default: [])
        - prompts: List[Dict]   — MCP prompt definitions (default: [])
        - on_initialize()       — Custom initialization logic
        - on_shutdown()         — Custom shutdown/cleanup logic
    """

    # --- MUST be overridden by subclasses ---
    server_name: str = "leviathan-plugin"
    version: str = "0.0.0"
    tools: List[Dict] = []

    # --- MAY be overridden ---
    resources: List[Dict] = []
    prompts: List[Dict] = []

    def __init__(self):
        self.running = True
        self._setup_logging()

    def _setup_logging(self):
        """Configure stderr logging for MCP servers."""
        if not logging.getLogger().handlers:
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s [%(levelname)s] %(message)s",
                handlers=[logging.StreamHandler(sys.stderr)],
            )

    # ========================================================================
    # JSON-RPC 2.0 HELPERS
    # ========================================================================

    @staticmethod
    def _response(id: Optional[int], result: Any) -> Dict:
        """Build a JSON-RPC 2.0 success response."""
        return {"jsonrpc": "2.0", "id": id, "result": result}

    @staticmethod
    def _error(id: Optional[int], code: int, msg: str) -> Dict:
        """Build a JSON-RPC 2.0 error response."""
        return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}}

    # ========================================================================
    # LIFECYCLE HOOKS (override in subclass)
    # ========================================================================

    async def on_initialize(self, params: Dict) -> None:
        """Called after 'initialize' request. Override for custom setup."""
        pass

    async def on_shutdown(self) -> None:
        """Called on 'shutdown' request. Override for cleanup."""
        pass

    # ========================================================================
    # TOOL DISPATCH (MUST override in subclass)
    # ========================================================================

    async def dispatch_tool(self, name: str, args: Dict) -> str:
        """Handle a tool call. Must be overridden by subclass.

        Args:
            name: Tool name from tools/call request
            args: Tool arguments dict

        Returns:
            String result to send back to the client.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement dispatch_tool()"
        )

    # ========================================================================
    # MCP REQUEST HANDLER
    # ========================================================================

    async def handle(self, req: Dict) -> Optional[Dict]:
        """Process an incoming MCP JSON-RPC request.

        Routes standard MCP methods to their handlers.
        Subclasses normally don't need to override this.
        """
        method = req.get("method", "")
        params = req.get("params", {})
        rid = req.get("id")

        if method == "initialize":
            await self.on_initialize(params)
            return self._response(
                rid,
                {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": self.server_name,
                        "version": self.version,
                    },
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                },
            )

        elif method == "initialized":
            return None

        elif method == "shutdown":
            self.running = False
            await self.on_shutdown()
            return self._response(rid, None)

        elif method == "tools/list":
            return self._response(rid, {"tools": self.tools})

        elif method == "tools/call":
            name = params.get("name", "")
            tool_args = params.get("arguments", {})
            try:
                result = await self.dispatch_tool(name, tool_args)
                return self._response(
                    rid,
                    {"content": [{"type": "text", "text": str(result)}]},
                )
            except Exception as e:
                logger.error(f"Error in tool '{name}': {e}")
                return self._response(
                    rid,
                    {
                        "content": [{"type": "text", "text": f"ERROR: {e}"}],
                        "isError": True,
                    },
                )

        elif method == "resources/list":
            return self._response(rid, {"resources": self.resources})

        elif method == "prompts/list":
            return self._response(rid, {"prompts": self.prompts})

        elif method.startswith("notifications/"):
            return None

        else:
            return self._error(rid, -32601, f"Unknown method: {method}")

    # ========================================================================
    # STDIO TRANSPORT (Content-Length framing)
    # ========================================================================

    async def run(self):
        """Main event loop — reads from stdin, writes to stdout.

        Uses binary mode on Windows (msvcrt) and Content-Length framing
        per the MCP specification.
        """
        # Binary mode on Windows
        if sys.platform == "win32":
            import msvcrt

            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
            msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)

        # Setup async reader on stdin
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(
            lambda: protocol, sys.stdin.buffer
        )

        logger.info(f"{self.server_name} v{self.version} started")
        buf = b""

        while self.running:
            try:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buf += chunk

                # Process all complete messages in buffer
                while True:
                    if b"Content-Length:" not in buf:
                        break
                    header_end = buf.find(b"\r\n\r\n")
                    if header_end == -1:
                        break

                    # Parse Content-Length header
                    header = buf[:header_end].decode("utf-8")
                    length = 0
                    for line in header.split("\r\n"):
                        if line.startswith("Content-Length:"):
                            length = int(line.split(":")[1].strip())

                    body_start = header_end + 4
                    if len(buf) < body_start + length:
                        break  # Incomplete body, wait for more data

                    # Extract and parse message
                    body = buf[body_start : body_start + length].decode("utf-8")
                    buf = buf[body_start + length :]

                    req = json.loads(body)
                    resp = await self.handle(req)

                    # Send response with Content-Length framing
                    if resp:
                        data = json.dumps(resp).encode("utf-8")
                        frame = f"Content-Length: {len(data)}\r\n\r\n".encode("utf-8")
                        sys.stdout.buffer.write(frame + data)
                        sys.stdout.buffer.flush()

            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                break

        logger.info(f"{self.server_name} stopped")

    # ========================================================================
    # ENTRYPOINT
    # ========================================================================

    @classmethod
    def main(cls):
        """Convenience entrypoint — creates instance and runs event loop.

        Usage in plugins:
            if __name__ == "__main__":
                MyPlugin.main()
        """
        asyncio.run(cls().run())
