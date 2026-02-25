#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - Tentacle Protocol Server v14.2
    Real-Time Semantic Translation Server

    Model Context Protocol Server para traducao semantica em tempo real.
    Integra com VS Code para aplicar regras automaticamente durante digitacao.

    Autor: ThiagoFrag
    Versao: 14.2.0
================================================================================
"""

import asyncio
import json
import logging
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("leviathan-mcp")

# ============================================================================
# CONSTANTES
# ============================================================================

VERSION = "14.2.0"
SERVER_NAME = "leviathan-tentacle-server"

# ============================================================================
# MCP PROTOCOL IMPLEMENTATION
# ============================================================================


class SemanticEngine:
    """Motor de traducao semantica."""

    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.rules: Dict[str, str] = {}
        self.reverse_rules: Dict[str, str] = {}
        self._load_rules()

    def _load_rules(self) -> None:
        """Carrega regras do config.json."""
        if not self.config_path.exists():
            logger.warning(f"Config nao encontrado: {self.config_path}")
            return

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.rules = {k: v for k, v in data.items() if not k.startswith("_")}
            self.reverse_rules = {v: k for k, v in self.rules.items()}
            logger.info(f"Carregadas {len(self.rules)} regras de traducao")
        except Exception as e:
            logger.error(f"Erro ao carregar config: {e}")

    def reload_rules(self) -> int:
        """Recarrega regras do arquivo."""
        self._load_rules()
        return len(self.rules)

    def translate(self, text: str, mode: str = "encode") -> tuple[str, List[Dict]]:
        """Traduz texto aplicando regras."""
        rules = self.rules if mode == "encode" else self.reverse_rules
        changes = []
        result = text

        # Ordenar por tamanho (maior primeiro)
        sorted_rules = sorted(rules.items(), key=lambda x: len(x[0]), reverse=True)

        for original, replacement in sorted_rules:
            pattern = re.compile(rf"\b{re.escape(original)}\b", re.IGNORECASE)
            matches = list(pattern.finditer(result))

            if matches:
                for match in reversed(matches):
                    start, end = match.span()
                    matched_text = match.group(0)

                    # Preservar case
                    if matched_text.isupper():
                        new_text = replacement.upper()
                    elif matched_text[0].isupper():
                        new_text = replacement.capitalize()
                    else:
                        new_text = replacement

                    result = result[:start] + new_text + result[end:]
                    changes.append(
                        {
                            "original": original,
                            "replacement": replacement,
                            "position": start,
                            "length": len(matched_text),
                        }
                    )

        return result, changes

    def find_sensitive_terms(self, text: str) -> List[Dict]:
        """Encontra termos sensiveis no texto."""
        findings = []

        for term in self.rules.keys():
            pattern = re.compile(rf"\b{re.escape(term)}\b", re.IGNORECASE)
            for match in pattern.finditer(text):
                findings.append(
                    {
                        "term": term,
                        "sanitized": self.rules[term],
                        "start": match.start(),
                        "end": match.end(),
                        "line": text[: match.start()].count("\n") + 1,
                        "column": match.start() - text.rfind("\n", 0, match.start()),
                    }
                )

        return findings

    def get_completions(self, prefix: str) -> List[Dict]:
        """Retorna sugestoes de autocompletar."""
        completions = []
        prefix_lower = prefix.lower()

        for original, sanitized in self.rules.items():
            if sanitized.lower().startswith(prefix_lower):
                completions.append(
                    {
                        "label": sanitized,
                        "detail": f"[HOG] Traduz para: {original}",
                        "insertText": sanitized,
                        "kind": 1,  # Text
                    }
                )

        return completions[:20]  # Limitar a 20 sugestoes


class MCPServer:
    """Servidor MCP para integracao com VS Code."""

    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.config_path = base_path / "config.json"
        self.engine = SemanticEngine(self.config_path)
        self.request_id = 0
        self.running = True

    async def handle_request(self, request: Dict) -> Optional[Dict]:
        """Processa uma requisicao MCP."""
        method = request.get("method", "")
        params = request.get("params", {})
        request_id: Optional[int] = request.get("id")

        logger.info(f"Requisicao: {method}")

        try:
            if method == "initialize":
                return self._handle_initialize(request_id, params)

            elif method == "initialized":
                return None  # Notificacao, sem resposta

            elif method == "shutdown":
                self.running = False
                return {"jsonrpc": "2.0", "id": request_id, "result": None}

            elif method == "tools/list":
                return self._handle_tools_list(request_id)

            elif method == "tools/call":
                return await self._handle_tool_call(request_id, params)

            elif method == "resources/list":
                return self._handle_resources_list(request_id)

            elif method == "resources/read":
                return self._handle_resource_read(request_id, params)

            elif method == "prompts/list":
                return self._handle_prompts_list(request_id)

            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32601,
                        "message": f"Metodo nao encontrado: {method}",
                    },
                }

        except Exception as e:
            logger.error(f"Erro ao processar {method}: {e}")
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32603, "message": str(e)},
            }

    def _handle_initialize(self, request_id: Optional[int], params: Dict) -> Dict:
        """Inicializa o servidor MCP."""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
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

    def _handle_tools_list(self, request_id: Optional[int]) -> Dict:
        """Lista ferramentas disponiveis."""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "encode",
                        "description": "Sanitiza texto substituindo termos sensiveis por termos neutros de Teoria de Grafos",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "text": {
                                    "type": "string",
                                    "description": "Texto para sanitizar",
                                }
                            },
                            "required": ["text"],
                        },
                    },
                    {
                        "name": "decode",
                        "description": "Restaura termos originais a partir de termos sanitizados",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "text": {
                                    "type": "string",
                                    "description": "Texto para restaurar",
                                }
                            },
                            "required": ["text"],
                        },
                    },
                    {
                        "name": "check",
                        "description": "Verifica se o texto contem termos sensiveis",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "text": {
                                    "type": "string",
                                    "description": "Texto para verificar",
                                }
                            },
                            "required": ["text"],
                        },
                    },
                    {
                        "name": "find_terms",
                        "description": "Encontra e lista todos os termos sensiveis no texto com posicoes",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "text": {
                                    "type": "string",
                                    "description": "Texto para analisar",
                                }
                            },
                            "required": ["text"],
                        },
                    },
                    {
                        "name": "reload_rules",
                        "description": "Recarrega as regras de traducao do config.json",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                    {
                        "name": "get_rules",
                        "description": "Retorna todas as regras de traducao carregadas",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "category": {
                                    "type": "string",
                                    "description": "Filtrar por categoria (opcional)",
                                }
                            },
                        },
                    },
                    {
                        "name": "translate_file",
                        "description": "Traduz um arquivo completo",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "file_path": {
                                    "type": "string",
                                    "description": "Caminho do arquivo",
                                },
                                "mode": {
                                    "type": "string",
                                    "enum": ["encode", "decode"],
                                    "description": "Modo de traducao",
                                },
                            },
                            "required": ["file_path", "mode"],
                        },
                    },
                ]
            },
        }

    async def _handle_tool_call(self, request_id: Optional[int], params: Dict) -> Dict:
        """Executa uma ferramenta."""
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if tool_name == "encode":
            text = arguments.get("text", "")
            result, changes = self.engine.translate(text, "encode")
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "translated": result,
                                    "changes_count": len(changes),
                                    "changes": changes[:10],
                                },
                                indent=2,
                            ),
                        }
                    ]
                },
            }

        elif tool_name == "decode":
            text = arguments.get("text", "")
            result, changes = self.engine.translate(text, "decode")
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "restored": result,
                                    "changes_count": len(changes),
                                    "changes": changes[:10],
                                },
                                indent=2,
                            ),
                        }
                    ]
                },
            }

        elif tool_name == "check":
            text = arguments.get("text", "")
            findings = self.engine.find_sensitive_terms(text)
            is_clean = len(findings) == 0
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "is_clean": is_clean,
                                    "sensitive_terms_found": len(findings),
                                    "findings": findings[:20],
                                },
                                indent=2,
                            ),
                        }
                    ]
                },
            }

        elif tool_name == "find_terms":
            text = arguments.get("text", "")
            findings = self.engine.find_sensitive_terms(text)
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {"total_findings": len(findings), "findings": findings},
                                indent=2,
                            ),
                        }
                    ]
                },
            }

        elif tool_name == "reload_rules":
            count = self.engine.reload_rules()
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Regras recarregadas: {count} regras ativas",
                        }
                    ]
                },
            }

        elif tool_name == "get_rules":
            category = arguments.get("category", "").lower()
            rules = self.engine.rules

            if category:
                rules = {
                    k: v
                    for k, v in rules.items()
                    if category in k.lower() or category in v.lower()
                }

            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {"total_rules": len(rules), "rules": rules}, indent=2
                            ),
                        }
                    ]
                },
            }

        elif tool_name == "translate_file":
            file_path = Path(arguments.get("file_path", ""))
            mode = arguments.get("mode", "encode")

            if not file_path.is_absolute():
                file_path = self.base_path / file_path

            if not file_path.exists():
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Erro: Arquivo nao encontrado: {file_path}",
                            }
                        ],
                        "isError": True,
                    },
                }

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            result, changes = self.engine.translate(content, mode)

            # Backup antes de sobrescrever
            backup_path = file_path.with_suffix(file_path.suffix + ".bak")
            shutil.copy2(file_path, backup_path)
            logger.info(f"Backup criado: {backup_path}")

            # Salvar arquivo traduzido
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(result)

            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "file": str(file_path),
                                    "mode": mode,
                                    "changes_count": len(changes),
                                    "success": True,
                                },
                                indent=2,
                            ),
                        }
                    ]
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32601,
                "message": f"Ferramenta nao encontrada: {tool_name}",
            },
        }

    def _handle_resources_list(self, request_id: Optional[int]) -> Dict:
        """Lista recursos disponiveis."""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "resources": [
                    {
                        "uri": "megazord://config",
                        "name": "Regras de Traducao",
                        "description": "Configuracao completa de regras semanticas",
                        "mimeType": "application/json",
                    },
                    {
                        "uri": "megazord://stats",
                        "name": "Estatisticas",
                        "description": "Estatisticas do motor de traducao",
                        "mimeType": "application/json",
                    },
                ]
            },
        }

    def _handle_resource_read(self, request_id: Optional[int], params: Dict) -> Dict:
        """Le um recurso."""
        uri = params.get("uri", "")

        if uri == "megazord://config":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(self.engine.rules, indent=2),
                        }
                    ]
                },
            }

        elif uri == "megazord://stats":
            stats = {
                "version": VERSION,
                "rules_count": len(self.engine.rules),
                "categories": {
                    "security": len(
                        [
                            k
                            for k in self.engine.rules
                            if any(
                                x in k for x in ["bypass", "exploit", "vulnerability"]
                            )
                        ]
                    ),
                    "malware": len(
                        [
                            k
                            for k in self.engine.rules
                            if any(x in k for x in ["virus", "trojan", "malware"])
                        ]
                    ),
                    "attacks": len(
                        [
                            k
                            for k in self.engine.rules
                            if any(x in k for x in ["xss", "sql", "injection"])
                        ]
                    ),
                    "access": len(
                        [
                            k
                            for k in self.engine.rules
                            if any(x in k for x in ["root", "admin", "shell"])
                        ]
                    ),
                },
            }
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(stats, indent=2),
                        }
                    ]
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32602, "message": f"Recurso nao encontrado: {uri}"},
        }

    def _handle_prompts_list(self, request_id: Optional[int]) -> Dict:
        """Lista prompts disponiveis."""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "prompts": [
                    {
                        "name": "sanitize_code",
                        "description": "Sanitiza codigo para envio seguro a IAs",
                        "arguments": [
                            {
                                "name": "code",
                                "description": "Codigo a sanitizar",
                                "required": True,
                            }
                        ],
                    },
                    {
                        "name": "restore_code",
                        "description": "Restaura codigo apos resposta da IA",
                        "arguments": [
                            {
                                "name": "code",
                                "description": "Codigo a restaurar",
                                "required": True,
                            }
                        ],
                    },
                ]
            },
        }

    def _send_response(self, response: Dict) -> None:
        """Envia resposta com Content-Length framing (MCP protocol)."""
        body_bytes = json.dumps(response).encode("utf-8")
        header = f"Content-Length: {len(body_bytes)}\r\n\r\n".encode("utf-8")
        sys.stdout.buffer.write(header + body_bytes)
        sys.stdout.buffer.flush()

    def _read_message(self) -> Optional[Dict]:
        """Le uma mensagem com Content-Length framing do stdin."""
        # Ler headers
        content_length = 0
        while True:
            line = sys.stdin.readline()
            if not line:
                return None  # EOF
            line = line.strip()
            if not line:
                break  # Header vazio = fim dos headers
            if line.lower().startswith("content-length:"):
                content_length = int(line.split(":", 1)[1].strip())

        if content_length == 0:
            return None

        # Ler body
        body = sys.stdin.read(content_length)
        if not body:
            return None

        try:
            return json.loads(body)
        except json.JSONDecodeError as e:
            logger.error(f"JSON invalido: {e}")
            return None

    async def run_stdio(self):
        """Executa servidor via stdin/stdout com Content-Length framing."""
        logger.info(f"LEVIATHAN MCP Server v{VERSION} iniciado")
        logger.info(f"Config: {self.config_path}")
        logger.info(f"Regras: {len(self.engine.rules)}")

        loop = asyncio.get_event_loop()

        while self.running:
            try:
                # Ler mensagem com Content-Length framing
                request = await loop.run_in_executor(None, self._read_message)

                if request is None:
                    break

                # Processar requisicao
                response = await self.handle_request(request)

                # Enviar resposta com Content-Length framing
                if response:
                    await loop.run_in_executor(None, self._send_response, response)

            except Exception as e:
                logger.error(f"Erro no loop principal: {e}")
                break

        logger.info("Servidor encerrado")


# ============================================================================
# PONTO DE ENTRADA
# ============================================================================


def main():
    """Funcao principal."""
    import argparse

    parser = argparse.ArgumentParser(description="MEGAZORD MCP Server")
    parser.add_argument("--config", "-c", type=str, help="Caminho do config.json")
    args = parser.parse_args()

    # Determinar caminho base
    if args.config:
        config_path = Path(args.config)
        base_path = config_path.parent
    else:
        base_path = Path(__file__).parent.resolve()

    # Criar e executar servidor
    server = MCPServer(base_path)
    asyncio.run(server.run_stdio())


if __name__ == "__main__":
    main()
