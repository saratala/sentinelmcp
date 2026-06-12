"""LangChain callback handler for automatic SentinelMCP protection."""
from __future__ import annotations

from typing import Any, Optional

from .client import AsyncSentinelClient
from .exceptions import SentinelError


class SentinelMCPMiddleware:
    """LangChain BaseCallbackHandler that intercepts tool calls via SentinelMCP.

    Usage:
        from sentinelmcp_sdk.middleware import SentinelMCPMiddleware
        from sentinelmcp_sdk import AsyncSentinelClient

        async with AsyncSentinelClient(api_key="sk-...") as client:
            middleware = SentinelMCPMiddleware(client, "http://my-mcp-server:8001")
            # Pass as callback to LangChain agent
    """

    def __init__(self, client: AsyncSentinelClient, server_url: str, block_on_threat: bool = True):
        self.client = client
        self.server_url = server_url
        self.block_on_threat = block_on_threat

    async def on_tool_start(self, serialized: dict, input_str: str, **kwargs: Any) -> None:
        """Called before a tool runs — analyze the call with SentinelMCP."""
        tool_name = serialized.get("name", "unknown")
        try:
            result = await self.client.analyze(
                self.server_url,
                tool_calls=[{"name": tool_name, "arguments": {"input": input_str}}],
            )
            if result.is_blocked and self.block_on_threat:
                raise SentinelError(
                    f"SentinelMCP blocked tool call '{tool_name}': "
                    f"{result.threats[0].get('pattern', 'threat')} detected"
                )
        except SentinelError:
            raise
        except Exception:
            pass  # Don't block on sentinel errors — fail open

    async def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Called after a tool returns — scan the output for PII/injection."""
        try:
            result = await self.client.analyze(
                self.server_url,
                tool_calls=[{"name": "output_scan", "arguments": {"output": output[:2000]}}],
            )
            if result.is_blocked and self.block_on_threat:
                raise SentinelError(
                    f"SentinelMCP blocked tool output: sensitive data detected"
                )
        except SentinelError:
            raise
        except Exception:
            pass
