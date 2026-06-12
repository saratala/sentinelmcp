"""SentinelMCP Python SDK — 5-line integration for AI agents."""
from .client import AsyncSentinelClient, SentinelClient, SentinelResult
from .exceptions import AuthError, GatewayError, RateLimitError, SentinelError

__version__ = "0.2.0"
__all__ = [
    "SentinelClient",
    "AsyncSentinelClient",
    "SentinelResult",
    "SentinelError",
    "AuthError",
    "RateLimitError",
    "GatewayError",
]
