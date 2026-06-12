"""SentinelMCP SDK exceptions."""


class SentinelError(Exception):
    """Base exception for all SentinelMCP errors."""
    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.status_code = status_code


class AuthError(SentinelError):
    """API key or JWT token is invalid or expired."""


class RateLimitError(SentinelError):
    """Request rate limit exceeded."""


class GatewayError(SentinelError):
    """Gateway returned an unexpected error."""
