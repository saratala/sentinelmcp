"""Auth debug endpoints."""
from __future__ import annotations
from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["auth"])

@router.get("/jwks")
async def get_jwks() -> dict:
    """Returns JWKS public keys for debugging. Returns empty keys array if not configured."""
    from app.config import settings
    if not settings.jwks_url:
        return {"keys": []}
    import httpx
    async with httpx.AsyncClient() as client:
        resp = await client.get(settings.jwks_url, timeout=5.0)
        return resp.json()

@router.get("/status")
async def auth_status() -> dict:
    """Returns current auth configuration (no secrets)."""
    from app.config import settings
    return {
        "api_key_auth": True,
        "jwt_enabled": bool(settings.jwt_secret or settings.jwks_url),
        "jwt_issuer": settings.jwt_issuer or None,
        "jwks_configured": bool(settings.jwks_url),
        "hs256_mode": bool(settings.jwt_secret and not settings.jwks_url),
    }
