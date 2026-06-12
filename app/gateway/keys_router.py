"""Per-tenant API key management endpoints.

POST   /keys          — create a new key (returns raw key once)
GET    /keys          — list active keys for a tenant
DELETE /keys/{key_id} — revoke a key immediately
GET    /keys/policy   — list loaded policy rules (for debugging)
"""
from __future__ import annotations

from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.core.auth import require_api_key
from app.core.database import get_db
from app.core.keys import create_key, list_keys, revoke_key
from app.core.policy_engine import get_policy_engine
from app.core.rate_limit import limiter

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/keys", tags=["keys"])


class CreateKeyRequest(BaseModel):
    label: str
    tenant_id: str
    rate_limit_per_min: int = 600
    expires_at: Optional[str] = None   # ISO-8601


class CreateKeyResponse(BaseModel):
    api_key: str          # shown ONCE — store immediately
    key_id: str
    prefix: str
    tenant_id: str
    label: str
    warning: str = "Store this key securely. It will not be shown again."


@router.post("", dependencies=[Depends(require_api_key)])
@limiter.limit("10/minute")
async def create_api_key(
    request: Request,
    body: CreateKeyRequest,
) -> CreateKeyResponse:
    """Create a new per-tenant API key. Returns the raw key exactly once."""
    from datetime import datetime
    expires_at = None
    if body.expires_at:
        try:
            expires_at = datetime.fromisoformat(body.expires_at.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="expires_at must be ISO-8601")

    redis = request.app.state.redis
    async for db in get_db():
        raw_key, row = await create_key(
            db, redis,
            label=body.label,
            tenant_id=body.tenant_id,
            rate_limit_per_min=body.rate_limit_per_min,
            expires_at=expires_at,
        )
        return CreateKeyResponse(
            api_key=raw_key,
            key_id=str(row.id),
            prefix=row.key_prefix,
            tenant_id=row.tenant_id,
            label=row.label,
        )


@router.get("", dependencies=[Depends(require_api_key)])
@limiter.limit("30/minute")
async def list_api_keys(
    request: Request,
    tenant_id: Optional[str] = None,
) -> dict:
    """List active API keys (hashes not returned — keys are write-once)."""
    async for db in get_db():
        rows = await list_keys(db, tenant_id=tenant_id)
        return {
            "keys": [
                {
                    "id": str(r.id),
                    "label": r.label,
                    "tenant_id": r.tenant_id,
                    "prefix": r.key_prefix,
                    "created_at": r.created_at.isoformat(),
                    "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
                    "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                    "rate_limit_per_min": r.rate_limit_per_min,
                    "active": r.active,
                }
                for r in rows
            ],
            "total": len(rows),
        }


@router.delete("/{key_id}", dependencies=[Depends(require_api_key)])
@limiter.limit("10/minute")
async def revoke_api_key(
    request: Request,
    key_id: str,
) -> dict:
    """Revoke an API key immediately — removes from Redis cache and marks inactive."""
    redis = request.app.state.redis
    async for db in get_db():
        revoked = await revoke_key(db, redis, key_id=key_id)
        if not revoked:
            raise HTTPException(status_code=404, detail=f"Key {key_id} not found")
        return {"revoked": key_id, "status": "inactive"}


@router.get("/policy", dependencies=[Depends(require_api_key)])
async def list_policy_rules(request: Request) -> dict:
    """List all loaded policy rules — useful for debugging YAML changes."""
    engine = get_policy_engine()
    from app.core.policy_engine import POLICIES_DIR
    rules = []
    with engine._lock:
        for r in engine._rules:
            rules.append({
                "name": r.name,
                "layer": r.layer,
                "type": r.rule_type,
                "threat_type": r.threat_type,
                "confidence": r.confidence,
                "enabled": r.enabled,
                "owasp_id": r.owasp_id,
            })
    return {
        "rules": rules,
        "total": len(rules),
        "policies_dir": str(POLICIES_DIR),
        "by_layer": {
            "L1": engine.rule_count(1),
            "L2": engine.rule_count(2),
            "L3": engine.rule_count(3),
        },
    }
