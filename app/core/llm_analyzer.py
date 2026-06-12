"""LLM-based semantic analysis for grey-zone risk scores (Layer 4 hybrid path).

Called only when TF-IDF produces a score in the grey zone (0.35 ≤ score < 0.75).

Provider selection (SENTINEL_LLM_PROVIDER):
  "auto"      — try Ollama first (local, free), fall back to Anthropic if key set (default)
  "ollama"    — always use Ollama at SENTINEL_OLLAMA_URL (dev/offline)
  "anthropic" — always use Anthropic API (prod/cloud)

Design constraints:
- Total timeout: 3 seconds (asyncio.wait_for enforced by caller)
- Returns None on any failure (caller falls back to TF-IDF score)
- Temperature=0 for determinism
- max_tokens=256 (JSON answer only)
"""
from __future__ import annotations

import json
from typing import Optional

import httpx
import structlog

log = structlog.get_logger(__name__)

_SYSTEM_PROMPT = (
    "You are a security analyst reviewing MCP (Model Context Protocol) tool call "
    "sequences for signs of data exfiltration or reconnaissance attacks. "
    "Respond ONLY with a valid JSON object — no prose, no markdown fences."
)

_USER_TEMPLATE = """\
Analyze this sequence of tool calls from a single agent session for attack patterns.

Recent tool calls (oldest first):
{tool_calls}

TF-IDF category scores (0-1, higher = more signal):
{category_scores}

TF-IDF aggregate risk score: {tfidf_risk}

Does this sequence look like reconnaissance or data exfiltration?
Consider: unusual breadth across sensitive categories, systematic enumeration, \
credential harvesting, PII collection, file system mapping.

Respond with exactly this JSON structure:
{{"risk_score": <float 0.0-1.0>, "reasoning": "<one sentence>", \
"attack_type": <"reconnaissance"|"data_exfiltration"|"credential_harvesting"|null>, \
"confidence": <"high"|"medium"|"low">}}\
"""


def _build_prompt(window: list[str], category_scores: dict, tfidf_risk: float) -> str:
    recent = window[-10:] if len(window) > 10 else window
    return _USER_TEMPLATE.format(
        tool_calls="\n".join(f"  {i+1}. {c}" for i, c in enumerate(recent)),
        category_scores=", ".join(f"{k}={v:.3f}" for k, v in category_scores.items()),
        tfidf_risk=f"{tfidf_risk:.4f}",
    )


def _parse_result(raw: str, tfidf_risk: float) -> dict:
    result = json.loads(raw.strip())
    score = float(result.get("risk_score", tfidf_risk))
    result["risk_score"] = max(0.0, min(1.0, score))
    return result


async def _call_ollama(prompt: str, ollama_url: str, model: str) -> str:
    """Call Ollama via its OpenAI-compatible /v1/chat/completions endpoint."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
        "max_tokens": 256,
        "stream": False,
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(f"{ollama_url.rstrip('/')}/v1/chat/completions", json=payload)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


async def _call_anthropic(prompt: str, api_key: str, model: str) -> str:
    """Call Anthropic Claude API."""
    from anthropic import AsyncAnthropic
    client = AsyncAnthropic(api_key=api_key)
    response = await client.messages.create(
        model=model,
        max_tokens=256,
        temperature=0,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


async def _ollama_reachable(ollama_url: str) -> bool:
    """Quick liveness check used for auto-detection."""
    try:
        async with httpx.AsyncClient(timeout=0.5) as client:
            r = await client.get(f"{ollama_url.rstrip('/')}/api/tags")
            return r.status_code == 200
    except Exception:
        return False


async def analyze_context(
    session_id: str,
    window: list[str],
    category_scores: dict[str, float],
    tfidf_risk: float,
    provider: str = "auto",
    ollama_url: str = "http://localhost:11434",
    ollama_model: str = "qwen2.5:7b",
    api_key: str = "",
    model: str = "claude-haiku-4-5-20251001",
) -> Optional[dict]:
    """Assess whether a grey-zone tool call sequence is an attack using an LLM.

    Returns dict with risk_score, reasoning, attack_type, confidence — or None on failure.
    """
    prompt = _build_prompt(window, category_scores, tfidf_risk)

    # Resolve "auto": prefer Ollama (local, free) then Anthropic (cloud)
    resolved = provider
    if provider == "auto":
        if await _ollama_reachable(ollama_url):
            resolved = "ollama"
        elif api_key:
            resolved = "anthropic"
        else:
            log.debug("llm_analysis_skipped_no_provider", session=session_id)
            return None

    log.info(
        "llm_analysis_called",
        session=session_id,
        tfidf_risk=tfidf_risk,
        provider=resolved,
        model=ollama_model if resolved == "ollama" else model,
    )

    try:
        if resolved == "ollama":
            raw = await _call_ollama(prompt, ollama_url, ollama_model)
        else:
            raw = await _call_anthropic(prompt, api_key, model)

        result = _parse_result(raw, tfidf_risk)
        result["provider"] = resolved
        log.info(
            "llm_analysis_result",
            session=session_id,
            provider=resolved,
            llm_risk_score=result["risk_score"],
            attack_type=result.get("attack_type"),
            confidence=result.get("confidence"),
        )
        return result

    except Exception as exc:
        log.warning(
            "llm_analysis_failed",
            session=session_id,
            provider=resolved,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return None
