"""LLM-based semantic analysis for grey-zone risk scores (Layer 4 hybrid path).

Called only when TF-IDF produces a score in the grey zone (0.35 ≤ score < 0.75).
Uses Claude Haiku for fast, cheap second-opinion analysis.

Design constraints:
- Total timeout: 3 seconds (asyncio.wait_for enforced by caller)
- Returns None on any failure (caller falls back to TF-IDF score)
- Temperature=0 for determinism
- max_tokens=256 (JSON answer only)
"""
from __future__ import annotations

import json
from typing import Optional

import structlog
from anthropic import AsyncAnthropic

log = structlog.get_logger(__name__)

_SYSTEM_PROMPT = """\
You are a security analyst reviewing MCP (Model Context Protocol) tool call sequences \
for signs of data exfiltration or reconnaissance attacks. \
Respond ONLY with a valid JSON object — no prose, no markdown fences.\
"""

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


async def analyze_context(
    session_id: str,
    window: list[str],
    category_scores: dict[str, float],
    tfidf_risk: float,
    api_key: str,
    model: str,
) -> Optional[dict]:
    """Call Claude to assess whether a grey-zone tool call sequence is an attack.

    Args:
        session_id: Session identifier (for logging only).
        window: Last N tool call text strings, oldest first.
        category_scores: Per-category TF-IDF scores.
        tfidf_risk: Aggregate TF-IDF risk score (in grey zone).
        api_key: Anthropic API key.
        model: Claude model ID to use.

    Returns:
        Dict with keys risk_score, reasoning, attack_type, confidence — or None on failure.
    """
    log.info("llm_analysis_called", session=session_id, tfidf_risk=tfidf_risk, model=model)

    # Show at most the last 10 calls to keep the prompt short
    recent_calls = window[-10:] if len(window) > 10 else window
    tool_calls_text = "\n".join(f"  {i+1}. {call}" for i, call in enumerate(recent_calls))
    scores_text = ", ".join(f"{k}={v:.3f}" for k, v in category_scores.items())

    prompt = _USER_TEMPLATE.format(
        tool_calls=tool_calls_text,
        category_scores=scores_text,
        tfidf_risk=f"{tfidf_risk:.4f}",
    )

    try:
        client = AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model=model,
            max_tokens=256,
            temperature=0,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        raw_text = response.content[0].text.strip()
        result = json.loads(raw_text)

        # Validate required fields and clamp risk_score
        risk_score = float(result.get("risk_score", tfidf_risk))
        risk_score = max(0.0, min(1.0, risk_score))
        result["risk_score"] = risk_score

        log.info(
            "llm_analysis_result",
            session=session_id,
            llm_risk_score=risk_score,
            attack_type=result.get("attack_type"),
            confidence=result.get("confidence"),
            tfidf_risk=tfidf_risk,
        )
        return result

    except Exception as exc:
        log.warning(
            "llm_analysis_failed",
            session=session_id,
            error=str(exc),
            error_type=type(exc).__name__,
            tfidf_risk=tfidf_risk,
        )
        return None
