"""Layer 4 — context accumulation and semantic mosaic detection.

Maintains a sliding window of the last N tool calls per agent session.
A TF-IDF classifier scores the accumulated call history against sensitive
data categories (credentials, PII, files, email, calendar).
When the aggregate risk score exceeds the threshold an alert fires.

Hybrid analysis:
- TF-IDF always runs first (<3ms, always fast).
- If risk_score is in the grey zone (llm_grey_zone_min ≤ score < llm_grey_zone_max),
  Claude Haiku is called for a semantic second opinion (3s timeout, fail-open).
- TF-IDF score ≥ llm_grey_zone_max → alert immediately (no LLM needed, confident).
- TF-IDF score < llm_grey_zone_min → pass (clearly safe, no LLM needed).
- If LLM call fails/times out → fall back to TF-IDF result.

Runs in parallel with the other layers — never serially. Latency budget: <3ms for
the TF-IDF path; grey-zone adds up to 3s for the LLM call.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Optional

import structlog
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

from app.models.schemas import ContextRiskResult

log = structlog.get_logger(__name__)

# Sliding window size per session.
WINDOW_SIZE = 20

# Risk score threshold above which a mosaic alert fires.
RISK_THRESHOLD = 0.75

# Sensitive data category reference documents used by the TF-IDF classifier.
# Each entry represents one category that an attacker might be assembling.
CATEGORY_REFERENCES: dict[str, str] = {
    "credentials": (
        "password secret api key token credential auth login oauth bearer "
        "private key certificate private_key client_secret access_token "
        "refresh_token ssh_key pgp signing_key"
    ),
    "pii": (
        "name email phone address ssn social security date of birth dob "
        "passport driver license national id tax id credit card bank account "
        "medical record health insurance biometric"
    ),
    "files": (
        "file read write download upload list directory path filesystem "
        "document spreadsheet database backup archive zip tar"
    ),
    "email_calendar": (
        "email send receive inbox calendar event meeting schedule appointment "
        "contact message thread attachment reminder"
    ),
    "system": (
        "environment variable shell execute command process memory network "
        "socket port firewall registry config infrastructure"
    ),
}

# Pre-built corpus: one doc per category reference + a neutral doc.
_CORPUS = list(CATEGORY_REFERENCES.values()) + ["neutral general purpose action"]
_CATEGORY_NAMES = list(CATEGORY_REFERENCES.keys())

# Fit the vectoriser once at import time — no per-request I/O.
_VECTORIZER = TfidfVectorizer(stop_words="english", sublinear_tf=True)
_CORPUS_MATRIX = _VECTORIZER.fit_transform(_CORPUS)


def _score_text(text: str) -> dict[str, float]:
    """Return a cosine-similarity score per category for ``text``."""
    vec = _VECTORIZER.transform([text])
    sims = cosine_similarity(vec, _CORPUS_MATRIX[: len(_CATEGORY_NAMES)]).flatten()
    return {name: float(round(score, 4)) for name, score in zip(_CATEGORY_NAMES, sims)}


def _mosaic_risk(category_scores: dict[str, float]) -> float:
    """Aggregate per-category scores into a single mosaic risk score.

    The mosaic threat comes from *breadth* — accessing many categories signals
    reconnaissance. Score = weighted combo of max individual + category spread.
    """
    scores = list(category_scores.values())
    if not scores:
        return 0.0
    max_score = max(scores)
    # Count categories with meaningful signal (>0.1).
    active_categories = sum(1 for s in scores if s > 0.1)
    breadth_bonus = min(active_categories / len(scores), 1.0) * 0.3
    return round(min(max_score + breadth_bonus, 1.0), 4)


class ContextLayer:
    """Layer 4 — sliding-window semantic mosaic scorer backed by Redis."""

    def __init__(
        self,
        redis_client: Any,
        window_size: int = WINDOW_SIZE,
        risk_threshold: float = RISK_THRESHOLD,
        llm_analysis_enabled: bool = False,
        anthropic_api_key: str = "",
        llm_analysis_model: str = "claude-haiku-4-5-20251001",
        llm_grey_zone_min: float = 0.35,
        llm_grey_zone_max: float = 0.75,
    ) -> None:
        self._redis = redis_client
        self._window = window_size
        self._threshold = risk_threshold
        self._llm_enabled = llm_analysis_enabled
        self._anthropic_api_key = anthropic_api_key
        self._llm_model = llm_analysis_model
        self._grey_zone_min = llm_grey_zone_min
        self._grey_zone_max = llm_grey_zone_max

    def _key(self, session_id: str) -> str:
        return f"ctx:{session_id}"

    async def _get_window(self, session_id: str) -> list[str]:
        """Return the current call window for a session (newest last)."""
        raw = await self._redis.lrange(self._key(session_id), 0, -1)
        return raw if raw else []

    async def _push_call(self, session_id: str, text: str) -> None:
        """Append a call description to the window, trimming to WINDOW_SIZE."""
        key = self._key(session_id)
        await self._redis.rpush(key, text)
        await self._redis.ltrim(key, -self._window, -1)
        await self._redis.expire(key, 3600)

    def _call_text(self, tool_name: str, params: dict[str, Any]) -> str:
        """Flatten a tool call into a single text string for scoring."""
        try:
            param_str = json.dumps(params, default=str)
        except Exception:
            param_str = str(params)
        return f"{tool_name} {param_str}"

    def _in_grey_zone(self, score: float) -> bool:
        """Return True if score is in the LLM grey zone."""
        return self._grey_zone_min <= score < self._grey_zone_max

    async def _try_llm_analysis(
        self,
        session_id: str,
        window: list[str],
        category_scores: dict[str, float],
        tfidf_risk: float,
    ) -> Optional[dict]:
        """Attempt LLM analysis with a 3s timeout. Returns None on any failure."""
        # Lazy import to avoid startup cost when LLM is disabled
        from app.core.llm_analyzer import analyze_context

        try:
            return await asyncio.wait_for(
                analyze_context(
                    session_id=session_id,
                    window=window,
                    category_scores=category_scores,
                    tfidf_risk=tfidf_risk,
                    api_key=self._anthropic_api_key,
                    model=self._llm_model,
                ),
                timeout=3.0,
            )
        except asyncio.TimeoutError:
            log.warning(
                "llm_analysis_timeout",
                session=session_id,
                tfidf_risk=tfidf_risk,
            )
            return None
        except Exception as exc:
            log.warning(
                "llm_analysis_failed",
                session=session_id,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return None

    async def evaluate(
        self,
        session_id: str,
        tool_name: str,
        params: dict[str, Any],
    ) -> ContextRiskResult:
        """Record a tool call and return the current session's mosaic risk."""
        t0 = time.perf_counter()

        call_text = self._call_text(tool_name, params)
        await self._push_call(session_id, call_text)
        window = await self._get_window(session_id)

        # Score the full window as one aggregated document.
        combined = " ".join(window)
        category_scores = _score_text(combined)
        risk_score = _mosaic_risk(category_scores)

        # ── Hybrid LLM path (grey zone only) ──────────────────────────────────
        llm_result: Optional[dict] = None
        llm_used = False

        should_call_llm = (
            self._llm_enabled
            and bool(self._anthropic_api_key)
            and self._in_grey_zone(risk_score)
        )

        if should_call_llm:
            llm_result = await self._try_llm_analysis(
                session_id=session_id,
                window=window,
                category_scores=category_scores,
                tfidf_risk=risk_score,
            )
            if llm_result is not None:
                llm_used = True
                llm_risk = llm_result["risk_score"]

                if llm_risk > risk_score:
                    log.info(
                        "llm_upgraded_risk_score",
                        session=session_id,
                        tfidf_risk=risk_score,
                        llm_risk=llm_risk,
                        attack_type=llm_result.get("attack_type"),
                    )
                elif llm_risk < risk_score:
                    log.info(
                        "llm_downgraded_risk_score",
                        session=session_id,
                        tfidf_risk=risk_score,
                        llm_risk=llm_risk,
                    )

                risk_score = llm_risk

        alerted = risk_score >= self._threshold

        if alerted:
            log.warning(
                "mosaic_risk_threshold_exceeded",
                session=session_id,
                risk_score=risk_score,
                category_scores=category_scores,
                window_size=len(window),
                llm_used=llm_used,
            )

        return ContextRiskResult(
            session_id=session_id,
            tool_name=tool_name,
            window_size=len(window),
            category_scores=category_scores,
            risk_score=risk_score,
            alerted=alerted,
            latency_ms=round((time.perf_counter() - t0) * 1000, 3),
            llm_analysis=llm_result,
        )

    async def clear_session(self, session_id: str) -> None:
        """Remove a session's call window (e.g. on session end)."""
        await self._redis.delete(self._key(session_id))
