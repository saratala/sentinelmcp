# Provisional Patent Application Draft
## SentinelMCP — Sliding-Window Behavioral Analysis with LLM Grey-Zone Adjudication for AI Agent Security

**Filing basis:** 35 U.S.C. § 111(b) Provisional Application  
**Status:** DRAFT — review with patent attorney before filing  
**Estimated filing cost:** ~$320 (USPTO micro-entity fee) + attorney conversion ~$8,000–$15,000  
**Priority window:** 12 months from filing date to convert to utility application  

---

## Title

**SYSTEM AND METHOD FOR DETECTING COORDINATED DATA EXFILTRATION IN AI AGENT SESSIONS USING SLIDING-WINDOW TERM FREQUENCY ANALYSIS WITH ADAPTIVE LLM ADJUDICATION**

---

## Field of the Invention

This invention relates to cybersecurity for artificial intelligence (AI) agent systems, and more particularly to real-time detection of multi-step coordinated attack patterns in AI agent tool-call sessions using sliding-window behavioral analysis combined with large language model (LLM) semantic adjudication for ambiguous threat signals.

---

## Background

AI agent systems (including those implementing the Model Context Protocol, MCP) execute sequences of tool calls against external services. A single tool call — reading a file, listing users, or checking environment variables — may appear benign in isolation. However, an attacker can orchestrate a sequence of individually innocuous calls that, in combination, constitute a coordinated exfiltration or reconnaissance attack. This pattern is known as a "mosaic attack."

Existing security approaches suffer from a fundamental limitation: they evaluate each tool call independently. Point-in-time inspection cannot detect patterns that only emerge across time. Furthermore, fixed-threshold detection systems produce binary allow/deny decisions, failing in the "grey zone" where a sequence is statistically elevated but not definitively malicious.

No prior art combines (1) session-scoped sliding-window frequency analysis across categorical threat dimensions with (2) dynamic LLM-based adjudication for grey-zone scores with (3) configurable provider fallback that preserves availability when cloud AI services are unavailable.

Citibank US12450494B1 covers AI agent action validation using generative AI but does not teach session-level behavioral analysis or categorical mosaic scoring. Meta LlamaFirewall (arXiv:2505.03574) addresses per-call prompt injection but not multi-call behavioral patterns.

---

## Summary of the Invention

The present invention provides a real-time security gateway for AI agent systems that detects multi-step coordinated attacks by:

1. Maintaining a sliding window of tool-call records per session
2. Computing per-call and aggregate TF-IDF scores across a fixed taxonomy of threat categories
3. Applying configurable thresholds to distinguish clean, grey-zone, and blocked sessions
4. For grey-zone sessions, invoking an LLM (local or cloud) to perform semantic adjudication
5. Resolving the LLM provider dynamically with a priority chain and silent fallback

---

## Detailed Description of Preferred Embodiments

### 1. System Architecture

The system comprises four sequential processing layers operating on each tool call:

- **Layer 1 (Schema):** Validates tool schemas using SHA-256 hash-watch and cryptographic HMAC attestation. Detects tool poisoning and rug-pull attacks via regex pattern matching and a registry of known-bad tool schemas.
- **Layer 2 (Parameter):** Validates tool invocation parameters against JSON Schema. Detects dangerous argument patterns (credential dumps, shell injection, privilege escalation).
- **Layer 3 (Output):** Scans tool responses for PII and injection payloads before returning to the agent. Applies redaction rather than hard rejection to preserve agent functionality.
- **Layer 4 (Context):** The novel embodiment of this invention. Maintains per-session state and performs the sliding-window behavioral analysis described below.

### 2. Sliding-Window Behavioral Analysis (Layer 4)

**2.1 Session State**

For each unique session identifier, the system maintains a fixed-length sliding window W of the N most recent tool calls (preferred embodiment: N=20). Each entry in W records:
- tool_name: the name of the invoked tool
- params_text: serialized string representation of the tool parameters
- timestamp: time of invocation

**2.2 Categorical Threat Taxonomy**

The system defines a fixed taxonomy of K threat categories (preferred embodiment: K=5):

| Category | Representative Terms |
|----------|---------------------|
| credentials | password, api_key, token, secret, ssh, env, .env |
| pii | ssn, passport, email, phone, address, dob, credit_card |
| files | /etc/passwd, /root, .ssh/id_rsa, shadow, authorized_keys |
| email_calendar | gmail, outlook, sendmail, calendar, meeting, contact |
| system | exec, shell, subprocess, os.system, eval, chmod, sudo |

**2.3 TF-IDF Scoring**

For each tool call, the system computes a per-category term-frequency score by tokenizing tool_name and params_text and measuring overlap with each category's term set. The aggregate risk score for a session is:

```
mosaic_risk = max_category_score + breadth_bonus
breadth_bonus = (number of categories with score > threshold_α) × β
```

In the preferred embodiment: threshold_α = 0.15, β = 0.05.

**2.4 Threshold Classification**

The system classifies each tool call result into one of three zones:

- **Green zone** (mosaic_risk < 0.35): pass without LLM adjudication
- **Grey zone** (0.35 ≤ mosaic_risk < 0.75): invoke LLM adjudication (§3)
- **Red zone** (mosaic_risk ≥ 0.75): block immediately, fire alert

These thresholds are configurable per deployment.

### 3. LLM Grey-Zone Adjudication

When a session enters the grey zone, the system invokes an LLM to perform semantic analysis of the tool-call sequence:

**3.1 Prompt Construction**

The system constructs a structured prompt containing:
- The last M tool calls from the sliding window (preferred: M=10)
- Per-category TF-IDF scores
- The aggregate mosaic_risk score
- A constrained output schema requiring: risk_score (float), reasoning (string), attack_type (enum), confidence (enum)

**3.2 Provider Resolution (Priority Chain)**

The system resolves the LLM provider using the following priority chain:

1. If provider == "ollama": use local Ollama instance at configured URL
2. If provider == "anthropic": use Anthropic Claude API
3. If provider == "auto" (default):
   a. Probe local Ollama with a 500ms liveness check (GET /api/tags)
   b. If reachable: use Ollama
   c. Else if Anthropic API key configured: use Anthropic
   d. Else: skip LLM, fall back to TF-IDF score

**3.3 Timeout and Fallback**

The LLM call is wrapped in an asyncio timeout (configurable, preferred: 8 seconds). On timeout or any error, the system silently falls back to the TF-IDF score. The system never blocks on LLM availability — security decisions degrade gracefully to the deterministic score.

**3.4 Score Adjudication**

If the LLM returns a risk_score:
- Recalculate final_risk = max(tfidf_risk, llm_risk_score)  
- Apply grey/red zone thresholds to final_risk
- Log provider, model, scores, and reasoning for audit

### 4. Cryptographic Schema Attestation

The system signs each validated tool schema record stored in the cache using HMAC-SHA256 with a configurable signing secret. On cache retrieval, the signature is verified before trusting the cached record. A signature mismatch indicates cache tampering and forces a fresh deep scan. This provides:

- Integrity: cached schemas cannot be silently substituted
- Tamper evidence: all integrity failures are logged with server URL and expected vs. actual hash
- Zero-overhead trust: HMAC verification adds < 0.1ms to each cache hit

### 5. Registry of Known-Bad Schemas

The system maintains a searchable registry of known-bad tool schema patterns with CVE-style identifiers (SMCP-YYYY-NNN). Each entry specifies:
- Attack type and OWASP LLM Top 10 category
- Indicator strings and tool name patterns
- Detection layer and confidence score
- Published date and references

Registry checks run before regex deep-scan, providing O(n) detection for catalogued attacks.

---

## Claims

**Claim 1.** A computer-implemented method for detecting coordinated attacks in AI agent sessions, comprising:
- maintaining, per session identifier, a sliding window of the N most recent tool-call records;
- computing, for each tool call, a per-category term-frequency score across a predefined taxonomy of threat categories;
- computing an aggregate mosaic risk score as a function of the maximum per-category score and a breadth bonus proportional to the count of elevated categories;
- classifying the aggregate score into a green zone, a grey zone, or a red zone using configurable thresholds;
- for grey-zone classifications, invoking a large language model to perform semantic adjudication of the tool-call sequence and returning a refined risk score; and
- blocking tool execution and firing an alert when the final risk score exceeds the red-zone threshold.

**Claim 2.** The method of claim 1, wherein invoking the large language model comprises:
- resolving an LLM provider via a priority chain: (a) checking liveness of a local LLM server; (b) falling back to a cloud LLM API if a key is configured; (c) returning None to silently skip adjudication if no provider is available.

**Claim 3.** The method of claim 2, wherein the LLM invocation is wrapped in an asynchronous timeout such that expiry causes silent fallback to the deterministic mosaic risk score without blocking the tool call.

**Claim 4.** The method of claim 1, further comprising:
- signing each validated tool schema record in a cache store using HMAC-SHA256 with a configurable secret;
- verifying the signature on each cache retrieval; and
- on signature mismatch, invalidating the cache record and forcing a fresh deep scan of the tool schema.

**Claim 5.** The method of claim 1, further comprising:
- maintaining a registry of known-bad tool schemas indexed by CVE-style identifiers;
- checking each incoming tool schema against the registry before performing regex-based deep scan; and
- returning a registry hit with identifier, severity, and attack type when a match is found.

**Claim 6.** A system for real-time security analysis of AI agent tool invocations, comprising:
- a schema validation layer that performs cryptographically attested tool schema validation;
- a parameter validation layer that enforces JSON Schema constraints on tool invocation parameters;
- an output inspection layer that scans tool responses for PII and injection payloads before returning to the agent; and
- a context analysis layer implementing the sliding-window behavioral analysis of claims 1–5.

**Claim 7.** The system of claim 6, wherein the context analysis layer maintains independent sliding windows per session identifier, enabling concurrent analysis of multiple agent sessions without state leakage.

**Claim 8.** A non-transitory computer-readable medium storing instructions that, when executed, perform the method of claims 1–5.

---

## Abstract

A security gateway for AI agent systems detects coordinated data exfiltration and reconnaissance attacks by maintaining a per-session sliding window of tool-call records and computing categorical TF-IDF scores across a predefined threat taxonomy. An aggregate mosaic risk score classifies each invocation into green (pass), grey (uncertain), or red (block) zones. Grey-zone invocations trigger semantic adjudication by a large language model, with provider resolved via a priority chain: local LLM server (e.g., Ollama), cloud LLM API, or silent fallback to the deterministic score. Tool schema records are protected by HMAC-SHA256 attestation to prevent cache tampering. A searchable registry of known-bad schemas with CVE-style identifiers enables O(n) detection of catalogued attacks before regex-based scanning.

---

## Filing Instructions

1. **This week:** File this as a **provisional application** at https://www.uspto.gov/patents/apply/applying-online
   - Select "Provisional Application for Patent"
   - Title: copy from above
   - Inventors: list all contributors
   - Attach this document as the specification
   - Fee: ~$320 (micro-entity) or ~$640 (small entity)
   - No claims required for provisional — but include them (adds protection)

2. **Within 12 months:** Convert to utility application with a registered patent attorney
   - Budget: $8,000–$15,000 for attorney drafting and filing
   - Prior art to cite: Citibank US12450494B1, Cisco US20240333765A1, Meta arXiv:2505.03574

3. **Important dates:**
   - Priority date is established on the day of provisional filing
   - Every day you wait narrows your window relative to competitors
   - The arxiv paper (2603.22489, March 2026) creates prior art pressure — file now

---

*This document is a draft for informational purposes. Consult a registered patent attorney (USPTO registration required) before filing.*
