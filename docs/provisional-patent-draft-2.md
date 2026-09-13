# Provisional Patent Application Draft (No. 2)
## SentinelMCP — Closed-Loop Offensive-to-Defensive Synthesis for AI-Agent Tool Security

**Filing basis:** 35 U.S.C. § 111(b) Provisional Application
**Status:** DRAFT — review with a registered patent attorney before filing
**Relationship to Draft No. 1:** Draft No. 1 claims the Layer-4 sliding-window mosaic + LLM grey-zone adjudication + HMAC schema attestation + registry. This draft claims *different, non-overlapping* mechanisms and may be filed as a separate provisional or combined by counsel.
**Estimated cost:** ~$130–$320 (USPTO micro/small-entity provisional) + attorney conversion ~$8k–$15k.
**Priority window:** 12 months from filing to convert to utility.

---

## Title

**SYSTEM AND METHOD FOR CLOSED-LOOP SYNTHESIS OF RUNTIME SECURITY CONTROLS FOR AI-AGENT TOOL PROTOCOLS FROM ACTIVE ADVERSARIAL PROBE RESULTS**

---

## Field of the Invention

Cybersecurity for AI-agent systems, and specifically the automatic conversion of confirmed vulnerabilities discovered by active adversarial probing of a tool server (e.g., a Model Context Protocol / MCP server) into deployed runtime detection-and-enforcement controls in a defensive gateway, without human authoring of the controls.

---

## Background

AI agents call external tools over protocols such as MCP. Two classes of security product exist today and operate **independently**:

1. **Offensive / testing tools** — scanners and "AI red-team" agents that probe a target for prompt injection, rug pulls, data leakage, SSRF, injection, etc., and emit a *report* for a human to read (e.g., static manifest scanners; red-team agents).
2. **Defensive / runtime tools** — gateways, "AI firewalls," and classifiers that inspect live traffic and block threats using human-authored rules or trained models.

The gap: findings from the offensive tool do **not** automatically become controls in the defensive tool. A human must read the report, hand-author a rule or signature, and deploy it. This is slow, error-prone, does not scale across a fleet of servers, and leaves a window between discovery and protection. Prior art reflects this separation:

- **US 12,437,058 B1 (Amazon)** validates agent action plans and tool-result data against rules/classifiers — but the rules are pre-existing, not synthesized from probe results.
- **US 20250209208A1 (Cisco / Robust Intelligence)** and **HiddenLayer patents (US 12,130,917 / 12,137,118 / 12,248,883)** detect prompt injection with classifiers — trained offline, not generated from live probing.
- **US 12450494B1 (Citibank)** validates agent actions with generative AI against supplied guidelines — the guidelines are inputs, not derived from adversarial testing.
- **US 20240333765A1 (Cisco)** feeds attacker interactions with honeypots back to retrain an LLM to make *better honeypots* — a feedback loop, but it improves *deception content*, not the *detection/enforcement rules* of a defensive gateway, and it is not driven by a structured probe→rule synthesis.

No prior art found teaches a **closed loop** in which an active adversarial probe's *confirmed* findings are deterministically synthesized into (a) versioned threat-registry advisories and (b) live detection rules installed into a running multi-layer enforcement gateway, such that red-teaming one server hardens defenses fleet-wide with no human in the authoring path.

---

## Summary of the Invention

A security system for AI-agent tool protocols comprising an **active probe subsystem**, a **defensive gateway** with a hot-reloadable policy engine and a versioned threat registry, and a **synthesis engine** that closes the loop between them. On a confirmed (VULNERABLE) probe finding, the synthesis engine:

1. Derives a **deterministic, idempotent identifier** from the target and attack class (so re-probing updates rather than duplicates);
2. Generates a **registry advisory** (attack type, severity, OWASP mapping, indicators, provenance/evidence, origin server) that the gateway consults on future connections;
3. Where the finding yields a reusable indicator, generates a **detection rule** and installs it into the running policy engine at a specified inspection layer, taking effect without restart;
4. Persists both artifacts so they survive restart and propagate across gateway instances sharing the registry/policy store.

Two further, independently useful mechanisms are disclosed: an **approval-view fidelity detector** (Section 4) and a **dual-score security benchmark** (Section 5).

---

## Detailed Description of Preferred Embodiments

### 1. System Architecture
Three cooperating subsystems: (i) an active probe that issues adversarial requests to a target tool server over the tool protocol and classifies each response as VULNERABLE / PROTECTED / INCONCLUSIVE across a set of attack classes (e.g., prompt injection, rug pull, sensitive-data leakage, SQL injection, path traversal, SSRF, denial-of-service); (ii) a defensive gateway with an ordered set of inspection layers (schema, parameter, output, context) whose parameter/schema layers consult a hot-reloadable **policy engine** and a **threat registry**; and (iii) a **synthesis engine** connecting (i) to (ii).

### 2. Closed-Loop Synthesis (the novel embodiment)
For each finding with verdict VULNERABLE and a recognized attack class:

**2.1 Deterministic identifier.** Compute `id = f(host(target), attack_class)` via a stable hash, yielding an identifier of the form `SMCP-AUTO-<hash>`. Because the id depends only on target host and attack class, re-probing the same weakness updates the same artifact instead of creating duplicates (**idempotency**).

**2.2 Advisory generation.** Emit a structured advisory containing: the mapped canonical attack type; severity; OWASP-LLM category; a description incorporating probe detail; **derived indicator strings**; the inspection layer; **provenance** (origin server URL, truncated evidence, source = auto-synthesized); and a publication date. Insert it into the registry and rebuild the registry's lookup indices so the gateway consults it immediately.

**2.3 Rule generation and live install.** For attack classes whose confirming payloads generalize (e.g., injection/SSRF/traversal), emit a policy rule object `{name, layer, type (regex|keyword), keywords|pattern, threat_type, owasp_id, confidence, enabled}` and install it into the running policy engine. Installation is **by-name idempotent** (an existing rule of the same name is replaced) and takes effect on the next inspected call **without restart**.

**2.4 Persistence and propagation.** Persist the advisory to the registry feed and the rule to a synthesized-rules file that the policy engine's file watcher already loads; gateway instances sharing these stores converge to the same controls (fleet-wide propagation).

**2.5 Non-actionable findings.** PROTECTED / INCONCLUSIVE findings, and unrecognized attack classes, produce no artifacts.

### 3. Worked Example
An active probe confirms SQL-injection on `target-mcp.example.com`. The synthesis engine creates advisory `SMCP-AUTO-5BE9C697` (attack_type=DANGEROUS_ACTION, OWASP LLM07, origin server + evidence recorded) and installs a layer-2 keyword rule `auto_sql_injection_5be9c697` matching the confirming payloads. Immediately afterward, a live tool invocation carrying `'; DROP TABLE users` to any server is blocked by the newly-installed rule — discovery on one server now protects the whole fleet, with no human authoring.

### 4. Approval-View Fidelity Detection (independent mechanism)
Tool descriptions/outputs can carry content **invisible to a human approval view** yet tokenized by the model — via the Unicode Tag block (U+E0000–U+E007F mapping ASCII to non-rendering codepoints), bidirectional overrides, or zero-width runs. The detector computes the divergence between the human-rendered view and the model-ingested view: it (a) flags the presence of tag-block/bidi/zero-width concealment (near-zero false positives because legitimate tool text lacks them), (b) **decodes** any tag-block-smuggled ASCII back to plaintext, and (c) re-scans the decoded plaintext with the injection detectors, surfacing the concealed instruction. A run threshold on zero-width characters avoids false positives on legitimate emoji joiners.

### 5. Dual-Score Security Benchmark (independent mechanism)
A method of reporting an AI-security detector's effectiveness as **two separated numbers**: a deterministic-core detection rate (pattern/rule layers, reproducible, no model inference) and an incremental "LLM lift" obtained by re-checking only core-missed cases with a model-based layer, accompanied by a false-positive rate measured against a benign control set — pinned to a hashed dataset, provider, and model version for reproducibility. This separates reproducible, low-latency coverage from model-dependent coverage and its precision cost.

---

## Claims

**Claim 1.** A computer-implemented method for hardening a security gateway for an AI-agent tool protocol, comprising: issuing, by an active probe, one or more adversarial requests to a target tool server; classifying a response as indicating a confirmed vulnerability of an attack class; automatically synthesizing, from the confirmed vulnerability, (a) a registry advisory comprising the attack class, a severity, and provenance identifying the target server, and (b) when the attack class has a generalizable indicator, a detection rule; installing the detection rule into a running policy engine of the gateway such that it applies to subsequent tool invocations without a restart; and inserting the advisory into a threat registry consulted by the gateway.

**Claim 2.** The method of claim 1, wherein the advisory and rule are assigned an identifier deterministically derived from the target server and the attack class, such that re-probing the same vulnerability updates the existing artifacts rather than creating duplicates.

**Claim 3.** The method of claim 1, wherein a response classified as protected or inconclusive, or an unrecognized attack class, produces no synthesized artifact.

**Claim 4.** The method of claim 1, further comprising persisting the synthesized advisory and rule to shared stores such that a plurality of gateway instances converge to the same controls, whereby a vulnerability discovered on one server hardens enforcement for other servers.

**Claim 5.** The method of claim 1, wherein installing the detection rule is idempotent by rule name, an existing rule of the same name being replaced, and wherein the rule specifies an inspection layer among a schema layer, a parameter layer, an output layer, and a context layer.

**Claim 6.** A method for detecting concealment in AI-agent tool content, comprising: receiving a text of a tool description or tool output; detecting a divergence between a human-rendered view and a model-ingested view of the text by identifying at least one of a Unicode Tag-block codepoint, a bidirectional-override codepoint, or a run of zero-width codepoints exceeding a threshold; decoding Tag-block codepoints to their represented characters; and scanning the decoded characters with an injection detector to surface a concealed instruction.

**Claim 7.** A method for reporting AI-security detection effectiveness, comprising: computing a deterministic-core detection rate over a hashed dataset using non-model detection layers; computing an incremental detection contribution by re-evaluating only core-missed cases with a model-based layer; measuring a false-positive rate of the model-based layer over a benign control set; and reporting the deterministic-core rate and the incremental contribution as separate values together with the provider and model identifiers used.

**Claim 8.** A system comprising an active probe subsystem, a defensive gateway with a hot-reloadable policy engine and a versioned threat registry, and a synthesis engine configured to perform the method of claims 1–5.

**Claim 9.** A non-transitory computer-readable medium storing instructions that, when executed, perform the method of any of claims 1–7.

---

## Abstract

A security system for AI-agent tool protocols closes the loop between offensive testing and defensive enforcement. An active probe issues adversarial requests to a target tool server and classifies confirmed vulnerabilities by attack class. A synthesis engine deterministically converts each confirmed finding into a versioned threat-registry advisory and, where a generalizable indicator exists, a detection rule that is installed into a running policy engine and applied to subsequent tool invocations without restart; artifacts are idempotent and persisted so a plurality of gateway instances converge, hardening the whole fleet from a single discovery with no human authoring. Additional disclosed mechanisms include an approval-view fidelity detector that surfaces content concealed via Unicode Tag-block, bidirectional-override, or zero-width characters by measuring the divergence between the human-rendered and model-ingested views, and a dual-score benchmark that separately reports deterministic-core detection and model-based incremental lift with a benign-control false-positive rate.

---

## Prior-Art Notes (honest assessment — informal search, not an FTO opinion)

- **Closest to Claim 1 (closed loop):** Cisco **US20240333765A1** (honeypot-retrain feedback loop — improves deception content, not gateway detection/enforcement rules); Amazon **US12437058B1** and generic "continuous improvement of detection rules" patents (**US12526324**, **US11909773**) — rule improvement exists generally, but not *probe-confirmed-finding → synthesized gateway rule + registry advisory* for an agent tool protocol. Closed-loop framing appears **unclaimed**; novelty rests on the specific offense→defense synthesis pipeline.
- **Claim 6 (approval-view fidelity):** invisible-Unicode / Tag-block detection is **well-documented as technique** (Cisco blog, NVIDIA garak, CSA, ATR rules) — the bare stripping is prior art. The defensible novelty is the *rendered-vs-model divergence* framing plus decode-and-rescan in the tool-approval context; treat as a narrower dependent claim.
- **Claim 7 (dual-score benchmark):** the "ablation / LLM-lift over deterministic baseline" idea appears in ML-evaluation literature (prior art against a broad claim); the specific *two-number security-effectiveness reporting with pinned dataset/provider/model + benign-control FP rate* appears **unclaimed** and was assessed as the cleanest white space.
- **Caveats:** Google Patents/USPTO full-text lags publication by ~18 months, so recent filings may be invisible. This is informal prior-art research, **not** legal advice or a freedom-to-operate opinion. A registered patent attorney should run a CPC-scoped search and chart claims before filing.

## Filing Instructions
1. File as a provisional at uspto.gov (Provisional Application for Patent); attach this document as the specification; list all inventors; pay the micro/small-entity fee.
2. Within 12 months, convert to a utility application with counsel; cite the prior art above (US12437058B1, US20240333765A1, US20250209208A1, US12130917B1, US12450494B1, US12526324, US11909773).
3. Priority date is set on filing — file before public disclosure or a demo that teaches the closed-loop mechanism.

*Draft for informational purposes only. Consult a registered patent attorney before filing.*
