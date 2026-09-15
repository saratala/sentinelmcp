"""Branded, shareable HTML report for an active-probe assessment.

Renders a ProbeReport into a polished, print-to-PDF page you can hand to a
prospect after scanning their MCP server — the top-of-funnel GTM artifact.
Self-contained (inline CSS, no assets), so it works as a saved .html or a URL.
"""
from __future__ import annotations

import html

# Per-attack remediation guidance shown next to each finding.
_REMEDIATION = {
    "prompt_injection": "Strip/validate tool descriptions before they reach the model; never treat tool text as instructions.",
    "rug_pull": "Pin tool schemas by hash at approval and alert on any drift; re-validate on a short interval.",
    "pii_leak": "Apply least-privilege to tool credentials and redact sensitive fields at the boundary.",
    "sql_injection": "Parameterize queries server-side; reject additional properties and validate every argument.",
    "path_traversal": "Canonicalize and sandbox file paths; deny access outside an allow-listed root.",
    "ssrf": "Egress-filter tool network access; block link-local/metadata and unapproved destinations.",
    "dos": "Enforce request-size and timeout limits; rate-limit expensive tools.",
}

_SEV_COLOR = {"CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#a16207", "LOW": "#15803d"}
_RISK_COLOR = {"CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#a16207",
               "LOW": "#15803d", "SAFE": "#15803d"}


def _e(s) -> str:
    return html.escape(str(s if s is not None else ""))


def render_probe_report(report: dict) -> str:
    """Return a self-contained branded HTML report for a probe result."""
    server = _e(report.get("server_url", "unknown"))
    tested_at = _e(report.get("tested_at", ""))[:19].replace("T", " ")
    risk_score = report.get("risk_score", 0)
    risk_level = str(report.get("risk_level", "UNKNOWN")).upper()
    risk_color = _RISK_COLOR.get(risk_level, "#334155")
    findings = report.get("findings", [])
    vulns = report.get("vulnerabilities_found", 0)
    total = report.get("total_attacks", len(findings))
    recommendation = _e(report.get("recommendation", ""))
    owasp = ", ".join(sorted({_e(f.get("owasp_id", "")) for f in findings if f.get("owasp_id")}))
    hardening = report.get("hardening") or {}

    # Findings rows — vulnerable first, then the rest.
    order = {"VULNERABLE": 0, "INCONCLUSIVE": 1, "PROTECTED": 2}
    rows = ""
    for f in sorted(findings, key=lambda x: order.get(x.get("verdict"), 3)):
        verdict = str(f.get("verdict", "")).upper()
        sev = str(f.get("severity", "LOW")).upper()
        attack = f.get("attack_type", "")
        sev_c = _SEV_COLOR.get(sev, "#334155")
        vmark = ("🚨" if verdict == "VULNERABLE" else "✓" if verdict == "PROTECTED" else "—")
        remediation = _REMEDIATION.get(attack, "") if verdict == "VULNERABLE" else ""
        rows += f"""
      <tr>
        <td><strong>{_e(attack)}</strong></td>
        <td>{_e(f.get('owasp_id',''))}</td>
        <td>{vmark} {_e(verdict)}</td>
        <td><span class="sev" style="background:{sev_c}">{_e(sev)}</span></td>
        <td class="ev">{_e(str(f.get('evidence','') or f.get('details',''))[:180])}</td>
        <td class="rem">{_e(remediation)}</td>
      </tr>"""

    # "How SentinelMCP defends this" — includes closed-loop proof when present.
    if hardening.get("advisories_created") or hardening.get("rules_installed"):
        defense = (
            f"<p>SentinelMCP's closed loop already converted these findings into "
            f"<strong>{len(hardening.get('advisories_created', []))} registry advisory(ies)</strong> and "
            f"<strong>{len(hardening.get('rules_installed', []))} live detection rule(s)</strong> — "
            f"the same attacks are now blocked at the gateway, fleet-wide, with no human authoring.</p>")
    else:
        defense = (
            "<p>Deployed inline, SentinelMCP blocks each of these at the gateway before your "
            "agent acts — and its closed loop can auto-synthesize live detection rules from "
            "confirmed findings so one discovery hardens the whole fleet.</p>")

    verdict_line = (
        f"{vulns} of {total} attack classes are exploitable"
        if vulns else f"No exploitable findings across {total} attack classes")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelMCP — MCP Security Assessment</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, Arial, sans-serif; color: #0f172a; background: #f8fafc; font-size: 13px; }}
  .page {{ max-width: 920px; margin: 0 auto; padding: 40px; background: #fff; }}
  header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #14532d; padding-bottom: 18px; }}
  .logo {{ font-size: 24px; font-weight: 800; color: #14532d; letter-spacing: -.5px; }}
  .logo span {{ color: #16a34a; }}
  .meta {{ text-align: right; color: #475569; font-size: 12px; line-height: 1.7; }}
  h2 {{ font-size: 13px; text-transform: uppercase; letter-spacing: .5px; color: #14532d; margin: 26px 0 10px; }}
  .hero {{ display: grid; grid-template-columns: 200px 1fr; gap: 20px; align-items: center; margin-top: 22px;
           background: #f0fdf4; border: 1px solid #dcfce7; border-radius: 10px; padding: 22px; }}
  .score {{ text-align: center; }}
  .score .num {{ font-size: 54px; font-weight: 800; color: {risk_color}; line-height: 1; }}
  .score .lbl {{ font-size: 11px; color: #64748b; text-transform: uppercase; }}
  .badge {{ display: inline-block; color: #fff; background: {risk_color}; padding: 4px 12px; border-radius: 999px; font-weight: 700; font-size: 12px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 6px; font-size: 12px; }}
  th {{ background: #14532d; color: #fff; text-align: left; padding: 8px 10px; font-size: 11px; text-transform: uppercase; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  .sev {{ color: #fff; border-radius: 4px; padding: 2px 7px; font-size: 10px; font-weight: 700; }}
  .ev {{ color: #475569; font-family: ui-monospace, monospace; font-size: 11px; max-width: 240px; word-break: break-word; }}
  .rem {{ color: #166534; max-width: 220px; }}
  .defense {{ background: #ecfdf5; border-left: 4px solid #16a34a; padding: 14px 16px; border-radius: 6px; margin-top: 8px; }}
  .cta {{ margin-top: 26px; background: #14532d; color: #fff; border-radius: 10px; padding: 20px 24px; }}
  .cta a {{ color: #86efac; }}
  footer {{ margin-top: 24px; border-top: 1px solid #e2e8f0; padding-top: 12px; color: #94a3b8; font-size: 11px; display: flex; justify-content: space-between; }}
  @media print {{ body {{ background: #fff; }} .page {{ padding: 16px; }} @page {{ margin: 1.2cm; }} }}
</style></head>
<body><div class="page">
  <header>
    <div>
      <div class="logo">Sentinel<span>MCP</span></div>
      <div style="color:#475569;font-size:12px;margin-top:4px">MCP Security Assessment</div>
    </div>
    <div class="meta">
      <strong>Target:</strong> {server}<br>
      <strong>Assessed:</strong> {tested_at} UTC<br>
      Standard: OWASP LLM Top 10
    </div>
  </header>

  <div class="hero">
    <div class="score">
      <div class="num">{_e(risk_score)}</div>
      <div class="lbl">Risk score / 10</div>
      <div style="margin-top:8px"><span class="badge">{_e(risk_level)}</span></div>
    </div>
    <div>
      <h2 style="margin-top:0">Executive summary</h2>
      <p style="font-size:14px;color:#0f172a"><strong>{_e(verdict_line)}.</strong></p>
      <p style="margin-top:8px;color:#475569">{recommendation}</p>
    </div>
  </div>

  <h2>Findings</h2>
  <table>
    <tr><th>Attack class</th><th>OWASP</th><th>Verdict</th><th>Severity</th><th>Evidence</th><th>Remediation</th></tr>
    {rows}
  </table>
  <p style="margin-top:8px;color:#64748b;font-size:11px">OWASP coverage tested: {owasp or 'n/a'}</p>

  <h2>How SentinelMCP defends this</h2>
  <div class="defense">{defense}</div>

  <div class="cta">
    <strong style="font-size:15px">Close these gaps before an agent acts on them.</strong>
    <p style="margin-top:6px;color:#d1fae5">Deploy SentinelMCP in-VPC as a zero-trust gateway between your AI agents and
    their MCP servers — every tool, verified in &lt;5&nbsp;ms. Reply to this report to start a design-partner pilot.</p>
  </div>

  <footer>
    <span>SentinelMCP — Every tool, verified.</span>
    <span>Generated automatically · informational, not a warranty of security</span>
  </footer>
</div></body></html>"""
