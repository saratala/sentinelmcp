#!/usr/bin/env python3
"""SentinelMCP LangGraph Security Research Agent.

A LangGraph agent with FAISS RAG over OWASP LLM Top 10 knowledge.
Does real security work: discovers MCP servers, calls sentinel_analyze
via the gateway, retrieves relevant OWASP context, and produces a
structured security assessment report.

Architecture:
  ┌──────────────────────────────────────────────────────┐
  │  LangGraph Agent                                      │
  │                                                      │
  │  Nodes:                                              │
  │    discover    → find MCP servers to assess          │
  │    rag_context → FAISS retrieval for OWASP knowledge │
  │    analyze     → call SentinelMCP gateway            │
  │    synthesize  → Ollama LLM final report             │
  │    done        → emit structured JSON result         │
  └──────────────────────────────────────────────────────┘

Usage:
  # Run the full agent pipeline:
  python demo/sentinel_agent.py

  # Assess specific servers:
  python demo/sentinel_agent.py --servers http://demo-clean:8001 http://demo-poisoned:8002

  # Use as a library (e.g. from sentinel_mcp_server.py):
  agent = SentinelRAGAgent()
  report = agent.run(servers=["http://my-server:8001"])
  explanation = agent.explain("PROMPT_INJECTION", "exfiltration_url")

Requirements:
  pip install langchain langchain-community langgraph faiss-cpu
  ollama serve && ollama pull qwen2.5:7b
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, TypedDict

import httpx

# ── Config ────────────────────────────────────────────────────────────────────

GATEWAY       = os.getenv("SENTINEL_GATEWAY_URL", "http://localhost:8888")
API_KEY       = os.getenv("SENTINEL_API_KEY",     "dev-key-123")
OLLAMA_URL    = os.getenv("OLLAMA_URL",            "http://localhost:11434")
OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL",          "qwen2.5:7b")
CLEAN_SERVER  = os.getenv("CLEAN_SERVER_URL",      "http://localhost:8001")
POISONED_SERVER = os.getenv("POISONED_SERVER_URL", "http://localhost:8002")

_GW_HEADERS = {"X-Sentinel-Key": API_KEY, "Content-Type": "application/json"}

# ── ANSI ──────────────────────────────────────────────────────────────────────

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; B = "\033[1m"; D = "\033[90m"; X = "\033[0m"


# ── RAG: build FAISS index from OWASP knowledge ───────────────────────────────

class SentinelRAGAgent:
    """FAISS-backed RAG agent for OWASP LLM security knowledge."""

    def __init__(self) -> None:
        self._vectorstore = None
        self._llm = None

    def _get_vectorstore(self):
        if self._vectorstore is not None:
            return self._vectorstore

        from langchain_community.vectorstores import FAISS
        from langchain_community.embeddings import OllamaEmbeddings
        from langchain.schema import Document
        from demo.sentinel_knowledge import DOCUMENTS

        print(f"  {D}Building FAISS index from {len(DOCUMENTS)} OWASP documents…{X}")
        embeddings = OllamaEmbeddings(
            base_url=OLLAMA_URL,
            model=OLLAMA_MODEL,
        )
        docs = [
            Document(
                page_content=d["content"],
                metadata={
                    "id": d["id"],
                    "title": d["title"],
                    "owasp_id": d["owasp_id"],
                    "threat_types": d["threat_types"],
                    "cve_refs": d["cve_refs"],
                },
            )
            for d in DOCUMENTS
        ]
        self._vectorstore = FAISS.from_documents(docs, embeddings)
        print(f"  {G}✓{X}  FAISS index ready — {len(docs)} documents")
        return self._vectorstore

    def _get_llm(self):
        if self._llm is not None:
            return self._llm
        from langchain_community.llms import Ollama
        self._llm = Ollama(base_url=OLLAMA_URL, model=OLLAMA_MODEL,
                           temperature=0.1)
        return self._llm

    def retrieve(self, query: str, k: int = 3) -> list[dict]:
        """Retrieve top-k relevant OWASP documents for a query."""
        vs = self._get_vectorstore()
        results = vs.similarity_search_with_score(query, k=k)
        return [
            {
                "title": doc.metadata["title"],
                "owasp_id": doc.metadata["owasp_id"],
                "threat_types": doc.metadata["threat_types"],
                "cve_refs": doc.metadata["cve_refs"],
                "content": doc.page_content[:500],
                "score": float(score),
            }
            for doc, score in results
        ]

    def explain(self, threat_type: str, pattern: str = "",
                context: str = "") -> str:
        """RAG + LLM explanation of a threat type."""
        query = f"{threat_type} {pattern} MCP security attack mitigation"
        docs = self.retrieve(query, k=2)

        context_text = "\n\n".join(
            f"[{d['owasp_id']}] {d['title']}:\n{d['content']}"
            for d in docs
        )

        prompt = f"""You are a security expert. Using the OWASP LLM Top 10 context below,
explain the following threat in plain English for a security report.

Threat type: {threat_type}
Pattern detected: {pattern or 'not specified'}
Additional context: {context or 'none'}

OWASP Context:
{context_text}

Provide:
1. What this attack is (1-2 sentences)
2. How it works in MCP/agent pipelines specifically (2-3 sentences)
3. OWASP LLM category and CVEs if applicable
4. Three specific mitigation steps

Keep it technical but clear. No preamble."""

        llm = self._get_llm()
        explanation = llm(prompt)

        return json.dumps({
            "threat_type": threat_type,
            "pattern": pattern,
            "owasp_ids": list({d["owasp_id"] for d in docs}),
            "cve_refs": list({c for d in docs for c in d["cve_refs"]}),
            "explanation": explanation.strip(),
            "retrieved_docs": [d["title"] for d in docs],
            "source": "rag_ollama",
        }, indent=2)


# ── LangGraph state ───────────────────────────────────────────────────────────

class AgentState(TypedDict):
    servers: list[str]
    session_id: str
    rag_agent: Any
    discoveries: list[dict]       # raw tool lists per server
    rag_contexts: list[dict]      # retrieved OWASP docs
    analyses: list[dict]          # gateway analyze results
    final_report: dict            # synthesized output


# ── LangGraph nodes ───────────────────────────────────────────────────────────

def node_discover(state: AgentState) -> AgentState:
    """Fetch tool lists from each server to understand what's being assessed."""
    print(f"\n{C}{B}[ 1/4  DISCOVER ]{X}  Fetching tool definitions from {len(state['servers'])} server(s)…")
    discoveries = []

    with httpx.Client(timeout=10) as client:
        for server_url in state["servers"]:
            url = server_url if server_url.endswith("/") else server_url + "/"
            try:
                r = client.post(url, json={
                    "jsonrpc": "2.0", "id": 1,
                    "method": "tools/list", "params": {},
                }, headers={"Content-Type": "application/json"})
                data = r.json()
                tools = data.get("result", {}).get("tools", [])
                discoveries.append({
                    "server_url": server_url,
                    "tool_count": len(tools),
                    "tool_names": [t["name"] for t in tools],
                    "descriptions": {t["name"]: t.get("description", "")
                                     for t in tools},
                    "reachable": True,
                })
                print(f"  {G}✓{X}  {server_url} — {len(tools)} tool(s): "
                      f"{', '.join(t['name'] for t in tools[:4])}")
            except Exception as e:
                discoveries.append({
                    "server_url": server_url,
                    "reachable": False,
                    "error": str(e),
                })
                print(f"  {R}✗{X}  {server_url} — unreachable: {e}")

    return {**state, "discoveries": discoveries}


def node_rag_context(state: AgentState) -> AgentState:
    """Retrieve OWASP context relevant to discovered tools and descriptions."""
    print(f"\n{C}{B}[ 2/4  RAG ]{X}  Retrieving OWASP context…")
    rag_agent = state["rag_agent"]
    rag_contexts = []

    # Build a query from all tool descriptions combined
    all_descriptions = []
    for d in state["discoveries"]:
        if d.get("reachable"):
            for name, desc in d.get("descriptions", {}).items():
                all_descriptions.append(f"{name}: {desc}")

    if not all_descriptions:
        print(f"  {Y}⚠{X}  No reachable servers — using generic OWASP context")
        query = "MCP tool security threats prompt injection supply chain"
    else:
        query = " ".join(all_descriptions)[:400]

    try:
        docs = rag_agent.retrieve(query, k=4)
        rag_contexts = docs
        for doc in docs:
            print(f"  {G}↑{X}  {doc['owasp_id']}: {doc['title']}  "
                  f"(score={doc['score']:.3f})")
    except Exception as e:
        print(f"  {Y}⚠{X}  RAG retrieval failed: {e}")
        print(f"     Is Ollama running? Try: ollama serve")

    return {**state, "rag_contexts": rag_contexts}


def node_analyze(state: AgentState) -> AgentState:
    """Call SentinelMCP gateway analyze endpoint for each reachable server."""
    print(f"\n{C}{B}[ 3/4  ANALYZE ]{X}  Running 4-layer security analysis…")
    analyses = []

    with httpx.Client(timeout=20) as client:
        for discovery in state["discoveries"]:
            server_url = discovery["server_url"]
            if not discovery.get("reachable"):
                analyses.append({"server_url": server_url, "skipped": True,
                                  "reason": "unreachable"})
                continue

            # Build representative tool calls for analysis
            tool_calls = [
                {"name": name, "arguments": {}}
                for name in discovery.get("tool_names", [])[:5]
            ]

            try:
                t0 = time.perf_counter()
                r = client.post(
                    f"{GATEWAY}/proxy/analyze",
                    json={
                        "server_url": server_url,
                        "session_id": state["session_id"],
                        "tool_calls": tool_calls,
                    },
                    headers=_GW_HEADERS,
                )
                elapsed = round((time.perf_counter() - t0) * 1000, 1)
                data = r.json()

                verdict = data.get("overall", "UNKNOWN")
                threats = data.get("threats_found", 0)
                colour = R if verdict == "BLOCK" else G
                symbol = "✗  BLOCK" if verdict == "BLOCK" else "✓  PASS"

                print(f"  {colour}{symbol}{X}  {server_url}")
                print(f"     threats={threats}  schema={data.get('schema_verdict')}  "
                      f"latency={elapsed}ms")
                if data.get("recommendation"):
                    print(f"     {D}{data['recommendation'][:80]}{X}")

                analyses.append({**data, "gateway_latency_ms": elapsed})

            except httpx.ConnectError:
                print(f"  {Y}⚠{X}  Gateway unreachable — is SentinelMCP running?")
                print(f"     docker compose up -d api")
                analyses.append({
                    "server_url": server_url,
                    "overall": "ERROR",
                    "error": "gateway_unreachable",
                })

    return {**state, "analyses": analyses}


def node_synthesize(state: AgentState) -> AgentState:
    """Use Ollama LLM + RAG context to synthesize the final security report."""
    print(f"\n{C}{B}[ 4/4  SYNTHESIZE ]{X}  Generating report with {OLLAMA_MODEL}…")

    # Build prompt with RAG context + analysis results
    owasp_context = "\n\n".join(
        f"[{d['owasp_id']}] {d['title']}:\n{d['content'][:300]}"
        for d in state["rag_contexts"][:3]
    )

    analysis_summary = []
    total_blocked = 0
    total_threats = 0
    for a in state["analyses"]:
        if a.get("skipped"):
            analysis_summary.append(f"- {a['server_url']}: UNREACHABLE")
            continue
        verdict = a.get("overall", "UNKNOWN")
        threats = a.get("threats_found", 0)
        total_threats += threats
        if verdict == "BLOCK":
            total_blocked += 1
        blocked_calls = [
            t["tool"] for t in a.get("tool_analyses", [])
            if t.get("verdict") == "BLOCK"
        ]
        analysis_summary.append(
            f"- {a.get('server_url', 'unknown')}: {verdict}, "
            f"{threats} threats, blocked tools: {blocked_calls or 'none'}"
        )

    prompt = f"""You are a senior AI security analyst. Produce a concise security assessment report.

OWASP LLM Top 10 Context:
{owasp_context}

MCP Server Analysis Results:
{chr(10).join(analysis_summary)}

Write a security report with these sections:
1. EXECUTIVE SUMMARY (2 sentences)
2. FINDINGS (bullet per server: verdict, key threats, OWASP IDs)
3. RISK LEVEL (CRITICAL/HIGH/MEDIUM/LOW with justification)
4. TOP 3 RECOMMENDATIONS (specific, actionable)

Be direct. No filler. Security professionals are the audience."""

    try:
        rag_agent = state["rag_agent"]
        llm = rag_agent._get_llm()
        t0 = time.perf_counter()
        report_text = llm(prompt)
        llm_ms = round((time.perf_counter() - t0) * 1000, 1)
        print(f"  {G}✓{X}  LLM synthesis complete  ({llm_ms}ms)")
    except Exception as e:
        report_text = f"LLM synthesis failed: {e}\nRaw results: {analysis_summary}"
        print(f"  {Y}⚠{X}  LLM unavailable: {e}")
        llm_ms = 0

    final_report = {
        "title": "SentinelMCP Security Assessment",
        "session_id": state["session_id"],
        "servers_assessed": len(state["servers"]),
        "servers_blocked": total_blocked,
        "total_threats": total_threats,
        "risk_level": "CRITICAL" if total_blocked > 0 else "LOW",
        "owasp_ids_triggered": list({
            doc["owasp_id"]
            for a in state["analyses"]
            for t in a.get("tool_analyses", [])
            if t.get("verdict") == "BLOCK"
            for doc in state["rag_contexts"]
            if any(
                err_part in " ".join(doc["threat_types"]).lower()
                for err_part in t.get("param_errors", [""])
            )
        }),
        "llm_report": report_text.strip(),
        "raw_analyses": state["analyses"],
    }

    return {**state, "final_report": final_report}


# ── Build and run the LangGraph ───────────────────────────────────────────────

def build_graph():
    from langgraph.graph import StateGraph, END

    g = StateGraph(AgentState)
    g.add_node("discover",   node_discover)
    g.add_node("rag_context", node_rag_context)
    g.add_node("analyze",    node_analyze)
    g.add_node("synthesize", node_synthesize)

    g.set_entry_point("discover")
    g.add_edge("discover",    "rag_context")
    g.add_edge("rag_context", "analyze")
    g.add_edge("analyze",     "synthesize")
    g.add_edge("synthesize",  END)

    return g.compile()


def run_assessment(servers: list[str]) -> dict:
    import uuid
    rag_agent = SentinelRAGAgent()
    graph = build_graph()

    print(f"\n{C}{B}{'━'*64}{X}")
    print(f"{C}{B}  SentinelMCP Security Research Agent{X}")
    print(f"{C}{B}{'━'*64}{X}")
    print(f"  Servers  : {len(servers)}")
    print(f"  Model    : {OLLAMA_MODEL} via {OLLAMA_URL}")
    print(f"  Gateway  : {GATEWAY}")

    initial_state: AgentState = {
        "servers": servers,
        "session_id": f"agent-{uuid.uuid4().hex[:8]}",
        "rag_agent": rag_agent,
        "discoveries": [],
        "rag_contexts": [],
        "analyses": [],
        "final_report": {},
    }

    result = graph.invoke(initial_state)
    report = result["final_report"]

    # Print the final report
    print(f"\n{C}{B}{'━'*64}{X}")
    print(f"{C}{B}  SECURITY ASSESSMENT REPORT{X}")
    print(f"{C}{B}{'━'*64}{X}\n")

    risk_colour = R if report["risk_level"] in ("CRITICAL", "HIGH") else Y
    print(f"  Risk Level    : {risk_colour}{B}{report['risk_level']}{X}")
    print(f"  Servers       : {report['servers_assessed']} assessed, "
          f"{report['servers_blocked']} blocked")
    print(f"  Total Threats : {report['total_threats']}")
    if report["owasp_ids_triggered"]:
        print(f"  OWASP IDs     : {', '.join(report['owasp_ids_triggered'])}")

    print(f"\n{B}LLM Analysis:{X}")
    for line in report["llm_report"].splitlines():
        print(f"  {line}")

    print(f"\n{D}Session: {report['session_id']}{X}")
    print()

    return report


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SentinelMCP LangGraph Security Research Agent"
    )
    parser.add_argument(
        "--servers", nargs="+",
        default=[CLEAN_SERVER, POISONED_SERVER],
        help="MCP server URLs to assess (default: clean + poisoned demo servers)",
    )
    parser.add_argument(
        "--explain", metavar="THREAT_TYPE",
        help="Explain a threat type using RAG (e.g. PROMPT_INJECTION, RUG_PULL)",
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Write JSON report to file",
    )
    args = parser.parse_args()

    if args.explain:
        print(f"\nExplaining: {args.explain}\n")
        agent = SentinelRAGAgent()
        result = agent.explain(args.explain)
        print(result)
        return

    report = run_assessment(args.servers)

    if args.output:
        with open(args.output, "w") as f:
            # Remove non-serializable rag_agent from output
            clean = {k: v for k, v in report.items() if k != "rag_agent"}
            json.dump(clean, f, indent=2, default=str)
        print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
