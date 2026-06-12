/**
 * SentinelMCP API client for VS Code extension.
 * Uses the native fetch() API (available in Node 18+ / VS Code built-in).
 */

export interface SentinelConfig {
  gatewayUrl: string;
  apiKey: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  cached_servers: number;
  latency_ms: Record<string, number>;
}

export interface AnalyzeResult {
  verdict: string;
  threats_found: number;
  threats: Array<{
    threat_type: string;
    pattern: string;
    match: string;
    confidence: number;
    owasp_id?: string;
  }>;
  latency_ms: number;
  session_id?: string;
}

export interface ThreatEvent {
  id: string;
  session_id: string;
  tool_name: string;
  threat_type: string;
  layer: number;
  pattern: string;
  blocked: boolean;
  timestamp: string;
}

export interface ThreatsResponse {
  threats: ThreatEvent[];
  total: number;
}

export interface ComplianceReport {
  period_days: number;
  total_threats: number;
  threats_blocked: number;
  compliance: Record<string, unknown>;
}

export interface ProbeReport {
  server_url: string;
  tested_at: string;
  risk_level: string;
  risk_score: number;
  vulnerabilities_found: number;
  findings: Array<{
    attack_type: string;
    verdict: string;
    severity: string;
    owasp_id: string;
    details: string;
  }>;
  recommendation: string;
}

function headers(config: SentinelConfig): Record<string, string> {
  return {
    'X-Sentinel-Key': config.apiKey,
    'Content-Type': 'application/json',
  };
}

async function apiFetch<T>(
  config: SentinelConfig,
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${config.gatewayUrl.replace(/\/$/, '')}${path}`;
  const response = await fetch(url, {
    ...options,
    headers: { ...headers(config), ...(options.headers as Record<string, string> || {}) },
  });
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`SentinelMCP ${response.status}: ${body.slice(0, 200)}`);
  }
  return response.json() as Promise<T>;
}

export async function getHealth(config: SentinelConfig): Promise<HealthResponse> {
  return apiFetch<HealthResponse>(config, '/health');
}

export async function getThreatsStats(config: SentinelConfig): Promise<{
  by_type: Record<string, number>;
  total: number;
}> {
  return apiFetch(config, '/gateway/threats/stats');
}

export async function getThreats(config: SentinelConfig, days = 7): Promise<ThreatsResponse> {
  return apiFetch<ThreatsResponse>(config, `/gateway/threats?days=${days}&limit=50`);
}

export async function analyzeServer(
  config: SentinelConfig,
  serverUrl: string,
  toolCalls: unknown[] = []
): Promise<AnalyzeResult> {
  return apiFetch<AnalyzeResult>(config, '/proxy/analyze', {
    method: 'POST',
    body: JSON.stringify({ server_url: serverUrl, tool_calls: toolCalls }),
  });
}

export async function getComplianceReport(
  config: SentinelConfig,
  days = 30
): Promise<ComplianceReport> {
  return apiFetch<ComplianceReport>(config, `/gateway/compliance/report?days=${days}`);
}

export async function probeServer(
  config: SentinelConfig,
  serverUrl: string,
  attacks: string[] = ['all']
): Promise<ProbeReport> {
  return apiFetch<ProbeReport>(config, '/probe', {
    method: 'POST',
    body: JSON.stringify({ server_url: serverUrl, attacks }),
  });
}
