/**
 * SentinelMCP VS Code Extension
 *
 * Features:
 * - Status bar showing live threat count
 * - Analyze MCP config files on change
 * - Run penetration test probes
 * - View compliance reports
 * - Works alongside Claude Code, GitHub Copilot, Continue.dev
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import {
  getHealth,
  getThreats,
  getThreatsStats,
  analyzeServer,
  getComplianceReport,
  probeServer,
  SentinelConfig,
  ProbeReport,
} from './api';

// ── State ─────────────────────────────────────────────────────────────────────

let statusBarItem: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;
let pollTimer: ReturnType<typeof setInterval> | undefined;
let lastThreatCount = 0;

// ── Config helper ─────────────────────────────────────────────────────────────

function getConfig(): SentinelConfig {
  const cfg = vscode.workspace.getConfiguration('sentinelmcp');
  return {
    gatewayUrl: cfg.get<string>('gatewayUrl', 'http://localhost:8888'),
    apiKey: cfg.get<string>('apiKey', 'dev-key-123'),
  };
}

// ── Status bar ────────────────────────────────────────────────────────────────

async function updateStatusBar(): Promise<void> {
  const cfg = vscode.workspace.getConfiguration('sentinelmcp');
  if (!cfg.get<boolean>('showStatusBar', true)) {
    statusBarItem.hide();
    return;
  }

  try {
    const stats = await getThreatsStats(getConfig());
    const blocked = stats.total_blocked ?? 0;
    lastThreatCount = blocked;

    if (blocked === 0) {
      statusBarItem.text = '$(shield) Sentinel: Safe';
      statusBarItem.backgroundColor = undefined;
      statusBarItem.tooltip = 'SentinelMCP: No threats blocked recently. Click to open dashboard.';
    } else {
      statusBarItem.text = `$(warning) Sentinel: ${blocked} blocked`;
      statusBarItem.backgroundColor = new vscode.ThemeColor(
        blocked > 10 ? 'statusBarItem.errorBackground' : 'statusBarItem.warningBackground'
      );
      statusBarItem.tooltip = `SentinelMCP: ${blocked} threats blocked. Click to view threats.`;
    }
    statusBarItem.show();
  } catch {
    statusBarItem.text = '$(shield) Sentinel: Offline';
    statusBarItem.backgroundColor = undefined;
    statusBarItem.tooltip = 'SentinelMCP: Gateway offline. Check settings.';
    statusBarItem.show();
  }
}

// ── MCP config discovery ──────────────────────────────────────────────────────

interface McpConfig {
  mcpServers?: Record<string, { url?: string; command?: string }>;
  servers?: Record<string, { url?: string }>;
}

function findMcpServerUrls(workspaceRoot: string): string[] {
  const configFiles = [
    '.mcp.json',
    '.claude.json',
    'claude_desktop_config.json',
    '.copilot/mcp.json',
  ];

  const urls: string[] = [];
  for (const file of configFiles) {
    const filePath = path.join(workspaceRoot, file);
    if (!fs.existsSync(filePath)) continue;
    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      const parsed: McpConfig = JSON.parse(raw);
      const servers = parsed.mcpServers ?? parsed.servers ?? {};
      for (const [, server] of Object.entries(servers)) {
        if (server.url) {
          urls.push(server.url);
        }
      }
    } catch {
      // malformed JSON — skip
    }
  }
  return urls;
}

// ── Commands ──────────────────────────────────────────────────────────────────

async function cmdAnalyze(): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) {
    vscode.window.showWarningMessage('SentinelMCP: No workspace folder open.');
    return;
  }

  const config = getConfig();
  outputChannel.show(true);
  outputChannel.appendLine(`\n[${'='.repeat(60)}]`);
  outputChannel.appendLine(`[SentinelMCP] Analyzing MCP servers — ${new Date().toISOString()}`);

  let totalIssues = 0;
  for (const folder of folders) {
    const urls = findMcpServerUrls(folder.uri.fsPath);
    if (!urls.length) {
      outputChannel.appendLine(`[INFO] No MCP server URLs found in ${folder.name}`);
      continue;
    }

    outputChannel.appendLine(`[INFO] Found ${urls.length} server(s) in ${folder.name}`);
    for (const url of urls) {
      outputChannel.appendLine(`\n  Analyzing: ${url}`);
      try {
        const result = await analyzeServer(config, url);
        if (result.verdict === 'BLOCK' || result.threats_found > 0) {
          totalIssues += result.threats_found;
          outputChannel.appendLine(`  [BLOCKED] ${result.threats_found} threat(s) found`);
          for (const t of result.threats) {
            outputChannel.appendLine(`    - ${t.threat_type} | ${t.pattern} | confidence: ${(t.confidence * 100).toFixed(0)}%`);
            if (t.owasp_id) {
              outputChannel.appendLine(`      OWASP: ${t.owasp_id}`);
            }
          }
          vscode.window.showWarningMessage(
            `SentinelMCP: ${result.threats_found} threat(s) found in ${url}`,
            'View Details'
          ).then(choice => { if (choice) outputChannel.show(); });
        } else {
          outputChannel.appendLine(`  [PASS] No threats detected (${result.latency_ms.toFixed(1)}ms)`);
        }
      } catch (err) {
        outputChannel.appendLine(`  [ERROR] ${err}`);
      }
    }
  }

  if (totalIssues === 0) {
    vscode.window.showInformationMessage('SentinelMCP: All MCP servers appear secure.');
  }
  await updateStatusBar();
}

async function cmdShowReport(): Promise<void> {
  const config = getConfig();
  vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'Fetching compliance report...' },
    async () => {
      try {
        const report = await getComplianceReport(config, 30);
        const doc = await vscode.workspace.openTextDocument({
          language: 'json',
          content: JSON.stringify(report, null, 2),
        });
        await vscode.window.showTextDocument(doc);
      } catch (err) {
        vscode.window.showErrorMessage(`SentinelMCP: Failed to fetch report — ${err}`);
      }
    }
  );
}

async function cmdProbe(): Promise<void> {
  const serverUrl = await vscode.window.showInputBox({
    prompt: 'Enter MCP server URL to probe',
    placeHolder: 'http://localhost:8001',
    validateInput: v => (v.startsWith('http') ? null : 'Must be a valid HTTP URL'),
  });
  if (!serverUrl) return;

  const attackPick = await vscode.window.showQuickPick(
    [
      { label: 'All attacks', description: 'Run all 7 OWASP probe types', value: ['all'] },
      { label: 'Prompt injection only', description: 'LLM01 — check tool descriptions', value: ['prompt_injection'] },
      { label: 'PII leak only', description: 'LLM06 — check for sensitive data in responses', value: ['pii_leak'] },
      { label: 'Supply chain (rug pull)', description: 'LLM05 — detect schema changes', value: ['rug_pull'] },
    ],
    { placeHolder: 'Select attack types to run' }
  );
  if (!attackPick) return;

  const config = getConfig();
  outputChannel.show(true);
  outputChannel.appendLine(`\n[SentinelMCP] Probing ${serverUrl}...`);

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `SentinelMCP: Probing ${serverUrl}...`,
      cancellable: false,
    },
    async () => {
      try {
        const report: ProbeReport = await probeServer(config, serverUrl, (attackPick as any).value);
        outputChannel.appendLine(`\nRisk Level: ${report.risk_level} (score: ${report.risk_score}/10)`);
        outputChannel.appendLine(`Vulnerabilities: ${report.vulnerabilities_found}/${report.findings.length}`);
        outputChannel.appendLine(`\nFindings:`);
        for (const f of report.findings) {
          const icon = f.verdict === 'VULNERABLE' ? '🔴' : f.verdict === 'PROTECTED' ? '🟢' : '🟡';
          outputChannel.appendLine(`  ${icon} [${f.owasp_id}] ${f.attack_type}: ${f.verdict}`);
          outputChannel.appendLine(`     ${f.details}`);
        }
        outputChannel.appendLine(`\nRecommendation: ${report.recommendation}`);

        const level = report.risk_level;
        const msg = `SentinelMCP Probe: ${level} risk — ${report.vulnerabilities_found} vulnerabilities found`;
        if (level === 'CRITICAL' || level === 'HIGH') {
          vscode.window.showErrorMessage(msg, 'View Details').then(c => { if (c) outputChannel.show(); });
        } else if (level === 'MEDIUM' || level === 'LOW') {
          vscode.window.showWarningMessage(msg, 'View Details').then(c => { if (c) outputChannel.show(); });
        } else {
          vscode.window.showInformationMessage(msg);
        }
      } catch (err) {
        outputChannel.appendLine(`[ERROR] Probe failed: ${err}`);
        vscode.window.showErrorMessage(`SentinelMCP: Probe failed — ${err}`);
      }
    }
  );
}

async function cmdOpenDashboard(): Promise<void> {
  const config = getConfig();
  const base = config.gatewayUrl.replace(/:\d+$/, '');
  const dashUrl = `${base}:5173`;
  await vscode.env.openExternal(vscode.Uri.parse(dashUrl));
}

async function cmdShowThreats(): Promise<void> {
  const config = getConfig();
  try {
    const result = await getThreats(config, 7);
    outputChannel.show(true);
    outputChannel.appendLine(`\n[SentinelMCP] Recent threats (last 7 days): ${result.total}`);
    for (const t of result.threats.slice(0, 20)) {
      outputChannel.appendLine(
        `  [${t.created_at.slice(0, 16)}] ${t.threat_type} | ${t.tool_name} | L${t.layer} | ${t.blocked ? 'BLOCKED' : 'FLAGGED'}`
      );
    }
    if (result.total > 20) {
      outputChannel.appendLine(`  ... and ${result.total - 20} more`);
    }
  } catch (err) {
    vscode.window.showErrorMessage(`SentinelMCP: Failed to fetch threats — ${err}`);
  }
}

// ── File watcher ──────────────────────────────────────────────────────────────

function setupFileWatcher(context: vscode.ExtensionContext): void {
  const pattern = '**/{.mcp.json,.claude.json,claude_desktop_config.json}';
  const watcher = vscode.workspace.createFileSystemWatcher(pattern);

  const onChanged = async (uri: vscode.Uri) => {
    const cfg = vscode.workspace.getConfiguration('sentinelmcp');
    if (!cfg.get<boolean>('autoAnalyze', true)) return;
    outputChannel.appendLine(`[INFO] MCP config changed: ${uri.fsPath}`);
    vscode.window.showInformationMessage(
      `SentinelMCP: MCP config changed — analyzing...`,
      'Analyze Now', 'Ignore'
    ).then(choice => { if (choice === 'Analyze Now') cmdAnalyze(); });
  };

  watcher.onDidChange(onChanged);
  watcher.onDidCreate(onChanged);
  context.subscriptions.push(watcher);
}

// ── Extension lifecycle ───────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  outputChannel = vscode.window.createOutputChannel('SentinelMCP');

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = 'sentinelmcp.showThreats';
  context.subscriptions.push(statusBarItem);

  // Register commands
  const cmds: [string, () => Promise<void>][] = [
    ['sentinelmcp.analyze', cmdAnalyze],
    ['sentinelmcp.showReport', cmdShowReport],
    ['sentinelmcp.probe', cmdProbe],
    ['sentinelmcp.openDashboard', cmdOpenDashboard],
    ['sentinelmcp.showThreats', cmdShowThreats],
  ];
  for (const [cmd, fn] of cmds) {
    context.subscriptions.push(vscode.commands.registerCommand(cmd, fn));
  }

  // File watcher
  setupFileWatcher(context);

  // Start polling
  const cfg = vscode.workspace.getConfiguration('sentinelmcp');
  const interval = (cfg.get<number>('pollIntervalSecs', 30)) * 1000;
  updateStatusBar();
  pollTimer = setInterval(updateStatusBar, interval);

  // Refresh on config change
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration('sentinelmcp')) {
        updateStatusBar();
      }
    })
  );

  outputChannel.appendLine('SentinelMCP extension activated.');
}

export function deactivate(): void {
  if (pollTimer) clearInterval(pollTimer);
  statusBarItem?.dispose();
  outputChannel?.dispose();
}
