# SentinelMCP — AI Agent Security

SentinelMCP is a real-time security monitor for AI agent tool calls, detecting prompt injection, PII leaks, rug-pull attacks, and supply chain threats as they happen. It integrates directly into VS Code and connects to the SentinelMCP gateway to give you live visibility into MCP server activity.

![OWASP LLM Top 10](https://img.shields.io/badge/security-OWASP%20LLM%20Top%2010-green)

## Features

- **Live status bar** — threat count updates every 30 seconds; click to see recent threats
- **Security probe** — active pen tests with 7 OWASP LLM attack types against any MCP server URL
- **Compliance report viewer** — PCI DSS 6.4.3 and SOC2 CC6.1 mappings rendered in VS Code
- **Threat viewer** — last 7 days of blocked threats with severity, type, and tenant context
- **MCP config file watcher** — auto-detects and re-analyzes `.mcp.json` and `.claude.json` on save
- **Web dashboard** — one-click shortcut to the full Grafana/admin dashboard

> **Screenshot placeholder** — add a screenshot of the status bar and threat viewer here.

## Requirements

The SentinelMCP gateway must be running and reachable (default: `http://localhost:8888`).

Start the gateway with:

```bash
docker compose up -d
```

See the [SentinelMCP repository](https://github.com/saratala/sentinelmcp) for full setup instructions.

## Configuration

| Setting | Default | Description |
|---|---|---|
| `sentinelmcp.gatewayUrl` | `http://localhost:8888` | SentinelMCP gateway base URL |
| `sentinelmcp.apiKey` | `dev-key-123` | API key sent as `X-Sentinel-Key` header |
| `sentinelmcp.autoAnalyze` | `true` | Re-analyze MCP config files on save |
| `sentinelmcp.showStatusBar` | `true` | Show threat count in the status bar |
| `sentinelmcp.pollIntervalSecs` | `30` | Status bar refresh interval in seconds |

## Commands

Open the Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`) and search "SentinelMCP":

| Command | Description |
|---|---|
| **SentinelMCP: Analyze MCP Servers** | Scan all MCP config files in the workspace and report findings |
| **SentinelMCP: Run Security Probe** | Run an active pen test against a server URL using 7 OWASP attack types |
| **SentinelMCP: Show Compliance Report** | View PCI DSS and SOC2 compliance status in a VS Code panel |
| **SentinelMCP: Show Recent Threats** | Display the last 7 days of detected and blocked threats |
| **SentinelMCP: Open Dashboard** | Open the SentinelMCP web dashboard in your browser |

## License

MIT
