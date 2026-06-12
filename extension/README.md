# SentinelMCP for VS Code

Real-time AI agent security monitoring for MCP tool calls.

## Features

- **Status bar** — live threat count, updates every 30 seconds
- **Auto-analyze** — detects changes to `.mcp.json`, `.claude.json`
- **Security probe** — run active pen tests against any MCP server
- **Compliance reports** — PCI DSS 6.4.3 and SOC2 CC6.1 mappings

## Setup

1. Start the SentinelMCP gateway: `docker compose up -d`
2. Set your API key in VS Code settings: `sentinelmcp.apiKey`
3. Gateway URL defaults to `http://localhost:8888`

## Commands

Open the Command Palette (`Cmd+Shift+P`) and search "SentinelMCP":

| Command | Description |
|---|---|
| Analyze MCP Servers | Scan all MCP configs in workspace |
| Run Security Probe | Active pen test against a server URL |
| Show Compliance Report | PCI/SOC2 compliance JSON |
| Show Recent Threats | Last 7 days of blocked threats |
| Open Dashboard | Open the web dashboard |

## Build

```bash
cd extension
npm install
npm run compile
```

To package: `npx vsce package`
