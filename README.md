# MCP Defender

This repo is a fork of [trickyfalcon/mcp-defender](https://github.com/trickyfalcon/mcp-defender).

An MCP (Model Context Protocol) server for Microsoft Defender Advanced Hunting and Microsoft Sentinel. Enables AI assistants to investigate security events using natural language by translating queries to KQL and executing them against Defender or Sentinel.

## Why fork?

The upstream repo authenticates as a **service principal** (certificate or client secret), which requires an application-permission app registration and admin consent for `AdvancedQuery.Read.All`. This fork defaults to **`InteractiveBrowserCredential`** — auth code + PKCE — so the server authenticates as the signed-in user instead. The app registration then only needs **delegated** permission (`ThreatHunting.Read.All` on Microsoft Graph), and no secret or certificate is needed, which reduces blast radius on the app.

This fork also:
- Migrates from the retired `api.security.microsoft.com` endpoint to the **Microsoft Graph Security API** (`graph.microsoft.com/v1.0/security/runHuntingQuery`)
- Adds **Microsoft Sentinel / Log Analytics** support (`run_sentinel_query`, `get_sentinel_tables`)
- Ships a bundled **Claude Code skill** for expert KQL authoring against both Defender and Sentinel
- **Enables all GitHub public-repo security features** (dependabot, codeql, vuln alerting, etc)

## How It Works

```
User: "Show me suspicious PowerShell activity in the last hour"
  ↓
AI translates to KQL using schema knowledge
  ↓
MCP executes query against Defender or Sentinel API
  ↓
AI interprets and explains the results
```

## Features

- **Advanced Hunting**: Execute KQL queries against the Microsoft Graph Security API
- **Microsoft Sentinel**: Execute KQL queries against Log Analytics workspaces (optional)
- **Dynamic Schema Discovery**: Fetch available tables and columns directly from your Defender or Sentinel instance
- **Natural Language Security Investigations**: Let AI translate your questions into KQL
- **Flexible Authentication**: Interactive browser (delegated user auth), certificate, or client secret

## Prerequisites

- Python 3.10+ (or `uv` / `uvx` for zero-install usage)
- Azure AD App Registration — see [HOWTO-ENTRA-APPREG-DELEGATED.md](HOWTO-ENTRA-APPREG-DELEGATED.md) for step-by-step setup

## Required API Permissions

### Interactive browser / delegated auth (recommended)

Register a **Public client** app in Entra ID (no secret or certificate needed):

- API permission: **Microsoft Graph** → `ThreatHunting.Read.All` (Delegated) — grant admin consent
- For Sentinel: **Log Analytics API** → `Data.Read` (Delegated) — grant admin consent
- The signed-in user needs **Security Reader** (or equivalent Defender "View Data" role)
- Set `AZURE_TENANT_ID` and `AZURE_CLIENT_ID`; leave `AZURE_CLIENT_SECRET` and `AZURE_CLIENT_CERTIFICATE_PATH` unset

See [HOWTO-ENTRA-APPREG-DELEGATED.md](HOWTO-ENTRA-APPREG-DELEGATED.md) for step-by-step setup.

### Service principal (certificate or client secret)

- API permission: **Microsoft Graph** → `ThreatHunting.Read.All` (Application, admin consented)
- For Sentinel: **Log Analytics API** → `Data.Read` (Application, admin consented)

## Configuration

1. Copy `.env.example` to `.env`
2. Fill in your Azure AD credentials:

```bash
# Option 1: Interactive browser — opens a browser for sign-in on first use (recommended)
# Requires a public client app registration. See HOWTO-ENTRA-APPREG-DELEGATED.md.
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id

# Option 2: Certificate authentication (service principal / no user required)
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_CERTIFICATE_PATH=/path/to/combined.pem

# Option 3: Client secret (service principal / no user required)
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret

# Optional: Microsoft Sentinel (enables run_sentinel_query + get_sentinel_tables)
SENTINEL_WORKSPACE_ID=your-log-analytics-workspace-id
```

For certificate auth, combine your private key and certificate:

```bash
cat private.key cert.pem > combined.pem
```

## Installation

```bash
# Recommended: install with uv
uv tool install git+https://github.com/mikeclueby4/mcp-defender

# Or with pip
pip install git+https://github.com/mikeclueby4/mcp-defender
```

## Usage

### Running the server

```bash
# After installing with uv tool install / pip install:
mcp-msdefenderkql

# Or run directly without installing (uv handles the venv):
uvx --from git+https://github.com/mikeclueby4/mcp-defender mcp-msdefenderkql

# Test interactively with MCP Inspector:
npx @modelcontextprotocol/inspector mcp-msdefenderkql
```

### Claude Code / Claude Desktop Configuration

Add to your MCP settings. Use the `uvx` form so no prior install step is needed:

**Claude Code** — project-level `.claude/settings.json` or user-level `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "defender": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/mikeclueby4/mcp-defender", "mcp-msdefenderkql"],
      "env": {
        "AZURE_TENANT_ID": "your-tenant-id",
        "AZURE_CLIENT_ID": "your-client-id"
      }
    }
  }
}
```

**Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "defender": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/mikeclueby4/mcp-defender", "mcp-msdefenderkql"],
      "env": {
        "AZURE_TENANT_ID": "your-tenant-id",
        "AZURE_CLIENT_ID": "your-client-id"
      }
    }
  }
}
```

For certificate auth, add `"AZURE_CLIENT_CERTIFICATE_PATH": "/path/to/combined.pem"` to `env`.  
For Sentinel, add `"SENTINEL_WORKSPACE_ID": "your-workspace-id"` to `env`.

## Available Tools

| Tool | Description |
|------|-------------|
| `run_hunting_query` | Execute KQL queries against Defender Advanced Hunting (Microsoft Graph Security API). Returns TSV with a header row. Results over ~10 KB are truncated inline; the full result is written to a tmpfile whose path is reported in a `[MCP-DEFENDER:OVERFLOW]` marker line. |
| `get_hunting_schema` | Get available Defender Advanced Hunting tables and columns |
| `run_sentinel_query` | Execute KQL queries against a Log Analytics workspace (Sentinel). Same TSV/overflow output format. Only available when `SENTINEL_WORKSPACE_ID` is set. |
| `get_sentinel_tables` | List all tables in the configured Log Analytics workspace. Only available when `SENTINEL_WORKSPACE_ID` is set. |

## Example Natural Language Queries

Once connected to Claude, you can ask:

- *"Show me any suspicious PowerShell activity in the last hour"*
- *"Find devices with failed login attempts"*
- *"What processes are making network connections to external IPs?"*
- *"List all devices that haven't checked in for 7 days"*
- *"Show me failed sign-ins from my Sentinel workspace in the last 24 hours"*

## Example KQL Queries

```kql
// Find failed logon attempts
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where Timestamp > ago(24h)
| summarize FailedAttempts = count() by AccountName, DeviceName
| top 10 by FailedAttempts

// Detect suspicious PowerShell
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("encodedcommand", "bypass", "hidden", "downloadstring")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Network connections to external IPs
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where Timestamp > ago(1h)
| summarize ConnectionCount = count() by DeviceName, RemoteIP
| top 20 by ConnectionCount
```

## Claude Code Skill

This repo ships a bundled **`defender-kql` Claude Code skill** in [`.claude/skills/defender-kql/`](.claude/skills/defender-kql/). It is loaded automatically when you open this repository in Claude Code.

The skill provides expert guidance for writing KQL against Defender Advanced Hunting and Sentinel, including:

- Tool routing (Defender vs Sentinel) and pre-query schema inspection workflow
- IP address comparison pitfalls (`ipv6_is_match()` for IPv4-mapped addresses)
- Defender-specific KQL syntax differences from standard ADX (no ternary, `let`+`join` limitations, double-serialized dynamic columns)
- Table-specific notes for `AIAgentsInfo`, `ExposureGraphNodes`, `EntraIdSignInEvents`, and others
- Entra/AAD table family split between Defender and Sentinel

The [`.claude/skills/defender-kql-workspace/`](.claude/skills/defender-kql-workspace/) folder contains the skill evaluation suite (6 evals across 3 iterations) used to measure and tune the skill.

## API Reference

| API | Endpoint |
|-----|----------|
| Defender Advanced Hunting | `POST https://graph.microsoft.com/v1.0/security/runHuntingQuery` |
| Defender Schema | `GET https://graph.microsoft.com/v1.0/security/runHuntingQuery` (schema endpoint) |
| Sentinel / Log Analytics | `POST https://api.loganalytics.azure.com/v1/workspaces/{id}/query` |

## License

MIT
