# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Fork of [trickyfalcon/mcp-defender](https://github.com/trickyfalcon/mcp-defender)** — replaces app-registration certificate/secret auth with `InteractiveBrowserCredential` (auth code + PKCE), so the server authenticates as the signed-in user rather than a service principal. Requires only a public client app registration with `ThreatHunting.Read.All` (Delegated on Microsoft Graph) — no certificate or secret.

MCP server for Microsoft Defender Advanced Hunting and Microsoft Sentinel. Enables AI assistants to execute KQL queries and investigate security events via natural language through the Model Context Protocol.

**Use case**: Users ask questions in natural language → AI translates to KQL → MCP executes against Defender or Sentinel → AI interprets results.

## Key Files

```
src/mcp_defender/server.py   # Entire server — credential init, token fetch, query execution, tool handlers
tests/test_server.py         # Tool schema tests (no live API calls; mock-free, tests list_tools() only)
pyproject.toml               # Entry point: mcp-msdefenderkql → mcp_defender.server:main
HOWTO-ENTRA-APPREG-DELEGATED.md  # Step-by-step Entra ID app registration guide for delegated auth
```

## Architecture

**Tools exposed** (2 always present + 2 conditional on `SENTINEL_WORKSPACE_ID`):
- `run_hunting_query` — executes KQL via the **Microsoft Graph Security API** (`POST graph.microsoft.com/v1.0/security/runHuntingQuery`); returns TSV with a header row. Results over ~10 KB are truncated: a `[MCP-DEFENDER:OVERFLOW]` sentinel line records counts and the path of a tmpfile containing the full result.
- `get_hunting_schema` — fetches available Defender Advanced Hunting tables/columns from the same API
- `run_sentinel_query` — executes KQL via the **Log Analytics API** (`POST api.loganalytics.azure.com/v1/workspaces/{id}/query`); same TSV/overflow output format. Only registered when `SENTINEL_WORKSPACE_ID` is set.
- `get_sentinel_tables` — lists all tables in the Log Analytics workspace. Only registered when `SENTINEL_WORKSPACE_ID` is set.

**Key functions in `server.py`:**
- `get_credential()` — lazy-initialized; checks env vars to pick credential type (see auth priority below)
- `get_access_token()` — gets bearer token for the Graph Security API, scope `https://graph.microsoft.com/.default`
- `get_sentinel_access_token()` — gets bearer token for Log Analytics, scope `ca7f3f0b-7d91-482c-8e09-c5d840d0eac5/.default` (Log Analytics SP app ID — the URL alias `api.loganalytics.azure.com` is not in its `servicePrincipalNames`)
- `run_defender_query()` — httpx POST to `https://graph.microsoft.com/v1.0/security/runHuntingQuery`
- `run_sentinel_query_http()` — httpx POST to `https://api.loganalytics.azure.com/v1/workspaces/{id}/query`

**Authentication priority in `get_credential()` — all require `AZURE_TENANT_ID` + `AZURE_CLIENT_ID`:**

1. **CertificateCredential** — if `AZURE_CLIENT_CERTIFICATE_PATH` is set (optional: `AZURE_CLIENT_CERTIFICATE_PASSWORD`)
2. **ClientSecretCredential** — if `AZURE_CLIENT_SECRET` is set
3. **InteractiveBrowserCredential** — fallback; opens browser on first use, then caches token persistently via `msal-extensions` (DPAPI on Windows); silent on subsequent starts until refresh token expires. `authenticate()` is called with only the Graph scope — the Sentinel token is acquired lazily on first use (avoids `AADSTS70011` multi-resource scope error).

> **Why not `AzureCliCredential`?** The Azure CLI's own first-party app was never granted `ThreatHunting.Read.All` — tokens only carry `user_impersonation`, which the Graph Security API rejects.
>
> **Why not `DeviceCodeCredential`?** Microsoft rolled out a default CA policy "Block device code flow" from Feb–May 2025. It will be blocked on most tenants.

## Bundled Claude Code Skill

`.claude/skills/defender-kql/SKILL.md` — loaded automatically when this repo is open in Claude Code. Provides KQL authoring guidance: tool routing (Defender vs Sentinel), pre-query schema inspection, `ipv6_is_match()` for IP comparisons, Defender-specific syntax gotchas, Entra/AAD table family split, and per-table notes.

`.claude/settings.json` — pre-registers the `microsoft-learn` MCP (`https://learn.microsoft.com/api/mcp`) for anyone opening this repo in Claude Code, enabling `microsoft_docs_fetch` which is listed in the skill's `allowed-tools`.

`.claude/skills/defender-kql-workspace/` — skill evaluation suite. Contains `evals.json`, 3 iterations of 6 evals each (with/without skill), and HTML benchmark reviews. Run evals with `model=sonnet-4.6` and `effort=low`; view HTML results with `start <path>.html` on Windows.

## Commands (or `uv` equivalents)

```bash
pip install -e ".[dev]"   # install with dev deps
mcp-msdefenderkql         # run the server
pytest                    # run tests (no live API needed)
ruff check .              # lint
mypy src                  # type check
```
