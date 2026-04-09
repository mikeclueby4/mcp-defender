---
name: defender-kql
description: >
  Expert guidance for writing and executing KQL queries against Microsoft Defender
  Advanced Hunting via the mcp-defender MCP server. Use this skill whenever the user
  asks about security events, threat hunting, investigating alerts, querying Defender
  tables, or anything involving KQL / Advanced Hunting — even if they don't say
  "defender-kql" explicitly. Also invoke for questions like "show me devices that...",
  "find sign-ins from...", "hunt for...", or "what happened to <entity>".
---

# Defender Advanced Hunting — KQL Guidance

You have access to two MCP tools:
- `get_hunting_schema` — fetch table schema (optionally with `table_name` for column detail)
- `run_hunting_query` — execute KQL against the tenant

## Before writing any query

**For any table you haven't used in this session**, do both of these before writing the real query:

1. `get_hunting_schema(table_name="<TableName>")` — get column names and types
2. `run_hunting_query("TableName | take 3")` — see real data shapes and value formats

This is especially important for tables with `dynamic` columns (bags of key/value pairs whose keys aren't visible in the schema). Skipping this step leads to queries that look valid but return nothing.

**For tables with complex dynamic columns** — particularly `ExposureGraphNodes`, `ExposureGraphEdges`, `AIAgentsInfo`, `CloudAppEvents` — also fetch the live Microsoft reference for that table. The docs help with column types and general structure; for dynamic columns like `NodeProperties` whose keys aren't enumerated in the docs, the `take 3` live sample (step 2 above) remains essential.

The target URL pattern is:
```
https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-<tablename-lowercase>-table
```

Fetch docs using whichever method is available, in priority order:

**1. MS Learn MCP** (best — structured markdown, no !INCLUDE gaps):
Look for a tool named `microsoft_docs_fetch` in your available tools (it may be prefixed `mcp__microsoft-learn__` or similar depending on how the user registered it). Call it with the learn.microsoft.com URL above.
If not yet configured, suggest the user add it — it's public, no auth needed:
```bash
claude mcp add --transport http microsoft-learn https://learn.microsoft.com/api/mcp
```

**2. raw.githubusercontent.com** (good fallback — raw markdown, free):
The defender-xdr docs source is in `MicrosoftDocs/defender-docs`. Try:
```
https://raw.githubusercontent.com/MicrosoftDocs/defender-docs/public/defender-xdr/advanced-hunting-<tablename-lowercase>-table.md
```
Caveat: `!INCLUDE` directives appear as literal text rather than being expanded. For most table reference pages the core schema content is inline, so this is usually fine.

**3. `web_read`** (web-utility-belt MCP) — fetch the rendered HTML page as a last resort.

---

## CRITICAL: IP address comparisons

**Never use string equality (`==`) or string-based joins on IP address columns.**

IPv4 addresses are increasingly logged in IPv6-mapped form: `::ffff:1.2.3.4`. A plain `IPAddress == "1.2.3.4"` will silently miss these rows — no error, just wrong (incomplete) results.

**Always use `ipv6_is_match()`:**

```kql
// Single IP
| where ipv6_is_match(IPAddress, "1.2.3.4")

// CIDR range — netmask is IPv6 prefix length, NOT the IPv4 prefix length
// Convert: IPv6 prefix = IPv4 prefix + 96
//   /8  → 104,  /16 → 112,  /24 → 120,  /32 → 128
// Example: 10.0.0.0/8 in IPv4 → ipv6_is_match(IP, "10.0.0.0", 104)
| where ipv6_is_match(IPAddress, "10.0.0.0", 104)

// Joining two tables on IP
| join kind=inner (
    OtherTable
    | extend IPKey = IPAddress
) on $left.SrcIP == $right.IPKey   // WRONG — use mv-expand + ipv6_is_match instead

// Better join pattern:
TableA
| join kind=inner TableB on $left.SrcIP == $right.DstIP  // only safe if both came from same source
// If unsure, normalize first:
| extend NormalizedIP = iff(IPAddress startswith "::ffff:", substring(IPAddress, 7), IPAddress)
```

When joining two tables on IPs where you can't guarantee format consistency, normalize both sides first or use `ipv6_is_match` in a post-join `where`.

---

## Defender KQL syntax gotchas

These diverge from standard ADX/KQL and will silently produce parse errors or wrong results:

**No ternary operator** — `condition ? a : b` is not supported. Use `iff()`:
```kql
// WRONG — parse error
| extend Label = IsBlocked ? "Blocked" : "Active"
// RIGHT
| extend Label = iff(IsBlocked, "Blocked", "Active")
```

**`let` + `union`/`join` causes parse errors** — Defender KQL does not support `union` or `join` downstream of a `let` subquery. This catches people writing before/after comparisons with two `let` windows joined together:
```kql
// WRONG — parse error
let Baseline = TableA | where Timestamp between (ago(30d) .. ago(3d));
let Recent   = TableA | where Timestamp > ago(3d);
Baseline | join kind=inner Recent on AppId  // fails
// also fails with: Baseline | union Recent

// RIGHT for before/after comparisons — use evaluate pivot() on a Period column:
TableA
| where Timestamp > ago(30d)
| extend Period = iff(Timestamp > ago(3d), "Recent", "Baseline")
| summarize Events=count() by AppId, Period
| evaluate pivot(Period, sum(Events))
| extend SpikeRatio = iff(todouble(Baseline) > 0, round(todouble(Recent) / todouble(Baseline), 2), todouble(999))

// RIGHT for multi-table queries — run as separate queries
TableA | where ...
// -- and separately --
TableB | where ...
```

**Double-serialized dynamic columns** — some dynamic columns (e.g. `NodeProperties`, `AgentToolsDetails`) are stored as JSON-encoded strings, not native dynamic objects. Direct property access returns null; wrap with `tostring()` first:
```kql
// WRONG — returns null
| extend val = NodeProperties.rawData.exposureScore
// RIGHT
| extend props = parse_json(tostring(NodeProperties))
| extend val = tostring(props.rawData.exposureScore)
```

---

## General KQL hygiene

**Time filter** — always include one; default to last 7 days unless the user specifies otherwise:
```kql
| where Timestamp > ago(7d)
```

**Limit columns** — use `project` to return only what's needed; Defender tables are wide and raw rows waste context:
```kql
| project Timestamp, DeviceName, AccountUpn, ActionType, AdditionalFields
```

**Summarize over raw rows** — for large tables (`DeviceEvents`, `DeviceNetworkEvents`, `EmailEvents`), prefer aggregation unless the user needs individual events:
```kql
| summarize Count=count() by DeviceName, ActionType
| sort by Count desc
```

**Large result sets** — if a query returns more rows than fit comfortably in context, spawn a subagent to ingest and summarize the output. Always use `model: "haiku"` for these — the task is pure reading/summarization, not reasoning, and Haiku is faster and cheaper for it.

**Dynamic column access** — use `tostring()`, `toint()`, `parse_json()`, and `bag_keys()` to work with dynamic columns safely:
```kql
| extend parsed = parse_json(AdditionalFields)
| extend ProcessName = tostring(parsed.ProcessName)
```

---

## Table coverage notes

The tenant has these notable tables that may need extra care:

| Table | Notes |
|-------|-------|
| `AIAgentsInfo` | Copilot Studio / AI agent inventory. `AgentToolsDetails`, `KnowledgeDetails`, `ConnectedAgentsSchemaNames` are dynamic — sample first. Data is sparse/snapshot-style — `ago(7d)` typically returns 0 rows; use `ago(90d)` or omit the time filter. |
| `EntraIdSignInEvents` | GA replacement for `AADSignInEventsBeta`. Has `GatewayJA4` (TLS fingerprint) and `IsSignInThroughGlobalSecureAccess` — tenant uses Global Secure Access. |
| `ExposureGraphNodes/Edges` | Security Exposure Management graph. `NodeProperties` keys vary by `NodeLabel` — the official docs don't enumerate them; always live-sample with `take 3` first. |
| `GraphAPIAuditEvents` | MS Graph API audit log. `RequestUri` + `Scopes` + `TargetWorkload` are the key hunting columns. |
| `MessageEvents` | Teams message security events (not email — that's `EmailEvents`). |
| `CloudStorageAggregatedEvents` | Aggregated Azure storage access; note `DataAggregationStartTime/EndTime` rather than a single `Timestamp`. |
| `AADSignInEventsBeta` | Still present alongside `EntraIdSignInEvents`; prefer the Entra table for new queries. |
