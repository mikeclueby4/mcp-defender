# MCP Server Usage Investigation Playbook

Symptoms: "what AI/MCP plugins are people using?", "what local MCP servers are installed?", inventory of AI tool integrations on endpoints.

> Query economy rules: **[KQL facts → Query economy](../kql-facts.md#query-economy--protect-your-context-budget)**

---

## Cross-platform filename matching

`FileName` contains `.exe` on Windows and no suffix on Mac/Linux. Use `has_any` with both variants to cover mixed fleets — `has_any` uses the inverted index and is fast even on large tables. Only Windows-specific noise (e.g. `conhost.exe`, `WerFault.exe`) needs the `.exe` form alone.

AI client set used throughout (bare names — `has_any` substring match covers `.exe` variants automatically):

| Agent | `FileName` match | Notes |
|---|---|---|
| Claude Desktop / Claude Code CLI | `claude` | Same binary name on all platforms |
| VS Code (any extension — Copilot, Cline, Continue) | `code` | |
| Cursor | `cursor` | |
| Windsurf | `windsurf` | |
| Gemini CLI | `gemini` | |
| OpenAI Codex CLI | `codex` | |

Canonical `has_any` blob — copy verbatim into every query. **Update this table and the blob together when adding new agents.**

```
"claude", "code", "cursor", "windsurf", "gemini", "codex"
```

Shell/runtime set: `"node", "npx", "python", "python3", "uv", "uvx", "cmd.exe", "bash", "sh", "zsh", "powershell", "pwsh"`

---

## Five detection strategies — use all five

MCP servers come in two transport flavours: **stdio** (local process, caught by Strategies 1–3) and **remote HTTP/SSE** (no local process, caught only by Strategy 4).

---

### Strategy 1: Server process command line

Catches the MCP server process itself (npm/npx, Python packages, standalone binaries).

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "mcp"
    and not (ProcessCommandLine has_any (
        "eslintServer", "pylance", "prettier", "tsserver", "pyright",
        "vscode-json-languageserver", "html-languageserver", "css-languageserver"
    ))
// AI client filter — update header table when adding new agents
| where InitiatingProcessFileName has_any (
        "claude", "code", "cursor", "windsurf", "gemini", "codex",
        "node", "python", "python3", "cmd.exe", "bash", "powershell", "pwsh", "sh", "zsh",
        "npx", "uvx", "uv")
    or InitiatingProcessCommandLine has_any ("claude", "codex", "cursor", "copilot", "windsurf", "gemini")
| where not (
    InitiatingProcessFileName has_any ("cmd.exe", "bash", "zsh", "sh", "powershell", "pwsh")
    and not (InitiatingProcessCommandLine has_any ("claude", "codex", "cursor", "copilot", "windsurf", "gemini"))
    and not (InitiatingProcessParentFileName has_any ("claude", "code", "cursor", "windsurf", "gemini", "codex"))
)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc
```

**Normalizing command lines into server identities** — extract a `ServerId` with `case()` matching on key substrings from `ProcessCommandLine`, then summarize by `ServerId`. Adapt the case branches to what you observe in your environment.

```kql
| extend ServerId = case(
    ProcessCommandLine has "some-mcp-server", "some-mcp-server",
    // add branches per server observed
    "other-mcp"
)
| where ServerId != "other-mcp"
| summarize Launches=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
    Users=make_set(InitiatingProcessAccountName, 10), Devices=make_set(DeviceName, 10),
    AIClients=make_set(InitiatingProcessFileName, 5)
  by ServerId
| sort by Launches desc
```

---

### Strategy 2: Tool-result filename patterns

Some MCP servers leave footprints in tool-result temp files that Claude Code writes, readable by child processes (`rg`, `python`, `bash`). The server process itself may not contain "mcp" in its command line.

Claude Code uses two temp-file naming schemes:

- **Older:** `~/.claude/projects/<hash>/<session>/tool-results/mcp-<server>-<tool>-<timestamp>.txt`
- **Newer:** `<tmpdir>/mcp__<server>__<tool> tool output (<shortid>).txt`

The newer format uses the `mcp__server__tool` namespace convention and lands in the OS temp directory. Files read directly by the Claude Code process may not surface in `DeviceProcessEvents` command lines due to Defender filtering.

Hunt via `DeviceFileEvents` for reads of files matching `mcp__*` or `mcp-*-tool-results` patterns by processes in the AI client ancestry.

---

### Strategy 3: Long-lived child processes of AI agent executables

MCP servers are persistent — started once, alive for the entire session. Estimate longevity from the spread between first and last `ProcessCreationTime` across all launches. **LongevityScore** = `SpanDays / Launches * 100` — a server seen across many days but rarely restarted scores high.

This catches servers whose binary name contains no "mcp" string at all.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
// AI client filter — update header table when adding new agents
| where InitiatingProcessFileName has_any ("claude", "code", "cursor", "windsurf", "gemini", "codex")
    or (InitiatingProcessFileName has_any ("node", "npx", "uv", "uvx")
        and InitiatingProcessCommandLine has_any ("claude", "cursor", "codex", "windsurf", "gemini"))
| where FileName !in~ (
    "conhost.exe", "WerFault.exe", "dllhost.exe", "msiexec.exe", "svchost.exe",
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "reg.exe", "sc.exe", "tasklist.exe"
)
| where not (FileName has "python"
    and ProcessCommandLine has_any ("lsp_server.py", "pylance", "pyright", "server.bundle.js"))
| summarize
    Launches      = count(),
    FirstSeen     = min(ProcessCreationTime),
    LastSeen      = max(ProcessCreationTime),
    UniqueDevices = dcount(DeviceName),
    Users         = make_set(InitiatingProcessAccountName, 5),
    SampleCmdLine = take_any(ProcessCommandLine),
    ParentCmdLine = take_any(InitiatingProcessCommandLine)
  by FileName, InitiatingProcessFileName
| extend SpanDays = round(datetime_diff("hour", LastSeen, FirstSeen) / 24.0, 1)
| extend LongevityScore = iff(Launches > 0, round(todouble(SpanDays) / todouble(Launches) * 100, 1), 0.0)
| sort by LongevityScore desc
| project FileName, InitiatingProcessFileName, Launches, SpanDays, LongevityScore, UniqueDevices, Users, SampleCmdLine
```

**LongevityScore interpretation:**

| Score | Signal |
|---|---|
| > 200 | Very strong MCP — seen across weeks, rarely restarted |
| 50–200 | Likely MCP — persistent across multiple days |
| 10–50 | Ambiguous |
| < 10 | Likely ephemeral |

**Common false positives:** VS Code updater (`CodeSetup-stable-*.exe`), extension VSIX verifier (`vsce-sign.exe`), tunnel probes, Python LSP servers (`--stdio` pattern mimics MCP but is not AI tooling), Python environment management daemons bundled inside VS Code extensions.

---

### Strategy 4: Remote/HTTP MCP servers via outbound network connections

Strategies 1–3 only catch **stdio** servers. **Remote MCP servers** (HTTP/SSE) leave no local process footprint — only an outbound HTTPS connection from the AI agent to an MCP endpoint.

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
// AI client filter — update header table when adding new agents
| where InitiatingProcessFileName has_any ("claude", "code", "cursor", "windsurf", "gemini", "codex")
    or (InitiatingProcessFileName has "node"
        and InitiatingProcessCommandLine has_any ("claude", "cursor", "codex", "windsurf", "gemini", "@anthropic-ai/claude-code"))
| where not (RemoteIP startswith "127." or RemoteIP == "::1")
| where RemotePort == 443
| where isnotempty(RemoteUrl)
| where RemoteUrl matches regex @"(?i)(^|[\./])mcp[\./]"
    or RemoteUrl has "mcp-proxy"
    or RemoteUrl has "api.mcp."
| summarize
    Connections = count(),
    UniqueDevices = dcount(DeviceName),
    Users = make_set(InitiatingProcessAccountName, 10)
  by RemoteUrl, InitiatingProcessFileName
| sort by Connections desc
```

Known remote MCP domains to look for: `mcp-proxy.anthropic.com` (Anthropic's relay — proxies to any user-configured remote server), `api.mcp.github.com`, `mcp.svc.cloud.microsoft`. Connections to the Anthropic relay are opaque — you see connection count but not which downstream servers are configured.

**Limitation:** Does not identify which remote servers are behind a relay. To enumerate those, inspect AI client config files (`~/.claude.json`, `%APPDATA%\Claude\claude_desktop_config.json`) via `DeviceFileEvents`.

---

### Strategy 5: Docker-based MCP servers

MCP servers distributed as container images use two patterns:

**stdio via `docker run -i`** — `-i` keeps stdin open for stdio MCP; `--rm` discards after session. Credentials passed as `-e VAR=value` appear in `ProcessCommandLine` in plaintext.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "docker" and ProcessCommandLine has "run" and ProcessCommandLine has " -i"
// AI client filter — update header table when adding new agents
| where InitiatingProcessFileName has_any ("claude", "code", "cursor", "windsurf", "gemini", "codex", "zsh", "bash", "sh")
    or InitiatingProcessCommandLine has_any ("claude", "windsurf", "gemini", "@anthropic-ai/claude-code")
| where not (ProcessCommandLine has_any ("docker stats", "docker ps", "docker inspect",
      "docker logs", "docker images", "docker-cli-plugin-metadata"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

**HTTP via compose** — longer-running MCP servers may run as a compose service rather than ephemeral `docker run`. Hunt `docker compose up` / `compose -f` where the compose file or service name contains "mcp".

**`claude mcp add` registration events** — records exact server registration including transport type. Anchor on `FileName has "claude"` + `ProcessCommandLine has " mcp "` + `has_any ("add", "remove", "list")`.

**Docker network visibility limitation:** All container outbound traffic is attributed to `com.docker.backend` — no per-container network attribution in `DeviceNetworkEvents`.

---

## Identifying the AI client

`has_any` on `InitiatingProcessFileName` with bare names (no `.exe`) matches both platforms:

| Match | Qualifier | Client |
|---|---|---|
| `has "claude"` | None | Claude Desktop or Claude Code |
| `has "code"` | None | VS Code (any AI extension — Copilot, Cline, Continue) |
| `has "cursor"` | None | Cursor IDE |
| `has "windsurf"` | None | Windsurf IDE |
| `has "gemini"` | None | Gemini CLI |
| `has "codex"` | None | OpenAI Codex CLI |
| `has "node"` | `cmdline has "@anthropic-ai/claude-code"` | Claude Code CLI (bare `node` without this qualifier is VS Code's own process) |
| `has_any ("cmd", "bash", "zsh", "sh", "pwsh")` | Check grandparent | Shell launched by AI agent to invoke `npx`/`uvx`; check `InitiatingProcessParentFileName` |

**npx pattern:** `npx -y <package>` (the `-y` auto-install flag) is the standard zero-install pattern. On Windows, `npx` runs inside `cmd.exe` — check the grandparent for the AI client. Pure build tooling uses `npx turbo`, `npx tsc`, etc. without `-y`.

**uv/uvx pattern:** `uv run --directory <path> -m <module>` or `uv tool run <package>`. Match on the module name or script path, not the runner invocation. `uv run` is also used for non-MCP tooling — distinguish by whether the parent is an AI agent vs a build/test shell.

---

## Combining all five strategies

Each strategy has a different denominator and catches different servers:
- **Strategy 1**: process-level, "mcp" in command line
- **Strategy 2**: tool-call level, temp file reads
- **Strategy 3**: longevity heuristic — catches servers with no "mcp" in binary or command line
- **Strategy 4**: remote/HTTP servers with no local process
- **Strategy 5**: Docker-based servers (stdio or HTTP via container)

For a complete inventory, union distinct server identities from all strategies and deduplicate.

---

## Security relevance by server type

| Server type | Risk | Why |
|---|---|---|
| Database MCP | High | Direct AI read/write DB access; scope = DB credentials used |
| Browser control (devtools/Playwright) | Medium–Critical | AI reads DOM, executes JS in browser session; critical if daily-driver profile with live session cookies |
| Project management (Jira/Confluence/etc.) | Medium | AI reads tickets/docs within user's permissions |
| Git/GitHub MCP | Medium | AI can read private repos, potentially push code |
| Code quality/SAST (SonarQube etc.) | Medium | AI reads vulnerability findings; service tokens may appear in `ProcessCommandLine` in plaintext |
| Web search/fetch | Low | Outbound only |
| Security hunting (read-only) | Low–Medium | Reads security telemetry; no write access |
| Docker-containerised (any) | Varies | Container isolation but network is opaque — all traffic attributed to `com.docker.backend` |
