# MCP Server Usage Investigation Playbook

Symptoms that trigger this playbook: "what AI/MCP plugins are people using?", "what local MCP servers are installed?", "is anyone using [tool] with Claude/Copilot?", inventory of AI tool integrations on endpoints.

---

## Four detection strategies — use all four

MCP servers come in two transport flavours: **stdio** (local process, caught by Strategies 1–3) and **remote HTTP/SSE** (no local process, caught only by Strategy 4). Each strategy catches servers the others miss — run all four for a complete inventory.

Strategies 1–3 operate on `DeviceProcessEvents` and only catch stdio servers:

### Strategy 1: Server process command line

Catches the MCP server process itself being launched. Works well for servers installed via `npm`/`npx`, Python packages, or standalone binaries.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "mcp"
    // Exclude common false positives — LSP/language servers that use --stdio
    and not (ProcessCommandLine has_any (
        "eslintServer", "pylance", "prettier", "tsserver", "pyright",
        "vscode-json-languageserver", "html-languageserver", "css-languageserver"
    ))
// AI agent executables — Windows (.exe) and Mac/Linux (no suffix) variants
| where InitiatingProcessFileName in~ (
        // Windows
        "claude.exe", "code.exe", "cursor.exe", "codex.exe",
        "node.exe", "python.exe", "cmd.exe", "bash.exe", "powershell.exe", "pwsh.exe",
        // Mac / Linux (no .exe)
        "claude", "code", "cursor", "codex",
        "node", "python", "python3", "zsh", "bash", "sh",
        // npx / uvx as direct launchers (Mac/Linux — Windows wraps these in cmd.exe)
        "npx", "uvx", "uv"
    )
    or InitiatingProcessCommandLine has_any ("claude", "codex", "cursor", "copilot")
// For shell parents (cmd/bash/zsh/sh/powershell), require AI agent in the command line
// OR in the grandparent — filters out manual terminal usage
| where not (
    InitiatingProcessFileName in~ ("cmd.exe", "bash.exe", "bash", "zsh", "sh",
                                   "powershell.exe", "pwsh.exe")
    and not (InitiatingProcessCommandLine has_any ("claude", "codex", "cursor", "copilot"))
    and not (InitiatingProcessParentFileName in~ (
        "claude.exe", "code.exe", "cursor.exe", "codex.exe",
        "claude", "code", "cursor", "codex", "node.exe", "node"
    ))
)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc
```

**Normalizing noisy command lines into logical server identities** — raw `ProcessCommandLine` explodes on npx cache paths, version strings, etc. Extract a `ServerId` with `case()`:

```kql
| extend ServerId = case(
    ProcessCommandLine has "mcp-oracle-db",          "mcp-oracle-db",
    ProcessCommandLine has "chrome-devtools-mcp",    "chrome-devtools-mcp",
    ProcessCommandLine has "web-utility-belt",        "web-utility-belt",
    ProcessCommandLine has "web_utility_belt",        "web-utility-belt",
    ProcessCommandLine has "@modelcontextprotocol/server-github", "github-mcp",
    ProcessCommandLine has "mcp-atlassian",           "mcp-atlassian",
    ProcessCommandLine has "gitlenses",               "GitLens-mcp",
    ProcessCommandLine has "mcp-xdr",                 "mcp-xdr",
    ProcessCommandLine has "context7-mcp",            "context7-mcp",
    ProcessCommandLine has "mcp-server-git",          "mcp-server-git",
    ProcessCommandLine has "safe_files_mcp",          "safe-files-mcp",
    ProcessCommandLine has "mcp/sonarqube",           "sonarqube-mcp",
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

Some MCP servers (notably **mcp-atlassian** / Jira/Confluence) leave their footprint not in their own process launch, but in the filenames of tool-result temp files that Claude Code writes and subsequent processes (`rg`, `python`, `bash`) read. The server process itself may not contain "mcp" in its command line in a way Strategy 1 catches.

Claude Code writes tool results to paths like:
```
~/.claude/projects/<project-hash>/<session-id>/tool-results/<server>-<tool>-<timestamp>.txt
```

Hunt these by looking for processes reading files matching that pattern:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine matches regex @"tool-results/mcp-[a-zA-Z0-9_-]+-[a-zA-Z0-9_-]+-\d+\.txt"
| extend ServerTool = extract(@"tool-results/(mcp-[a-zA-Z0-9_-]+-[a-zA-Z0-9_-]+)-\d+\.txt", 1, ProcessCommandLine)
| where isnotempty(ServerTool)
| extend Server = extract(@"tool-results/(mcp-[a-zA-Z0-9_-]+)-[a-zA-Z0-9_-]+-\d+\.txt", 1, ProcessCommandLine)
| extend Tool   = extract(@"tool-results/mcp-[a-zA-Z0-9_-]+-([a-zA-Z0-9_-]+)-\d+\.txt", 1, ProcessCommandLine)
| summarize Calls=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
    Users=make_set(InitiatingProcessAccountName, 10), Devices=make_set(DeviceName, 5)
  by Server, Tool
| sort by Calls desc
```

This reliably surfaces Atlassian/Jira, and any other server that follows the same temp-file naming convention.

---

---

### Strategy 3: Long-lived child processes of AI agent executables

MCP servers are persistent — started once, alive for the entire session. Ephemeral tools (shell, compilers, `grep`) exit in seconds and restart many times.

`DeviceProcessEvents` has no process-end time, so longevity is estimated from the spread between `min(ProcessCreationTime)` and `max(ProcessCreationTime)` across all launches. A process seen across many days but restarted rarely has a high **LongevityScore** = `SpanDays / Launches * 100`.

This strategy finds servers whose binary name doesn't contain "mcp" at all — e.g., `uv.exe` running `mcp-server-git`, or opaque binaries like `pet.exe server` or `codanna.exe serve --watch` that are shaped like MCP servers but undetectable by name.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("claude.exe", "code.exe", "cursor.exe")
    or (
        InitiatingProcessFileName =~ "node.exe"
        and InitiatingProcessCommandLine has_any ("claude", "cursor", "codex")
    )
// Exclude OS and editor infrastructure noise
| where FileName !in~ (
    "conhost.exe", "WerFault.exe", "dllhost.exe", "msiexec.exe", "svchost.exe",
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "reg.exe", "sc.exe", "tasklist.exe",
    // VS Code auto-updater, extension verifier, tunnel probe
    "inno_updater.exe", "vsce-sign.exe", "code-tunnel.exe",
    // Language servers (--stdio, not MCP)
    "python.exe"     // filter further by cmdline below
)
// Drop known LSP patterns — python LSP servers use --stdio but aren't MCP
| where not (FileName =~ "python.exe" and ProcessCommandLine has_any ("lsp_server.py", "pylance", "pyright", "server.bundle.js"))
// Drop VS Code auto-updater (CodeSetup-stable-*.exe)
| where FileName !startswith "CodeSetup-stable-"
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

**Interpreting LongevityScore:**

| Score | Interpretation |
|---|---|
| > 200 | Very strong MCP signal — seen across weeks, rarely restarted |
| 50–200 | Likely MCP — persistent across multiple days |
| 10–50 | Ambiguous — could be a moderately long-lived tool or noisy background process |
| < 10 | Likely ephemeral (shell commands, compilers, search tools) |

**Strategy 3 false positives to exclude:**
- `CodeSetup-stable-*.exe` — VS Code updater runs infrequently between releases, scores very high
- `vsce-sign.exe` — extension VSIX verifier
- `inno_updater.exe` — VS Code Inno Setup GC
- `code-tunnel.exe tunnel status` — VS Code tunnel probe
- `python.exe … lsp_server.py --stdio` — Black/Ruff/Pylance LSP (use `--stdio` like MCP, not AI integrations)
- `python3.13.exe -B -I -c "import os; print(os.urandom…"` — VS Code Python extension entropy probe
- `pet.exe server` — **"Python Environment Tools"** daemon bundled inside `ms-python.python` VS Code extension (path: `.vscode/extensions/ms-python.python-*/python-env-tools/bin/pet.exe`). Manages Python environment discovery via named pipe. Not an MCP server despite the identical `server` subcommand shape. `ProcessVersionInfoProductName` = "Python Environment Tools", `FolderPath` contains `.vscode\extensions\ms-python.` — use these to confirm.

---

### Strategy 4: Remote/HTTP MCP servers via outbound network connections

Strategies 1–3 rely entirely on `DeviceProcessEvents` and only catch **stdio MCP servers** (local processes). **Remote MCP servers** (HTTP/SSE transport) run server-side and leave no local process footprint — they are completely invisible to the first three strategies. The only evidence is an outbound HTTPS connection from the AI agent process to a known MCP endpoint.

Known remote MCP endpoints (confirmed in the wild):

| Domain | What it is |
|---|---|
| `mcp-proxy.anthropic.com` | Anthropic's MCP relay — proxies Claude Desktop to *any* remote MCP server the user has configured. A single domain covers many servers. |
| `api.mcp.github.com` | GitHub's hosted MCP server (repo access, code search, etc.) |
| `mcp.deepwiki.com` | DeepWiki — AI-powered documentation for GitHub repos |
| `mcp.jina.ai` | Jina web-utility-belt — web search and fetch |
| `mcp.svc.cloud.microsoft` | Microsoft 365 Copilot remote MCP endpoint |

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("claude.exe", "code.exe", "cursor.exe", "codex.exe")
    or (InitiatingProcessFileName =~ "node.exe"
        and InitiatingProcessCommandLine has_any ("claude", "cursor", "codex", "@anthropic-ai/claude-code"))
| where not (RemoteIP startswith "127." or RemoteIP == "::1")
| where RemotePort == 443
| where isnotempty(RemoteUrl)
// Match any hostname with "mcp" as a label component, plus known relay/proxy patterns
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

**Interpreting results:**

- `mcp-proxy.anthropic.com` connections are opaque — the proxy forwards to whatever remote servers the user has configured in Claude Desktop. Connection count reflects total tool calls across *all* remote MCP servers, not just one.
- `api.mcp.github.com` and `mcp.svc.cloud.microsoft` are point-to-point (one domain = one server).
- New remote MCP servers from unknown providers will appear as novel `*.mcp.*` domains — treat these as worth investigating: who runs the server? what data flows to it?

**Strategy 4 limitation:** Does not identify *which* remote servers are behind `mcp-proxy.anthropic.com`. To enumerate those, you'd need Claude Desktop's local config file (`~/.claude.json` or `%APPDATA%\Claude\claude_desktop_config.json`) via `DeviceFileEvents` or endpoint inventory — out of scope for network-only hunting.

---

## Combining all four strategies

Run all four queries separately — they have different denominators:
- **Strategy 1**: launch counts for processes with "mcp" in command line
- **Strategy 2**: approximate tool-call counts via Claude Code's tool-result temp file reads
- **Strategy 3**: persistent process inventory by longevity heuristic
- **Strategy 4**: remote/HTTP MCP server connections via `DeviceNetworkEvents`

For a definitive inventory, union the distinct server identities from all four and deduplicate. Strategy 3 is the only one that catches MCP servers whose binary name and command line contain no "mcp" string at all. Strategy 4 is the only one that catches remote MCP servers with no local process footprint.

---

## Common false positives in Strategy 1

| Pattern that matches "mcp" | What it actually is |
|---|---|
| `eslintServer.js --stdio` | ESLint language server (LSP), not MCP |
| `pylance`, `pyright` | Python LSP servers |
| `tsserver` | TypeScript language server |
| `prettier` | Code formatter (LSP mode) |
| `vscode-json-languageserver` | VS Code JSON schema LSP |

All use `--stdio` transport like MCP but are not AI tool integrations.

---

## Identifying the AI client

`InitiatingProcessFileName` on the MCP server's process row names the AI client:

| Value | Qualifier needed | Client |
|---|---|---|
| `claude.exe` | None | Claude Desktop or Claude Code (Windows) |
| `code.exe` | None | VS Code with Copilot or Claude extension |
| `cursor.exe` | None | Cursor IDE |
| `node.exe` | `InitiatingProcessCommandLine has "@anthropic-ai/claude-code"` | Claude Code CLI (runs as Node) — bare `node.exe` without this qualifier is VS Code's own extension host or utility process |
| `codex` / `codex.exe` | None | OpenAI Codex CLI |
| `bash.exe` / `cmd.exe` | Check grandparent (`InitiatingProcessParentFileName`) | Shell launched by Claude Code to invoke `npx`/`uvx` commands; grandparent will be `claude.exe` or `node.exe` |

On Mac, look at `InitiatingProcessCommandLine` since executables don't have `.exe`.

### npx as an MCP launcher

`npx -y <package>` is the standard zero-install pattern for npm-based MCP servers. On Windows, `npx` runs as `cmd.exe /d /s /c "npx …"` — the immediate parent of the MCP server process is `cmd.exe`, not `claude.exe`. Check the grandparent (`InitiatingProcessParentFileName`) or use `InitiatingProcessCommandLine has "npx"`.

**Confirmed npx-launched MCP servers seen in the wild:**
```
cmd.exe /d /s /c "npx ^"-y^" ^"@upstash/context7-mcp^""   ← context7 MCP (launched by claude.exe)
```

**Non-MCP npx usage to distinguish:**
```
npx turbo lint / typecheck   ← build tooling, not MCP (parent: bash.exe from dev workflow)
```

The MCP signal: `npx -y <package>` (the `-y` auto-install flag) with `claude.exe` or `code.exe` somewhere in the process ancestry. Pure build tooling uses `npx turbo`, `npx tsc`, etc. without `-y`.

### uv / uvx as an MCP launcher

`uv run --directory <path> -m <module>` and `uv tool run <package>` are the standard patterns for Python-based MCP servers. The same server appears under many command-line variants — match on the **module name** (`-m mcp_xdr.server`, `-m web_utility_belt_mcp`) or script path, not the runner invocation.

**Confirmed uv-launched MCP servers seen in the wild:**
| Command fragment | Server |
|---|---|
| `-m web_utility_belt_mcp` | web-utility-belt (Jina) — MCP web search/fetch |
| `-m mcp_xdr.server` | mcp-xdr — this server |
| `-m mcp_defender.server` | mcp-defender (predecessor to mcp-xdr) |
| `tool run mcp-server-git` | mcp-server-git — git operations |
| `run --no-project … safe_files_mcp.py` | safe_files_mcp — file access control |

`uv run` is also used for non-MCP tooling (`uv run pytest …`, `uv run hook_rag_symbols.py`, etc.) — distinguish by whether the parent is `claude.exe`/`code.exe` vs a shell running build/test commands.

### Docker as an MCP launcher

MCP servers are increasingly distributed as container images. Two distinct patterns:

**Pattern A — `docker run -i` (stdio transport)**

`docker run -i --rm <image>` is the canonical form: `-i` keeps stdin open for stdio MCP communication, `--rm` discards the container after the session. The AI client (`claude`, `code.exe`) registers the server with this as its launch command.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "docker" and ProcessCommandLine has "run"
    and ProcessCommandLine has " -i"
    // Environment variables passed to container are often credentials — capture them
| where InitiatingProcessFileName in~ ("claude", "claude.exe", "zsh", "bash", "bash.exe",
      "code", "code.exe", "cursor", "cursor.exe")
    or InitiatingProcessCommandLine has_any ("claude", "@anthropic-ai/claude-code")
| where not (ProcessCommandLine has_any ("docker stats", "docker ps", "docker inspect",
      "docker logs", "docker images", "docker-cli-plugin-metadata"))
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

**Confirmed `docker run -i` MCP servers seen in the wild:**
| Image | Server | Notes |
|---|---|---|
| `mcp/sonarqube` | SonarQube MCP | Docker Hub `mcp/` namespace — Docker's curated MCP catalog |
| `mcr.microsoft.com/playwright/mcp` | Playwright MCP | Microsoft-published browser automation MCP |

**Credential leakage risk:** `-e SONARQUBE_TOKEN -e SONARQUBE_ORG` — secrets passed as env vars appear in `ProcessCommandLine` in plaintext. This is high-value forensic data.

**Pattern B — `docker compose up` with MCP service**

Longer-running MCP servers may run as a named compose service rather than ephemeral `docker run`. The container name in `ProcessCommandLine` is the signal:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "docker" and ProcessCommandLine has_any ("compose up", "compose -f")
    and ProcessCommandLine has_any ("mcp", "st-mcp", "claude-proxy", "proxy")
| where InitiatingProcessFileName in~ ("claude", "claude.exe", "zsh", "bash", "bash.exe",
      "code", "code.exe") 
    or InitiatingProcessCommandLine has_any ("claude", "@anthropic-ai/claude-code")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| sort by Timestamp desc
```

**Pattern C — `claude mcp add` registration events**

`claude mcp add` commands record exactly what server was registered and how — the clearest possible inventory signal. Catches both stdio and HTTP transport registrations.

**Command line shape:** On Windows the full binary path precedes the subcommand, e.g.:
```
C:\Users\foo\AppData\Local\Programs\Claude\claude.exe mcp add --scope user ...
```
On Mac/Linux:
```
/usr/local/bin/claude mcp add --scope user ...
```
So `FileName` (`claude.exe` / `claude`) is the reliable anchor — anchor on `FileName`, then look for ` mcp ` (space-padded) plus `add`/`remove`/`list` to avoid matching unrelated commands that happen to contain the word "mcp":

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("claude.exe", "claude")
    and ProcessCommandLine has " mcp "
    and ProcessCommandLine has_any ("add", "remove", "list")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| sort by Timestamp desc
```

> **Note:** `ProcessCommandLine` on Windows typically contains the full quoted path + arguments, so `has " mcp "` (space both sides) correctly filters to the `mcp` subcommand and not paths that contain "mcp". On Mac/Linux the binary path itself may contain "mcp" (e.g. `/usr/local/bin/mcp-…`) — if hunting a mixed fleet, add `and ProcessCommandLine has_any ("mcp add", "mcp remove", "mcp list")` as a belt-and-suspenders filter.

**Confirmed `claude mcp add` registrations seen in the wild:**
```
claude mcp add --scope user playwright -- docker run -i --rm --init \
  --add-host=host.docker.internal:host-gateway mcr.microsoft.com/playwright/mcp \
  --headless --no-sandbox
                                    ← Playwright MCP via Docker, stdio transport

claude mcp add --scope user --transport http playwright http://localhost:8931/mcp
                                    ← Playwright MCP via HTTP, container already running on port 8931
```

The `--transport http` variant indicates an HTTP/SSE MCP server running locally (typically in a Docker container with a port mapping). Strategy 4 (network) won't catch this because traffic stays on loopback — Strategy 3 (longevity, port-listening container) or Pattern B (compose) is needed.

**`docker-mcp` CLI plugin**

Docker's official MCP management tool (`docker mcp` / `docker-mcp`). Presence indicates the user is using Docker Hub's curated MCP catalog. The plugin itself only appears as `docker-cli-plugin-metadata` calls (capability discovery from Docker Desktop) — actual server launches go through `docker run -i`.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("docker-mcp", "docker-mcp.exe")
    or (ProcessCommandLine has "docker" and ProcessCommandLine has "mcp "
        and not ProcessCommandLine has "docker-cli-plugin-metadata")
| summarize count(), make_set(InitiatingProcessAccountName, 10), 
    make_set(ProcessCommandLine, 5) by DeviceName
```

**Docker MCP network visibility limitations:**

All container outbound traffic is attributed to `com.docker.backend` (Mac) or the Docker Desktop backend process (Windows) — there is **no per-container network attribution** in `DeviceNetworkEvents`. You can see that *a* container made an outbound connection, but not *which* container. Port-mapped listeners (`-p 8080:8080`) appear as `ConnectionRequest` events from `com.docker.backend` to `0.0.0.0`/`::` — they show what ports are exposed, but inbound connections to those ports are not recorded.

---

## Security relevance by server type

| Server | Risk level | Why |
|---|---|---|
| Database MCP (Oracle, Postgres, etc.) | High | AI has direct read/write database access; scope of data exposure depends on DB credentials used |
| Browser control (chrome-devtools-mcp, Playwright MCP) | Medium | AI can read page DOM, execute JS in browser session, potentially exfiltrate session cookies |
| Jira/Confluence (mcp-atlassian) | Medium | AI reads project data, tickets, docs — scope is the user's Jira permissions |
| Git/GitHub MCP | Medium | AI can read private repos, potentially push code |
| SonarQube MCP (`mcp/sonarqube`) | Medium | AI reads code quality/vulnerability findings; `SONARQUBE_TOKEN` appears in `ProcessCommandLine` in plaintext |
| Web search/fetch | Low | Outbound only; standard internet access |
| Security hunting (mcp-xdr) | Low-Medium | Reads security telemetry; no write access |
| Code graph/analysis | Low | Read-only static analysis |
| Docker-containerised MCP (any) | Varies | Container provides isolation but network activity is opaque — all traffic attributed to `com.docker.backend`, no per-container visibility |

---

## Supplementary hunts

### AI rules files — prompt injection vector

AI coding assistants load instruction files from the project directory (`.cursorrules`, `.github/copilot-instructions.md`, `.claude/CLAUDE.md`, `mcp.json`). Researchers have demonstrated these can be weaponized with hidden Unicode characters or injected via supply chain to cause the AI to generate backdoors or exfiltrate data. Hunt for non-AI processes creating or modifying these files — legitimate writes come from the AI agent itself:

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ (".cursorrules", "copilot-instructions.md", "CLAUDE.md", "mcp.json",
        ".mcp.json", "claude_desktop_config.json")
    or FileName endswith ".cursorrules"
| where ActionType in ("FileCreated", "FileModified")
// Flag writes by processes other than the AI agents themselves
| where InitiatingProcessFileName !in~ (
    "claude.exe", "claude", "code.exe", "code", "cursor.exe", "cursor",
    "codex.exe", "codex", "node.exe", "node"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    FolderPath, FileName, ActionType, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| sort by Timestamp desc
```

**What to look for:** Writes by `git.exe`, `python.exe`, `curl.exe`, `bash`, or other non-AI processes touching these files — potential supply chain injection or malicious repo content. Also look for files created in unexpected locations (e.g., system temp, user downloads) — rules files are expected only in project directories.

---

### MCP credential store access by non-agent processes

Many MCP environments store API keys in plaintext JSON files (`~/.claude.json`, `%APPDATA%\Claude\claude_desktop_config.json`, `~/.config/claude/`). Research has documented these files having insecure world-readable permissions. Hunt for processes *other than* the AI client touching these config files — a potential indicator of credential harvesting by malware or a compromised MCP server:

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (
    ".config/claude", "AppData/Roaming/Claude", "AppData/Local/Claude",
    ".claude", "Library/Application Support/Claude"
)
    and (FileName endswith ".json" or FileName endswith ".env" or FileName == "credentials")
// Only flag reads/opens by unexpected processes
| where ActionType in ("FileRead", "FileAccessed")
| where InitiatingProcessFileName !in~ (
    "claude.exe", "claude", "code.exe", "code", "cursor.exe", "cursor",
    "node.exe", "node", "electron.exe"
)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

**High-signal findings:** Any script interpreter (`python.exe`, `powershell.exe`, `bash`), archiver, or network tool reading MCP config files. This is the credential exfiltration pattern described in research on the `postmark-mcp` malicious server case.

---

### Microsoft 365 Copilot interaction audit (`CloudAppEvents`)

For M365 Copilot (distinct from Claude/Cursor MCP servers — this is Microsoft's own AI assistant), interaction events flow into `CloudAppEvents` when the M365 Defender / Cloud Apps connector is enabled. Useful for AI-use audit and detecting token theft abuse (stolen tokens being used for Copilot data extraction):

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft 365 Copilot"
    and ActionType == "CopilotInteraction"
| summarize
    Interactions = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
  by AccountId, AccountDisplayName, Application
| sort by Interactions desc
```

**Token theft correlation:** Combine with `BehaviorAnalytics` to flag Copilot interactions from a new ISP immediately after a first-time login — characteristic of AiTM phishing token reuse:

```kql
BehaviorAnalytics
| where Timestamp > ago(7d)
| where ActivityType == "LogonAtypical" and InvestigationPriority > 5
| join kind=inner (
    CloudAppEvents
    | where Timestamp > ago(7d)
    | where Application == "Microsoft 365 Copilot" and ActionType == "CopilotInteraction"
) on AccountId
| project Timestamp, AccountId, AccountDisplayName, ActivityType, InvestigationPriority,
    Application, ActionType
| sort by InvestigationPriority desc
```

> **Join note:** `BehaviorAnalytics` is Sentinel-only; `CloudAppEvents` exists in both Defender and Sentinel. Run the join via `run_sentinel_query` — both tables are available there.
