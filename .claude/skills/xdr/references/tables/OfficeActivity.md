# OfficeActivity

## Time column

Uses `TimeGenerated` (not `Timestamp`) — this is a Sentinel/Log Analytics table. Use `run_sentinel_query`.

## Retention

Standard retention is ~90 days. Confirmed earliest record in at least one tenant: 2026-01-16 for a query run on 2026-04-16.

## ClientAppId is unreliable for OAuth app attribution

`ClientAppId` exists as a column but is **unpopulated for most OAuth app activity**, including third-party apps with delegated Graph permissions (e.g. ChatGPT with `Files.Read.All`). Do not rely on `ClientAppId` to prove or rule out file access by a specific OAuth app — absence of hits does not mean no access occurred.

Workaround: correlate by `UserId` + time window aligned to when the OAuth app's Graph API calls were observed in `GraphAPIAuditEvents`.

## Key columns for file access investigation

| Column | Notes |
|---|---|
| `UserId` | UPN of the acting user |
| `Operation` | `FileAccessed`, `FileDownloaded`, `FileModified`, `FileSyncDownloadedFull`, `DLPRuleMatch`, etc. |
| `OfficeWorkload` | `"OneDrive"`, `"SharePoint"` |
| `SourceFileName` | Filename — blank on `DLPRuleMatch` rows |
| `OfficeObjectId` | Full path or GUID depending on operation |
| `SiteUrl` | SharePoint site URL |
| `UserAgent` | Client app string — useful for distinguishing desktop Office, sync client, browser, etc. |
| `FileSizeDownloaded` | Populated on download operations |
| `ClientAppId` | OAuth app GUID — unreliable, often blank |

## DLPRuleMatch rows

`DLPRuleMatch` events have `SourceFileName` blank — file identity is only in `OfficeObjectId` (a GUID). To resolve the filename, join on `OfficeObjectId` to other `OfficeActivity` rows for the same user around the same time.

## Useful filter pattern

```kql
OfficeActivity
| where TimeGenerated > ago(30d)
| where UserId has "user@example.com"
    and OfficeWorkload in ("OneDrive", "SharePoint")
    and Operation in ("FileDownloaded", "FileAccessed", "FileSyncDownloadedFull")
| project TimeGenerated, Operation, SourceFileName, SiteUrl, OfficeObjectId, UserAgent
| order by TimeGenerated asc
```
