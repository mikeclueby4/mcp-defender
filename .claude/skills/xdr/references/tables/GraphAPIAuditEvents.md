# GraphAPIAuditEvents — Table Notes

## Column types (per official docs)

**`ApplicationId`** — type `string` (GUID), not int. Filter directly by GUID string:
```kql
| where ApplicationId == "e0476654-c1d5-430b-ab80-70cbd947616a"
```

**`ResponseStatusCode`** — type `string` per official docs. Wrap with `toint()` for numeric comparisons:
```kql
| where toint(ResponseStatusCode) >= 400
| summarize Errors=countif(toint(ResponseStatusCode) >= 400)
```

**`RequestDuration`** — type `string` containing millisecond values (docs say "milliseconds"; empirically may be microseconds — verify with `tolong()` and sanity-check against expected latency). Wrap with `tolong()` before math:
```kql
| summarize AvgMs=round(avg(tolong(RequestDuration)), 1)
```

## Column sizes

**`RequestUri`** — contains full URLs including Graph delta continuation tokens, which can be several kilobytes each. A handful of rows can push past the 10 KB inline result threshold.

Extract just the path for summarization:
```kql
| extend Path = tostring(parse_url(RequestUri).Path)
```

Or drop it entirely when it's not needed:
```kql
| project-away RequestUri
```

## Key hunting columns

`ApplicationId`, `RequestMethod`, `ResponseStatusCode`, `RequestUri` (or its extracted `Path`), `Scopes`, `IpAddress`, `TargetWorkload`, `RequestDuration`, `ApiVersion`

`ServicePrincipalId` is present but often empty for app-only calls; use `ApplicationId` as the stable app identity.

## No `OAuthAppId` column

The table does **not** have an `OAuthAppId` column — it uses `ApplicationId` (int). You cannot directly filter by the GUID from `OAuthAppInfo`. To hunt by OAuth app GUID, resolve the integer `ApplicationId` first via a separate `OAuthAppInfo` query, then use that integer here.

## No `AccountUpn` column

User identity is `ServicePrincipalId` + `AccountObjectId` — there is no `AccountUpn`. To resolve to a UPN, cross-reference with `SigninLogs` on `AppId`.

## OfficeActivity.ClientAppId does not reliably record OAuth app calls

When pivoting from `GraphAPIAuditEvents` to `OfficeActivity` to find which files were accessed by a specific OAuth app: `OfficeActivity.ClientAppId` is **unpopulated for most OAuth app file access** — Microsoft does not consistently write the OAuth app GUID into SharePoint/OneDrive audit records. A zero-row result on `ClientAppId == "<guid>"` does NOT prove no files were accessed. Fall back to correlating by `UserId` + time window.
