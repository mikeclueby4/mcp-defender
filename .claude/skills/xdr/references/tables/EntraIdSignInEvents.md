# EntraIdSignInEvents

Defender-only (`run_hunting_query`). GA replacement for `AADSignInEventsBeta` (deprecated Dec 2025). Covers both interactive and non-interactive user sign-ins in one table.

Uses `Timestamp` (not `TimeGenerated`).

## Column name gotchas — common mistakes

| Wrong (from other tables) | Correct in EntraIdSignInEvents |
|---|---|
| `AppName`, `AppDisplayName` | `Application` |
| `AppId` | `ApplicationId` |
| `CountryCode` | `Country` (full country name string, e.g. `"SE"`) |
| `DeviceId` | `EntraIdDeviceId` |
| `UPN`, `UserPrincipalName` | `AccountUpn` |
| `ObjectId`, `UserId` | `AccountObjectId` |

## Key columns

| Column | Type | Notes |
|---|---|---|
| `AccountUpn` | string | Sign-in identity |
| `Application` | string | App display name |
| `ApplicationId` | string | App GUID |
| `LogonType` | string | JSON array, e.g. `["interactiveUser"]` or `["nonInteractiveUser"]` |
| `IPAddress` | string | Use `ipv6_is_match()` for comparisons |
| `Country` / `State` / `City` | string | Flat geo columns — no parse_json needed |
| `ErrorCode` | int | `0` = success |
| `GatewayJA4` | string | TLS fingerprint; populated when Global Secure Access is deployed |
| `IsSignInThroughGlobalSecureAccess` | bool | Global Secure Access path indicator |
| `EntraIdDeviceId` | string | Device GUID from Entra |
| `DeviceName` | string | Device hostname |
| `DeviceTrustType` | string | e.g. `"Azure AD joined"`, `"Azure AD registered"` |
| `ConditionalAccessPolicies` | string | JSON-encoded — use `parse_json(tostring(...))` |
| `AuthenticationProcessingDetails` | string | JSON-encoded key/value pairs |
| `UniqueTokenId` | string | Token ID for cross-table correlation |
| `ReportId` | string | GUID — globally unique per event |

## Geo columns are flat — no parse_json needed

Unlike `SigninLogs` (Sentinel), geo data is in flat top-level columns, not nested JSON:
```kql
// CORRECT for EntraIdSignInEvents
| project Country, State, City

// WRONG (Sentinel SigninLogs pattern — does not apply here)
| project Country = tostring(parse_json(tostring(LocationDetails)).countryOrRegion)
```

## LogonType filtering

`LogonType` is a JSON array stored as string. Use `contains` not `==`:
```kql
| where LogonType contains "interactiveUser"
| where LogonType contains "nonInteractiveUser"
```

## If empty — fallback to Sentinel

Some tenants have RBAC/routing issues that cause `EntraIdSignInEvents` to return no rows via `run_hunting_query`. If so, use `SigninLogs` + `AADNonInteractiveUserSignInLogs` via `run_sentinel_query` (see `SigninLogs.md` for union gotchas).
