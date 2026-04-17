# AuditLogs

Sentinel table (`run_sentinel_query`). Uses `TimeGenerated`. Covers Entra directory audit events: user/group/app/role changes, PIM activations, authentication validation, and service operations.

---

## Category values for Entra audit

Primary categories for identity/access audits:

| Category | Covers |
|---|---|
| `RoleManagement` | Direct role assignments, PIM eligible/active changes, PIM policy updates |
| `GroupManagement` | Group lifecycle (create/delete/restore), membership changes (add/remove member/owner) |
| `UserManagement` | User creation/deletion/property changes |
| `ApplicationManagement` | App registration, service principal, OAuth permission changes |
| `Authentication` | MFA validation, SSPR, legacy auth events |

---

## RoleManagement — PIM operation name taxonomy (confirmed live)

Every PIM change generates **two** AuditLogs rows with the same `CorrelationId`:
- Row 1: human actor (`InitiatedBy.user.userPrincipalName` populated) — the person who initiated
- Row 2: system completion (`InitiatedBy.app.displayName == "MS-PIM"`, empty UPN) — backend execution

Always de-duplicate when summarizing, or you will double-count every PIM event:

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where Category == "RoleManagement"
| extend Actor = parse_json(tostring(InitiatedBy))
| extend ActorUPN = tostring(Actor.user.userPrincipalName)
| extend ActorApp = tostring(Actor.app.displayName)
| extend ActorLabel = iff(ActorUPN != "", ActorUPN, iff(ActorApp != "", ActorApp, "System"))
// De-duplicate: keep the human-actor row when both exist for the same correlation
| summarize arg_min(iff(ActorUPN != "", 0, 1), *) by CorrelationId
```

Confirmed `OperationName` values under `Category == "RoleManagement"`:

| OperationName | Meaning |
|---|---|
| `Add eligible member to role in PIM completed` | PIM eligible assignment added (system row) |
| `Remove eligible member from role in PIM completed` | PIM eligible assignment removed (system row) |
| `Add member to role completed` | Direct (active/permanent) role assignment added |
| `Remove member from role completed` | Direct (active/permanent) role assignment removed |
| `Add member to role in PIM completed` | PIM time-bounded activation completed |
| `Remove member from role in PIM completed` | PIM activation removed or expired |
| `Update role setting in PIM` | PIM role policy changed (MFA requirement, max duration, etc.) |
| `Add role assignment to role definition` | Role assigned at management-plane level |
| `Remove role assignment from role definition` | Role removed at management-plane level |

The human-initiated row has a non-empty `userPrincipalName`; the paired system row has `ActorApp == "MS-PIM"`.

**Permanently assigned roles do not generate PIM audit events** — no activate/deactivate entries will appear. If `AuditLogs` shows no PIM events for a user but their roles are visible elsewhere, the role is permanently (not eligible) assigned.

---

## GroupManagement — use an allowed-ops whitelist

`Category == "GroupManagement"` + `has_any("group","member")` without a whitelist captures large volumes of read/OData noise (e.g. `GroupsODataV4_Get`, `Settings_GetSettingsAsync`). In a moderately active tenant, a 7-day window returns ~1,860 rows of which ~1,550 are system reads. Use an explicit allowlist:

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in (
    "Add member to group", "Remove member from group",
    "Add owner to group",  "Remove owner from group",
    "Add group", "Delete group", "Hard Delete group",
    "Restore Group", "Update group"
)
| where Result =~ "success"
```

---

## Role-assignable groups: membership changes appear as GroupManagement, NOT RoleManagement

When role access is granted through a role-assignable group (common PIM/JIT hardening pattern), the audit event is `Category == "GroupManagement"` / `OperationName == "Add member to group"` — there is **no** corresponding `RoleManagement` event. A complete Entra ID role audit requires both queries:

1. `Category == "RoleManagement"` — direct assignments and PIM eligible/active changes
2. Group membership allowlist above — for group-based role grants

Cross-reference the group `displayName` against known role-assignable group naming conventions (e.g. `PAG-T*`, `PAM-*`) to identify which membership changes represent effective role changes.

---

## Parsing InitiatedBy and TargetResources

Both columns are JSON blobs stored as strings — parse before access:

```kql
// Actor
| extend Actor    = parse_json(tostring(InitiatedBy))
| extend ActorUPN = tostring(Actor.user.userPrincipalName)   // null for SP actors
| extend ActorApp = tostring(Actor.app.displayName)           // populated for SP/PIM actors

// Target — JSON array of typed objects
| extend TargetList = parse_json(tostring(TargetResources))
| mv-expand Target = TargetList
| extend TargetType        = tostring(Target.type)            // "Group", "User", "ServicePrincipal", "Role"
| extend TargetDisplayName = tostring(Target.displayName)
| extend TargetUPN         = tostring(Target.userPrincipalName)  // populated for User targets
```

For member-add/remove events: the `"Group"` object carries the group name; the `"User"` or `"ServicePrincipal"` object carries the member's UPN/displayName.

**The `roles` array inside `InitiatedBy`/`TargetResources`** reflects roles used to *authorize that specific audit operation*, not the user's complete role assignments. It is routinely empty (`[]`) even for users with assigned roles.

---

## Searching by target user

`TargetResources` is a JSON array string — use `has` for substring matching rather than parsing when you only need to filter:

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where TargetResources has "user@example.com" or InitiatedBy has "user@example.com"
```

---

## PIM role activation operation names (quick filter reference)

```kql
AuditLogs
| where OperationName in (
    "Add member to role in PIM completed",
    "Add eligible member to role in PIM completed",
    "Remove member from role in PIM completed",
    "Remove eligible member from role in PIM completed",
    "Add member to role completed"
)
```
