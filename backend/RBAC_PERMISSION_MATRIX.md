# RBAC permission matrix

Application roles are `SUPER_ADMIN`, `ADMIN` (Organization Admin), and `SECURITY_ANALYST`. The legacy `CUSTOMER` enum/database assignment is retained only so existing rows can be read; it is not seeded for new installations, assignable at registration, granted as an authority, or supported by user-management workflows. Customer-only accounts cannot authenticate. JWT role and organization claims are not authoritative: current user roles, account status, and organization status are reloaded from the database for each request.

| Capability / endpoint | Anonymous | SUPER_ADMIN | ADMIN | SECURITY_ANALYST | CUSTOMER |
|---|---|---|---|---|---|
| `POST /api/auth/register` as Organization Admin (organization name; no organization ID) | Submit pending application | Submit pending application | Submit pending application | Submit pending application | Submit pending application |
| `POST /api/auth/register` as Security Analyst (approved `organizationName`; no ID or invitation) | Submit pending membership request | Submit pending membership request | Submit pending membership request | Submit pending membership request | Denied |
| Public registration as `SUPER_ADMIN`, legacy `CUSTOMER`, or any unsupported role | Denied | Denied | Denied | Denied | Denied |
| `GET /api/organizations/pending`, `GET /api/organizations/{id}` | Denied | Allowed for registration review | Denied | Denied | Denied |
| Approve/reject initial organization registration | Denied | Allowed | Denied | Denied | Denied |
| `GET /api/organizations/registry` (own approved org and all other approved orgs; metadata only) | Denied | Allowed | Denied | Denied | Denied |
| `DELETE /api/organizations/{id}` (soft-deactivate organization) | Denied | Allowed, except own org or org with active Super Admin | Denied | Denied | Denied |
| `GET /api/organizations/me/dashboard` | Denied | Denied | Own approved organization only | Denied | Denied |
| `GET /api/organizations/me/users`, `/me/users/{userId}` | Denied | Denied | Own approved organization only | Denied | Denied |
| `GET /api/organizations/me/approval-requests` | Denied | Denied | Own pending analyst requests | Denied | Denied |
| Approve/reject organization member through `/me/approval-requests/{userId}` | Denied | Denied | Own eligible analyst only | Denied | Denied |
| Suspend/restore/deactivate `/api/organizations/me/users/{userId}/...` | Denied | Denied | Own eligible analyst only | Denied | Denied |
| `GET /api/organizations/admin-accounts` | Denied | Allowed | Denied | Denied | Denied |
| Suspend/restore/deactivate `/api/organizations/admin-accounts/{userId}/...` | Denied | Eligible Organization Admins only; no self/last-admin action | Denied | Denied | Denied |
| Existing `/api/organizations/{organizationId}/members` and `/membership-requests` | Denied | Denied absent independent exact tenant membership and ADMIN role | Own approved organization only | Denied | Denied |
| `GET /api/users/me` | Denied | Own active profile, roles, account status; nullable org context | Own active profile, roles, account and organization status | Own active profile, roles, account/organization and approved membership status | Denied |
| `GET /api/targets`, `GET /api/targets/{targetId}` | Denied | Denied | Own approved organization targets, including pending/rejected | Own approved targets only | Denied |
| `POST /api/targets` | Denied | Denied | Create a pending target in own approved organization | Denied | Denied |
| `POST /api/targets/{targetId}/decision` | Denied | Denied | Approve/reject a pending target in own organization | Denied | Denied |
| `DELETE /api/targets/{targetId}` | Denied | Denied | Soft-delete a target in own organization | Denied | Denied |
| `/api/scans` operational jobs/findings | Denied | No global bypass | Own approved-organization jobs | Own approved-organization jobs | Denied |

Dashboard and account-management endpoints return display names rather than email addresses. Tenant routes derive the organization from the authenticated principal; service checks repeat the role, account-state, organization-membership, and target-user scope checks. Suspended, disabled, locked, pending, or unapproved-organization identities cannot use existing JWT sessions. Deactivation is soft and preserves account records.

## Current-user profile, organization registry, and deletion

- `GET /api/users/me` returns `UserProfileResponse` fields `id`, `email`, `firstName`, `lastName`, nullable `organizationId`, `organizationName`, `organizationStatus`, sorted supported `roles`, `accountStatus`, and nullable `membershipApprovalStatus`. Organization status and Analyst approval are read from persisted organization/user status. For an active analyst, membership status is `APPROVED`; non-analyst membership status is null. Passwords, hashes, JWTs, and reset tokens are never included. Pending or disabled accounts cannot authenticate to read their profile.

- `GET /api/organizations/registry` requires an authenticated `SUPER_ADMIN` JWT and returns the standard API envelope containing `OrganizationRegistryResponse { ownOrganization, approvedOrganizations }`. Each `OrganizationRegistryItem` has `id`, `name`, `status`, `ownOrganization`, `registeredAt`, `approvedAt`, and `adminDisplayName`. It returns all approved organizations ordered by name, except an approved organization associated with the Super Admin is represented as `ownOrganization`. `ownOrganization` is `null` when the Super Admin has no approved associated organization; pending/rejected/deleted entries are excluded. This registry is organization metadata only and does not grant access to tenant scanner data.
- `DELETE /api/organizations/{id}` requires an authenticated `SUPER_ADMIN` JWT and returns `OrganizationDeletionResponse { id, name, status, deletedAt }` in the standard envelope. It soft-deactivates the organization (`DELETED`), retaining users and historical/audit records. The caller's own organization and organizations with an active Super Admin cannot be deactivated (409); a missing ID returns 404. Role failures return 403 and unauthenticated calls return 401.
- `POST /api/auth/register` accepts `{ firstName, lastName, email, password, role?, organizationName, organizationContactEmail? }`. If `role` is omitted or blank it defaults to `SECURITY_ANALYST`; otherwise only `ADMIN` and `SECURITY_ANALYST` are allowed. For `ADMIN`, `organizationName` creates a pending organization and pending registration Admin; Super Admin approval activates that explicitly associated Admin. For `SECURITY_ANALYST`, the server resolves a unique case-insensitive, trimmed organization name against an `APPROVED` organization and creates a pending membership. Analyst registration needs neither an organization ID nor an invitation token. Unknown, ineligible, or ambiguous names are rejected. Client-supplied IDs, status, approval fields, invitation tokens, and other unknown properties are rejected. Successful registration responds with `{ success, message, data: { email } }`.

`V4__Add_organization_invitations.sql` remains unchanged as historical Flyway migration history. The legacy invitation table is retained but no Java entity, repository, DTO, service, or endpoint uses it. Existing table data is not deleted. `V5__Add_organization_targets.sql` adds persistent targets. `V6__Add_persistent_scan_jobs_and_findings.sql` adds tenant-associated scan job and finding tables. Apply migrations through Flyway; MySQL migration execution was not part of the automated H2 test suite.

## Target API contract

All target endpoints use the standard `ApiResponse` envelope:

- `GET /api/targets` returns `{ success, message, data: Target[] }`. Organization Admins receive all non-deleted targets in their approved organization; Security Analysts receive only approved targets in their approved organization.
- `GET /api/targets/{targetId}` returns one target under the same role/status visibility rules. A cross-organization or otherwise invisible ID returns 404.
- `POST /api/targets` accepts `{ name, url, type }` and returns 201 with a persisted target in `PENDING`. `type` is one of `WEB_APPLICATION`, `API`, `MOBILE`, `NETWORK`, or `OTHER`. Organization identity is derived from the authenticated database user; any client-supplied organization identifier is not used.
- `POST /api/targets/{targetId}/decision` accepts `{ decision }`, where decision is `APPROVE` or `REJECT`. Only pending targets can transition; repeated or invalid transitions return 409.
- `DELETE /api/targets/{targetId}` changes status to `DELETED` and retains the row and its organization relationship. Repeated deletion returns 409.
- Every create, decision, and deletion action writes a tenant-associated audit event. Target URLs must be valid absolute HTTP(S) URLs with a host and without embedded credentials.

These endpoints store and manage target authorization metadata only. Network requests are initiated only by an approved scan job; the worker applies per-request URL, DNS, redirect, response-size, timeout, and same-origin crawl limits. Target approval remains an authorization control, not a substitute for those execution-time SSRF protections.

## Initial scan-job API contract

Every endpoint below uses the standard `ApiResponse` envelope. Only active Organization Admins and Security Analysts in an approved organization can use these routes. The organization is derived from persisted identity; Super Admin has no operational-data bypass.

- `POST /api/scans` accepts `{ "targetId": 12, "scanType": "PASSIVE_HEADERS" }`. The target must be approved and in the caller's organization. Returns 201 with `ScanJobResponse`: `id`, `targetId`, `targetName`, `scanType`, `status`, `progress`, `statusMessage`, `failureReason`, `cancellationRequested`, `createdAt`, `startedAt`, `completedAt`. Caller-supplied tenant, requester, status, and progress are not accepted as DTO fields.
- `GET /api/scans?page=0&size=20` returns a stable Spring Data DTO page (`content` plus page metadata) scoped by organization.
- `GET /api/scans/{scanId}` returns one job from the caller's organization. Missing and cross-tenant IDs both return 404.
- `POST /api/scans/{scanId}/cancel` cancels only jobs not yet started and returns the updated `ScanJobResponse`; unsupported/repeated transitions return 409.
- `GET /api/scans/{scanId}/findings` returns `ScanFindingResponse[]` only after completion; a non-completed scan returns 409 and an actually completed job with no persisted findings returns `[]`. Each finding response includes `id`, `checkType`, `severity`, `affectedComponent`, `evidence`, `rationale`, `remediation`, `detectionSource`, `verificationStatus`, and `detectedAt`.
- `GET /api/scans/{scanId}/crawl-pages` returns `ScanCrawlPageResponse[]` for an accessible scan, including only persisted URL, depth, status code, response byte count, discovered-link count, and discovery timestamp. It never returns response bodies or cross-tenant pages; Organization Admins see organization jobs and Analysts see only their own jobs.

Job records, crawl-page metadata, and finding schema are persisted by Flyway migrations. Job creation enters `PENDING_APPROVAL`; an Organization Admin approval queues the bounded scanner, which records lifecycle progress and findings. `PASSIVE_HEADERS` performs response-header/cookie checks plus conservative GET query-parameter SQLi and reflected-input checks. SQLi findings are `SUSPECTED` and require a clean baseline, differential quote tests, and a database-error signature; reflection findings are `POTENTIAL` and require raw unique-marker reflection in an HTML tag context. No POST/body/form requests, JavaScript execution, data extraction, destructive payloads, or authenticated access-control probing are performed. Execution rejects private, link-local, multicast, and cloud-metadata destinations by default, does not follow redirects, caps response size and crawl/detection requests, and rejects DNS address changes during a scan.
