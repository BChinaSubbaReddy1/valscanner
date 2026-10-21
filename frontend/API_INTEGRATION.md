# API integration

Configure `VITE_API_BASE_URL` with the backend origin; the default is `http://localhost:8080`. Protected requests use the stored bearer token. Responses use the backend `ApiResponse` envelope unless otherwise noted.

## Registration and authentication

| Method | Endpoint | Frontend use and contract |
| --- | --- | --- |
| `POST` | `/api/auth/register` | Public UI permits `ADMIN` and `SECURITY_ANALYST`. Admin sends `{ firstName, lastName, email, password, role, organizationName, organizationContactEmail? }`; the backend creates a pending organization and pending Admin account, defaulting contact email to the registrant. Analyst sends identity fields, role, and `organizationName`; the backend resolves the approved organization by name and creates a pending membership. Response data includes `email`. Neither flow sends an organization ID or invitation token. Backend `AuthService.register` rejects `CUSTOMER`, `SUPER_ADMIN`, and unsupported roles; `RegisterRequest` rejects unknown properties. The backend registration integration test covers CUSTOMER rejection. |
| `POST` | `/api/auth/login` | `{ email, password }`; the frontend then hydrates with `/api/users/me`. |
| `GET` | `/api/users/me` | Authenticated user ID, names, roles, organization ID/name/status, account status, and analyst membership approval status. The analyst workspace re-fetches this profile before showing scanner controls. |
| `POST` | `/api/auth/logout` | Invalidates the bearer token; the frontend clears local state even if the request fails. |
| `POST` | `/api/auth/forgot-password`, `/api/auth/reset-password` | Existing password recovery screens. |

## Super Admin organization management

| Method | Endpoint | Frontend use and contract |
| --- | --- | --- |
| `GET` | `/api/organizations/pending` | Pending registration requests; metadata includes primary contact name. |
| `GET` | `/api/organizations/registry` | Registry metadata only: `ownOrganization` (when approved) and `approvedOrganizations`, with IDs, names, status, registration/approval timestamps, admin display name, and `ownOrganization`. If the authenticated Super Admin profile has an organization ID but the registry omits it, the frontend fetches only `/api/organizations/{id}` metadata. It does not provide scanner resources. |
| `GET` | `/api/organizations/{id}` | Super Admin organization metadata only; the frontend uses the authenticated profile's organization ID only as a fallback for its own registry card. |
| `POST` | `/api/organizations/{id}/approve`, `/reject` | Decide pending requests. Optional body `{ reason }`. |
| `DELETE` | `/api/organizations/{id}` | Soft-deactivate an organization. Optional body `{ reason }`; backend enforces active Super Admin and own-organization restrictions. The frontend hides the action for the returned own organization and displays server errors for other domain restrictions. |
| `GET` | `/api/organizations/admin-accounts` | Pageable Organization Admin accounts with optional `status`; returns display name, role, status, and createdAt, without email. |
| `POST` | `/api/organizations/admin-accounts/{userId}/suspend`, `/restore`, `/deactivate` | Super Admin account lifecycle actions. The frontend submits `{}` after removing reason fields; the current backend requires a nonblank `reason` and will reject these requests until its contract is updated. |

## Organization Admin user management

All user-management requests are self-scoped; the frontend does not provide an organization ID. The backend resolves the authenticated Admin's approved organization.

| Method | Endpoint | Frontend use and contract |
| --- | --- | --- |
| `GET` | `/api/organizations/me/dashboard` | Organization account counts and active analyst count. |
| `GET` | `/api/organizations/me/users` | Pageable user list. Supports `role`, `status`, `search`, `page`, and `size`; response data is a Spring `Page`. The UI requests Security Analysts and does not display email addresses. |
| `GET` | `/api/organizations/me/users/{userId}` | Organization-scoped user details. |
| `GET` | `/api/organizations/me/approval-requests` | Pageable pending analyst/customer requests. The current UI instead uses `/api/organizations/me/users?role=SECURITY_ANALYST&status=PENDING_APPROVAL` for its request list so Customer workflows are not exposed. |
| `POST` | `/api/organizations/me/approval-requests/{userId}/approve`, `/reject` | The frontend submits `{}`. Current backend requires a nonblank reason in `UserAccountActionRequest`, so these actions need a backend contract update to work without a reason. |
| `POST` | `/api/organizations/me/users/{userId}/suspend`, `/restore`, `/deactivate` | The frontend submits `{}`. Current backend requires a nonblank reason in `UserAccountActionRequest`, so these actions need a backend contract update to work without a reason. |

## Target management

| Method | Endpoint | Frontend use and contract |
| --- | --- | --- |
| `GET` | `/api/targets` | Organization-owned targets for Admin; Security Analysts receive only approved targets. |
| `GET` | `/api/targets/{targetId}` | Role- and organization-scoped target detail. |
| `POST` | `/api/targets` | Admin-only create with `{ name, url, type }`; target starts `PENDING`. URL must be HTTP(S) without embedded credentials. |
| `POST` | `/api/targets/{targetId}/decision` | Admin-only `{ decision: "APPROVE" | "REJECT" }`; the optional backend reason is not requested or submitted. Only pending targets can be decided. |
| `DELETE` | `/api/targets/{targetId}` | Admin-only soft deactivation; response status becomes `DELETED`. |

The target screen shows Admin actions for the statuses the backend permits: pending targets can be decided; any non-deleted target can be deactivated. The backend remains authoritative for all access and state transitions.

The organization registry endpoint returns approved organizations and, when applicable, the approved Super Admin organization. Pending registrations are a separate endpoint. No endpoint in the supplied controller returns rejected organization history; after rejection and refresh, rejected records are not available in either list. The frontend does not infer or manufacture a rejected registry.

## Scans, findings, and reports

The Security Analyst workspace uses the following scanner endpoints. The shared API client attaches the stored JWT and sends no client-supplied organization ID; the backend resolves and enforces organization scope.

| Method | Endpoint | Contract and frontend behavior |
| --- | --- | --- |
| `POST` | `/api/scans` | Body `{ targetId, scanType }`. The only supported type is `PASSIVE_HEADERS`. The frontend sends this only for an `APPROVED` target after refreshing the authenticated profile and confirming `accountStatus: ACTIVE`, `membershipApprovalStatus: APPROVED`, and `organizationStatus: APPROVED`. Response contains the persisted job. |
| `GET` | `/api/scans?page={page}&size={size}` | Pageable scan jobs in the authenticated user's organization. The backend currently returns organization history, not only jobs requested by the signed-in user. Active jobs are refreshed every five seconds for a bounded five-minute window; users can explicitly refresh afterward. |
| `GET` | `/api/scans/{scanId}` | Job status/progress/details, including `statusMessage`, `failureReason`, `cancellationRequested`, `createdAt`, `startedAt`, and `completedAt`. The frontend refreshes active jobs every five seconds and renders only returned progress/timestamps. |
| `POST` | `/api/scans/{scanId}/cancel` | Cancellation is permitted by the backend while status is `CREATED`, `QUEUED`, or `RUNNING`. For a running job the backend records `cancellationRequested` and the worker is expected to transition it to a terminal state; the UI offers cancel only while the request remains eligible. |
| `GET` | `/api/scans/{scanId}/findings` | Available only after `COMPLETED`; returns `checkType`, `severity`, `affectedComponent`, `evidence`, `rationale`, `remediation`, `detectionSource`, `verificationStatus`, and `detectedAt`. The details route renders only fields returned by this API. |
| `GET` | `/api/scans/{scanId}/crawl-pages` | Authorized scan access; returns `id`, `url`, `depth`, `statusCode`, `responseBytes`, `discoveredLinks`, and `discoveredAt`. The details route displays these persisted metadata fields and never displays response bodies. |

The supplied backend includes a scan execution service and returns lifecycle metadata on scan jobs. `PASSIVE_HEADERS` execution also performs bounded SQL-injection and reflected-XSS checks automatically for eligible query parameters; the findings API identifies these as `SQL_INJECTION_SUSPECTED` / `REFLECTED_XSS_POTENTIAL` with `ACTIVE_QUERY_PARAMETER` detection source and `SUSPECTED` / `POTENTIAL` verification status. The frontend does not expose separate detector controls because the backend has no separate scan profile for them. No report/export endpoint or CVE field exists, so there is no report/CVE output in the UI.

## Scan approval

The backend exposes organization-scoped scan approval routes:

- `GET /api/scans/pending-approval?page={page}&size={size}`
- `POST /api/scans/{scanId}/approve`
- `POST /api/scans/{scanId}/reject` with `{ "reason": "..." }`

Analyst-created requests return `PENDING_APPROVAL`. The Admin approval page uses only the pending endpoint and refreshes after confirmed decisions. Analysts can view reviewer metadata and rejection reasons returned in `ScanJobResponse`, but cannot approve their own requests.

Organization Admins can also open `/admin/scans/{scanId}` to view organization-scoped scan status and completed-scan findings using the same authorized detail and findings endpoints. The frontend does not expose this route to analysts through Admin navigation, and the backend remains authoritative for tenant authorization.

The supplied backend currently supports only `PASSIVE_HEADERS` in `ScanType`. Crawl persistence, bounded SQL-injection checks, and reflected-XSS checks are part of that execution profile; there is no separate detector profile, report-generation endpoint, export endpoint, or findings-filter endpoint. The frontend does not expose unsupported scan profiles or fabricate reports. Finding severity/type filtering is applied only to findings already returned for the authorized completed scan.

## Role-scoped dashboard aggregates

The frontend consumes these verified dashboard endpoints:

- `GET /api/organizations/platform-dashboard` for `SUPER_ADMIN`, returning organization totals and organization status counts.
- `GET /api/organizations/me/dashboard` for `ADMIN`, returning organization-scoped user, target, scan-status, and severity totals.
- `GET /api/scans/me/dashboard` for `SECURITY_ANALYST`, returning analyst-scoped approved-target, scan-status, crawler-phase, and severity totals.

The backend returns crawler-phase counts (`crawlingScans` and related status aggregates), and crawl results are available through `/api/scans/{scanId}/crawl-pages`. Scan creation still exposes only `PASSIVE_HEADERS`; crawling and active detector checks are internal execution stages rather than selectable frontend profiles.

Several Organization Admin/Super Admin management endpoints still require a nonblank `reason` in backend `UserAccountActionRequest`. The frontend no longer requests or submits reasons as required; requests send an empty JSON object and these endpoints will fail validation until the backend makes those request bodies optional or removes the mandatory constraint. Organization approval/deletion bodies and target-decision reason are optional in the backend and continue to work without reasons.

## Error and verification notes

HTTP errors surface backend messages where available, with fallbacks for 400, 401, 403, 404, 409, and 5xx responses. An authenticated 401 clears the stored session and dispatches a session-expired event. Frontend tests mock APIs for component/request-shape checks; they do not prove live server authorization. Backend MockMvc integration tests validate server contracts and role/scope enforcement separately.

## Manual frontend/backend verification

Use the backend with its configured database and bootstrap Super Admin credentials, then start both applications:

1. Start the backend on `http://localhost:8080` using its configured database/JWT environment. In the frontend root, set `VITE_API_BASE_URL=http://localhost:8080` in `.env`, then run `npm run dev`.
2. Register an Organization Admin with a unique organization name. Sign in as Super Admin, open Organization approvals, approve the new request, and refresh the registry. Verify the approved organization and returned Admin display name come from the API.
3. Sign in as that Organization Admin. Create a target, approve the pending target, and verify it appears with the server-returned status. Confirm the page refreshes from `/api/targets`.
4. Register a Security Analyst using the exact approved organization name (not an ID), then approve the analyst from the Organization Admin user screen. Sign in as the Analyst and verify `/api/users/me` returns `ACTIVE`, `APPROVED`, and approved organization status; the workspace re-fetches this profile and lists the backend-authorized approved targets.
5. Verify role guards by trying the Admin target route as an Analyst and the Super Admin organization route as an Admin. Verify API authorization independently; frontend guards are not the security boundary.
6. For a backend contract check, submit public registration with `role: "CUSTOMER"` and with an unknown field; both should return a client error. The checked-in backend integration test is `RegistrationApprovalTenantIntegrationTest`.
7. On an approved target, start a `PASSIVE_HEADERS` scan and verify the `POST /api/scans` body contains only `targetId` and `scanType`, then inspect the returned job, crawl pages, findings, and history. Verify cancellation while the backend reports `PENDING_APPROVAL`, `CREATED`, `QUEUED`, `CRAWLING`, `SCANNING`, or `RUNNING`, and try a scan ID from another organization to confirm the backend returns not found. The frontend does not claim live execution until this workflow is run against the configured backend. Reports are unsupported.
8. Check management operations without reason fields. Organization approval/deletion and target decisions are optional-reason server contracts; user/admin membership lifecycle endpoints currently reject `{}` because backend validation still requires a reason. They need a backend change and are an explicit blocker.

These steps are a manual procedure, not a claim that live end-to-end testing has been performed.
