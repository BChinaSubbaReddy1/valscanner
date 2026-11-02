# API integration

Configure `VITE_API_BASE_URL` with the backend origin; the default Compose host port is `http://localhost:8081` (a standalone Spring Boot run defaults to `http://localhost:1080`). Protected requests use the stored bearer token. Responses use the backend `ApiResponse` envelope unless otherwise noted.

## Registration and authentication

| Method | Endpoint | Frontend use and contract |
| --- | --- | --- |
| `POST` | `/api/auth/register` | Public UI permits `ADMIN` and `SECURITY_ANALYST`. Admin sends `{ firstName, lastName, email, password, role, organizationName, organizationContactEmail? }`; the backend creates a pending organization and pending Admin account, defaulting contact email to the registrant. Analyst sends identity fields, role, and `organizationName`; the backend resolves the approved organization by name and creates a pending membership. Response data includes `email`. Neither flow sends an organization ID or invitation token. Backend `AuthService.register` rejects `CUSTOMER`, `SUPER_ADMIN`, and unsupported roles; `RegisterRequest` rejects unknown properties. The backend registration integration test covers CUSTOMER rejection. |
| `POST` | `/api/auth/login` | `{ email, password }`; successful credentials start the existing OTP challenge and do not issue an access token. |
| `POST` | `/api/auth/verify-login-otp`, `/api/auth/resend-login-otp` | Verify or resend the challenge using its challenge token. Only successful OTP verification returns the authenticated access token. |
| `GET` | `/api/users/me` | Authenticated user ID, names, roles, organization ID/name/status, account status, and analyst membership approval status. The analyst workspace re-fetches this profile before showing scanner controls. |
| `POST` | `/api/auth/logout` | Invalidates the bearer token; the frontend clears local state even if the request fails. |
| `POST` | `/api/auth/forgot-password` | Requests or resends a password-reset OTP; the response is account-enumeration neutral. |
| `POST` | `/api/auth/verify-reset-otp` | `{ email, otp }`; returns a short-lived reset capability only after successful OTP verification. |
| `POST` | `/api/auth/reset-password` | `{ token, password }`; the capability is single-use and expires. This flow is separate from login OTP. |

## Super Admin organization management

| Method | Endpoint | Frontend use and contract |
| --- | --- | --- |
| `GET` | `/api/organizations/pending` | Pending registration requests; metadata includes primary contact name. |
| `GET` | `/api/organizations/registry` | Registry metadata only: `ownOrganization` (when approved) and `approvedOrganizations`, with IDs, names, status, registration/approval timestamps, admin display name, and `ownOrganization`. If the authenticated Super Admin profile has an organization ID but the registry omits it, the frontend fetches only `/api/organizations/{id}` metadata. It does not provide scanner resources. |
| `GET` | `/api/organizations/{id}` | Super Admin organization metadata only; the frontend uses the authenticated profile's organization ID only as a fallback for its own registry card. |
| `POST` | `/api/organizations/{id}/approve`, `/reject` | Decide pending requests. Optional body `{ reason }`. |
| `DELETE` | `/api/organizations/{id}` | Soft-deactivate an organization. Optional body `{ reason }`; backend enforces active Super Admin and own-organization restrictions. The frontend hides the action for the returned own organization and displays server errors for other domain restrictions. |
| `GET` | `/api/organizations/admin-accounts` | Pageable Organization Admin accounts with optional `status`; returns display name, role, status, and createdAt, without email. |
| `POST` | `/api/organizations/admin-accounts/{userId}/suspend`, `/restore`, `/deactivate` | Super Admin account lifecycle actions; no reason body is required. |

## Organization Admin user management

All user-management requests are self-scoped; the frontend does not provide an organization ID. The backend resolves the authenticated Admin's approved organization.

| Method | Endpoint | Frontend use and contract |
| --- | --- | --- |
| `GET` | `/api/organizations/me/dashboard` | Organization account counts and active analyst count. |
| `GET` | `/api/organizations/me/users` | Pageable user list. Supports `role`, `status`, `search`, `page`, and `size`; response data is a Spring `Page`. The UI requests Security Analysts and does not display email addresses. |
| `GET` | `/api/organizations/me/users/{userId}` | Organization-scoped user details. |
| `GET` | `/api/organizations/me/approval-requests` | Pageable pending analyst membership requests. |
| `POST` | `/api/organizations/me/approval-requests/{userId}/approve`, `/reject` | Approve or reject an eligible organization analyst; no request body is required. |
| `POST` | `/api/organizations/me/users/{userId}/suspend`, `/restore`, `/deactivate` | Organization Admin account lifecycle actions; no reason body is required. |

## Target management

| Method | Endpoint | Frontend use and contract |
| --- | --- | --- |
| `GET` | `/api/targets` | Organization-owned targets for Admin; Security Analysts receive only approved targets. |
| `GET` | `/api/targets/{targetId}` | Role- and organization-scoped target detail. |
| `POST` | `/api/targets` | Admin-only create with `{ name, url, type }`; target starts `PENDING`. URL must be HTTP(S) without embedded credentials. |
| `POST` | `/api/targets/{targetId}/decision` | Admin-only `{ decision: "APPROVE" | "REJECT" }`; only pending targets can be decided. |
| `DELETE` | `/api/targets/{targetId}` | Admin-only soft deactivation; response status becomes `DELETED`. |
| `GET` | `/api/targets/assignment-analysts` | Admin-only active Security Analysts in the authenticated Admin's organization, returned by display name. |
| `GET` | `/api/targets/{targetId}/assignments` | Admin-only assignment list for an approved organization target. |
| `PUT` | `/api/targets/{targetId}/assignments/{analystId}` | Assigns or reassigns the approved target to an eligible same-organization analyst. |
| `DELETE` | `/api/targets/{targetId}/assignments/{analystId}` | Removes the assignment; backend authorization is revoked immediately. |

The target screen shows Admin actions for the statuses the backend permits: pending targets can be decided; any non-deleted target can be deactivated. The backend remains authoritative for all access and state transitions.
Analyst target lists, scan history, findings, crawl pages, reports, exports, and cross-engine overlap data are restricted to currently approved targets assigned to that analyst.

The organization registry endpoint returns approved organizations and, when applicable, the approved Super Admin organization. Pending registrations are a separate endpoint. No endpoint in the supplied controller returns rejected organization history; after rejection and refresh, rejected records are not available in either list. The frontend does not infer or manufacture a rejected registry.

## Scans, findings, and reports

The Security Analyst workspace uses the following scanner endpoints. The shared API client attaches the stored JWT and sends no client-supplied organization ID; the backend resolves and enforces organization scope.

| Method | Endpoint | Contract and frontend behavior |
| --- | --- | --- |
| `POST` | `/api/scans` | Body `{ targetId, scanType }`; supported types are `PASSIVE_HEADERS`, `ZAP_PASSIVE`, and `ZAP_ACTIVE`. The backend requires an approved target assigned to the authenticated Analyst. |
| `GET` | `/api/scans?page={page}&size={size}` | Admins receive their organization's scan history; Analysts receive history only for their currently assigned approved targets. Active jobs are refreshed every five seconds for a bounded five-minute window. |
| `GET` | `/api/scans/{scanId}` | Job status/progress/details, including `statusMessage`, `failureReason`, `cancellationRequested`, `createdAt`, `startedAt`, and `completedAt`. The frontend refreshes active jobs every five seconds and renders only returned progress/timestamps. |
| `POST` | `/api/scans/{scanId}/cancel` | Cancellation is permitted by the backend while status is `CREATED`, `QUEUED`, or `RUNNING`. For a running job the backend records `cancellationRequested` and the worker is expected to transition it to a terminal state; the UI offers cancel only while the request remains eligible. |
| `GET` | `/api/scans/{scanId}/findings` | Returns authorized scan findings, including check, severity, evidence, source, and verification metadata. Assignment ownership is checked by the backend. |
| `GET` | `/api/scans/{scanId}/crawl-pages` | Returns authorized persisted crawl metadata; response bodies are not exposed. |
| `GET` | `/api/scans/{scanId}/analytics` | Returns authorized link-wise aggregates from persisted findings/crawl pages, supported OWASP mappings, a conservative same-target/same-mode history comparison, and the scan-time ZAP enabled-rule snapshot where available. Partial scans are not treated as clean baselines; enabled rules are not presented as rules proven to have executed. |
| `GET` | `/api/scans/{scanId}/report` | Returns the authorized scan report and finding details, including exact same-scan native/ZAP overlap groups. |
| `GET` | `/api/scans/{scanId}/report/export?format=json\|csv\|pdf` | Exports the same authorized report, including overlap groups and persisted scan analytics. CSV formula-like values are neutralized. |
| `GET` | `/api/scans/{scanId}/correlations` | Returns exact same-scan native/ZAP overlaps by check type and affected component. Overlap is not proof of exploitability or verification. |

The backend runs bounded native checks and configured ZAP stages and returns separate engine states. NVD keyword candidates remain potential findings; candidate metadata is not evidence that a target is affected.

## Scan approval

The backend exposes organization-scoped scan approval routes:

- `GET /api/scans/pending-approval?page={page}&size={size}`
- `POST /api/scans/{scanId}/approve`
- `POST /api/scans/{scanId}/reject` with `{ "reason": "..." }`

Analyst-created requests return `PENDING_APPROVAL`. The Admin approval page uses only the pending endpoint and refreshes after confirmed decisions. Analysts can view reviewer metadata and rejection reasons returned in `ScanJobResponse`, but cannot approve their own requests.

Organization Admins can also open `/admin/scans/{scanId}` to view organization-scoped scan status and completed-scan findings using the same authorized detail and findings endpoints. The frontend does not expose this route to analysts through Admin navigation, and the backend remains authoritative for tenant authorization.

Reports, JSON/CSV/PDF exports, and local finding filters are implemented. The scanner still does not claim complete application coverage; crawl and scan stage counters describe bounded execution only.

## Role-scoped dashboard aggregates

The frontend consumes these verified dashboard endpoints:

- `GET /api/organizations/platform-dashboard` for `SUPER_ADMIN`, returning organization totals and organization status counts.
- `GET /api/organizations/me/dashboard` for `ADMIN`, returning organization-scoped user, target, scan-status, and severity totals.
- `GET /api/scans/me/dashboard` for `SECURITY_ANALYST`, returning analyst-scoped approved-target, scan-status, crawler-phase, and severity totals.
- `GET /api/organizations/platform-dashboard/analytics?days=30` for platform organization-registration history.
- `GET /api/organizations/me/dashboard/analytics?days=30` for organization-scoped daily scan and finding trends.
- `GET /api/scans/me/dashboard/analytics?days=30` for daily scan and finding trends restricted to the Analyst's assigned approved targets.

The dashboard renders backend-provided daily chart points and a corresponding data table; selecting 30 or 90 days changes the server-side query range. Platform, organization, and Analyst analytics use separate authorization scopes.

Organization user/admin lifecycle operations do not require a reason request body. Organization approval/deletion and target decisions retain their existing optional-body contracts.

## Error and verification notes

HTTP errors surface backend messages where available, with fallbacks for 400, 401, 403, 404, 409, and 5xx responses. An authenticated 401 clears the stored session and dispatches a session-expired event. Frontend tests mock APIs for component/request-shape checks; they do not prove live server authorization. Backend MockMvc integration tests validate server contracts and role/scope enforcement separately.

## Manual frontend/backend verification

Use the backend with its configured database and bootstrap Super Admin credentials, then start both applications:

1. Start the backend on `http://localhost:1080` using its configured database/JWT environment. In the frontend root, set `VITE_API_BASE_URL=http://localhost:1080` in `.env`, then run `npm run dev`.
2. Register an Organization Admin with a unique organization name. Sign in as Super Admin, open Organization approvals, approve the new request, and refresh the registry. Verify the approved organization and returned Admin display name come from the API.
3. Sign in as that Organization Admin. Create a target, approve the pending target, and verify it appears with the server-returned status. Confirm the page refreshes from `/api/targets`.
4. Register a Security Analyst using the exact approved organization name (not an ID), then approve the analyst from the Organization Admin user screen. Sign in as the Analyst and verify `/api/users/me` returns `ACTIVE`, `APPROVED`, and approved organization status; the workspace re-fetches this profile and lists the backend-authorized approved targets.
5. Verify role guards by trying the Admin target route as an Analyst and the Super Admin organization route as an Admin. Verify API authorization independently; frontend guards are not the security boundary.
6. For a backend contract check, submit public registration with `role: "CUSTOMER"` and with an unknown field; both should return a client error. The checked-in backend integration test is `RegistrationApprovalTenantIntegrationTest`.
7. Assign an approved target to one Analyst and confirm that a second Analyst cannot access the target or any scan-related route/export by guessing IDs. Inspect report and correlation output, then remove or reassign the target and verify access is revoked immediately.
8. Check management operations without reason fields and verify the backend's scoped approval and lifecycle responses.

These steps are a manual procedure, not a claim that live end-to-end testing has been performed.
