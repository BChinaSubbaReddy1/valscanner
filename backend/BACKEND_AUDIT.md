# Backend audit and implementation report

## Scope inspected

The workspace contains a Spring Boot 3.3.5 / Java 21 Maven backend with JWT authentication, registration and approval, organizations, user/role persistence, audit-event persistence, and bounded scan execution. Password-reset endpoints are unavailable until a real delivery integration exists. Organization-scoped targets, approval-gated scan jobs, passive checks, findings, same-origin crawl-page discovery, report endpoints, and JSON/CSV/PDF exports are implemented. Native active checks and schedules are not implemented; explicit `ZAP_ACTIVE` requests use the scoped ZAP integration. There is no separate `TargetUrlValidator`; target URL syntax validation is currently implemented in `TargetService`, while execution-time scheme, credential, DNS, and network-address checks are enforced by `ScanExecutionService`. The audit and changes apply only to the backend present here.

## Existing registration and security behavior

- Public registration allow-lists `ADMIN` and `SECURITY_ANALYST`; `SUPER_ADMIN` and `CUSTOMER` cannot be requested publicly.
- Organization Admin registration already accepts an organization name without an ID. It creates a pending organization and pending admin together, then stores an explicit registration-admin association. Supplying an organization ID with this role is rejected.
- A Super Admin approves/rejects the pending organization. Approval activates only the explicitly associated pending registration admin; rejection disables that account. No name match grants ownership of an existing organization.
- Security Analyst registration accepts an organization name, resolves it using a case-insensitive trimmed database query, rejects unknown/unapproved/ambiguous results, and remains pending until an Admin in that same persisted organization approves it.
- Public registration permits only `ADMIN` and `SECURITY_ANALYST`. Client organization IDs, invitation tokens, approval state, and unsupported fields are rejected. The Super Admin remains available only through the protected bootstrap mechanism.
- Invitation endpoints and Java invitation models/services have been removed. V4 is retained unchanged as historical Flyway migration and its table/data are left intact but unused.
- `CUSTOMER` is no longer seeded or accepted by public registration. The enum value remains solely for reading legacy role rows; Customer-only accounts cannot authenticate, and their assignments are not returned by Analyst-specific management/approval APIs.
- Method security protects the platform and organization endpoints; organization service checks also compare the authenticated admin's persisted organization to the requested tenant.
- The JWT filter reloads the user and roles from the database on every request. Only active users in an approved organization are enabled, so non-active accounts and suspended organizations cannot use existing JWT sessions.
- Existing Super Admin bootstrap is a platform-only identity without a synthetic organization. Password reset is unavailable until a delivery mechanism is implemented and does not issue tokens.

## Findings and changes in this implementation

| Area | Finding | Change |
|---|---|---|
| Dashboard | No organization-scoped user statistics existed, and active crawler states were not represented. | Added database-count dashboard endpoints; tenant identity is derived from the authenticated principal, and `CRAWLING`/`SCANNING` are reported separately. |
| User management | Only unpaginated member and analyst-request routes existed. | Added tenant-scoped user list/detail and paginated approval-request APIs, with role/status filters and name search. |
| Dashboard privacy | Membership response exposed email and had no display name. | Dashboard/user/approval/admin-account DTOs return display names and do not include email or authentication data. |
| Approval | Organization Admins required an invitation-based Analyst workflow and also supported legacy Customers. | Analysts now register by approved organization name and stay pending; approval queries and service checks permit only same-tenant Security Analysts and prevent self-approval. |
| Suspension | Account status had no distinct restorable suspended state. | Added `SUSPENDED`; authentication and JWT filter continue to allow only `ACTIVE`. State changes are audited without requiring a user-entered reason. |
| Deactivation | Physical deletion could break audit/history foreign keys. | Added soft deactivation (`DISABLED`), retaining the account and relationships; it cannot be restored through the suspension endpoint. |
| Admin lifecycle | Super Admins had no scoped API to manage organization-admin accounts. | Added a Super Admin-only account list and suspend/restore/deactivate operations, with a last-active-admin guard. No scanner-data access is implied. |
| Query cost | Organization and role-based user queries lacked combined indexes. | Flyway V3 adds indexes on `(organization_id, status)` and `(role_id, user_id)`. |
| Target management | No persistent target entity, API, tenant checks, lifecycle, or audit events existed. | Added organization-scoped target CRUD/approval with persisted state, analyst approved-target visibility, URL syntax validation, audit events, and Flyway V5. Target deletion is soft. |
| Scan-job management | Persistent jobs existed, but creation did not execute a scan. | Added pending approval, reviewer/reason persistence, tenant-scoped approval endpoints, post-commit bounded worker submission, duplicate-claim protection, execution-time approval/tenant revalidation, bounded HTTP retrieval with redirect and private-network controls, target-origin breadth-first crawling (depth 2/request budget 10), HTML-only crawl-page persistence, passive header/cookie/disclosure checks, evidence-backed findings, failure handling, and cancellation. Flyway V7 and V8 extend the existing schema. |

## API and authorization

Organization Admin APIs derive organization identity from the current authenticated user; their routes accept no organization ID:

- `GET /api/organizations/me/dashboard`
- `GET /api/organizations/me/users?role=&status=&search=&page=&size=`
- `GET /api/organizations/me/users/{userId}`
- `GET /api/organizations/me/approval-requests?page=&size=`
- `POST /api/organizations/me/approval-requests/{userId}/approve`
- `POST /api/organizations/me/approval-requests/{userId}/reject`
- `POST /api/organizations/me/users/{userId}/suspend`
- `POST /api/organizations/me/users/{userId}/restore`
- `POST /api/organizations/me/users/{userId}/deactivate` (soft deactivation)

Target management is under `/api/targets`: admins list, create, decide, and soft-delete targets within their approved organization; analysts list/read only approved targets in their own approved organization. The request/response fields and status transitions are specified in `RBAC_PERMISSION_MATRIX.md`.

Approval, suspension, restoration, and deactivation actions require no request body. Organization Admins may approve/manage only `SECURITY_ANALYST` users in their own approved organization; they cannot manage themselves, Super Admins, or Organization Admin accounts. Legacy `CUSTOMER` accounts are not part of these workflows. Audit events retain actor, action, target, organization, and timestamp without user-entered decision text.

Super Admin-only Organization Admin account endpoints:

- `GET /api/organizations/admin-accounts?status=&page=&size=`
- `POST /api/organizations/admin-accounts/{userId}/suspend`
- `POST /api/organizations/admin-accounts/{userId}/restore`
- `POST /api/organizations/admin-accounts/{userId}/deactivate` (soft deactivation)

These account endpoints do not grant scanner-data access. A Super Admin cannot manage their own account through them or suspend/deactivate the last active Organization Admin in an organization. Existing organization-registration review endpoints remain under `/api/organizations/{id}` and retain the Super Admin-only policy.

Scan-job endpoints under `/api/scans` allow active Organization Admins and Security Analysts in an approved organization to create requests for approved targets. Requests start at `PENDING_APPROVAL`; only a same-organization Organization Admin can approve or reject them. Analysts can list/read/cancel only their own requests; admins can list/read/cancel their organization’s requests and review pending requests. Super Admins have no scanner operational-data or approval access. Successful approval commits `QUEUED` state before post-commit executor submission. The pipeline is `PASSIVE_HEADERS`; execution progresses through `CRAWLING` and `SCANNING`, performs at most 10 bounded same-origin requests to depth 2, never follows redirects, and defaults to rejecting private or metadata-network destinations.

## Statistics and privacy definitions

- `totalUsers`: all user accounts associated with the approved organization.
- `approvedUsers`: accounts with status `ACTIVE`.
- `pendingApprovalRequests`: `SECURITY_ANALYST` accounts with status `PENDING_APPROVAL`.
- `suspendedUsers`: accounts with status `SUSPENDED`; rejected/deactivated `DISABLED` accounts are not counted as suspended.
- `activeSecurityAnalysts`: `SECURITY_ANALYST` accounts with status `ACTIVE`.

User dashboard, approval, and account-management responses use a display name derived from existing first/last name fields and omit email. Existing authentication and explicitly authorized Super Admin organization-registration review data remain unchanged.

## Database and data integrity

Flyway V3 adds only query indexes; the `SUSPENDED` value is stored in the existing string-backed status column and requires no column change. V4 remains unchanged, including its legacy invitation table; no existing invitation rows or Customer users/role rows are deleted. V5 adds target persistence; V6 adds scan-job and finding tables with tenant/target/requester foreign keys. User deletion is soft, preserving user-role, organization, audit, and historical-record references. No MySQL production/staging database was modified.

V2 remains the schema change for initial admin registration association. Analyst registration requires no schema change because `users.organization_id` already stores the explicit association. Review legacy organization/user mappings before deploying migrations; no organization owner is inferred from a matching name.

## Verification

- `mvn compile` passed: Java 21 compilation completed successfully.
- `mvn test` passed: 38 tests across six test classes, 0 failures, 0 errors, 0 skipped.
- `ScanExecutionServiceTest` includes controlled local-fixture positive and negative SQLi/reflection cases plus active-request budget enforcement.
- `ScanManagementIntegrationTest.crawlPagesAreReturnedOnlyForAnAuthorizedScan` verifies same-tenant retrieval and cross-tenant 404 behavior for crawl metadata.
- Focused registration, organization-management, and target-management tests passed before the full-suite runs.
- Tests use H2 with Flyway disabled. MySQL 8 Flyway migration execution/schema validation was not performed because the Docker engine was unavailable and no isolated MySQL test database was confirmed.

Phase 6A validation also confirmed by static inspection that V1-V8 are ordered and
that entity mappings for `scan_jobs`, `scan_findings`, and `scan_crawl_pages` match
the migration columns, foreign keys, and indexes. No live `flyway_schema_history`
or MySQL schema was available to inspect, and no migration repair or database
mutation was performed.

## Remaining scope and risks

- Persistent tenant-scoped scan requests, analyst-owned access, organization-admin approval/rejection, post-commit queueing, cancellation, findings storage/retrieval, bounded passive execution, same-origin endpoint discovery, authorized crawl-page retrieval, and report exports are implemented. `PASSIVE_HEADERS` makes passive requests only. `ZAP_ACTIVE` is the only active scan type and requires an available, origin-scoped ZAP service; there is no native active fallback for it. POST-body and authenticated-test-account coverage, browser execution, robots policy, and schedules are not implemented.

## Phase capability status

| Capability | Status | Evidence / limitation |
|---|---|---|
| Authentication and current-user JWT revalidation | VERIFIED | JWT signature/expiry/blacklist plus database status, role, and organization reload |
| Tenant-scoped targets, scans, findings, and crawl pages | VERIFIED | Service-level organization/requester predicates; `/api/scans/{scanId}/crawl-pages` returns persisted metadata only after the same access check |
| Passive response-header and cookie checks | VERIFIED | Bounded worker tests controlled responses and persists evidence-backed findings; each `Set-Cookie` is parsed independently, values are redacted, and missing attributes are `OBSERVED` rather than verified exploitability |
| Same-origin crawler and SSRF controls | VERIFIED | Depth/request/response/time limits, redirects disabled, target-origin scheme/host/effective-port comparison, address restrictions, DNS-set pinning, fragment normalization, HTML-only crawl-page records, and cancellation |
| Dashboard aggregates | VERIFIED | Organization and analyst counts use persisted tenant-scoped repository queries; platform dashboard exposes organization metadata counts only |
| SQL injection detection | PARTIAL | Native passive mode does not probe parameters. Active vulnerability requests are delegated to explicitly selected `ZAP_ACTIVE` and are restricted to the temporary same-origin context and configured scan/time budgets. Native bounded SQLi differential probes are not active in the current worker route; applicability and false negatives remain ZAP-dependent. |
| Reflected XSS detection | PARTIAL | `PASSIVE_HEADERS` does not submit test strings. `ZAP_ACTIVE` delegates active detection to scoped ZAP; ZAP alerts are mapped to potential/observed/verified according to reported confidence, with sanitized evidence. No browser execution is performed by the native scanner. |
| Access-control vulnerability probing | MISSING | Existing RBAC tests verify this backend's authorization, but the scanner does not probe target applications with test accounts |
| Reports and JSON/CSV/PDF exports | PARTIAL | Existing persisted findings are exported; CSV formula-leading fields are neutralized and one-page PDF exports report the omitted count. Schedules are not implemented. |

Native POST/form coverage, authenticated test accounts, browser execution, and access-control probing remain unsupported; they require explicit target request models and authorization workflows to avoid unsafe requests and false positives.

## Phase 6A security configuration result

- JWT and database credentials are environment-only in application defaults.
- Docker Compose fails fast when `DB_PASSWORD` or `JWT_SECRET` is not supplied.
- Bootstrap Super Admin credentials are blank by default and are never generated from
  a known password.
- Token issuance, validation, and blacklist handling use the single `JwtService`
  implementation; the duplicate `JwtTokenService` has been removed.
- Test-only JWT/H2 credentials remain in the test profile and are not production
  configuration.

## Phase 6C live MySQL and startup validation

### Environment

- Docker CLI is installed (`29.8.2`), but the Docker Desktop Linux daemon is not
  running. The attempted `docker version` command failed to connect to
  `dockerDesktopLinuxEngine`.
- No production, staging, or existing `scanner` database was contacted.
- No `.env` file, real secret, database, migration history, or table was created
  or modified.

### Static configuration result

- `application.properties` uses the MySQL driver, Flyway, and
  `hibernate.ddl-auto=validate`.
- Database username/password and JWT secret are environment-backed with blank
  application defaults.
- Docker Compose requires `DB_PASSWORD` and `JWT_SECRET`; it does not use known
  fallback credentials.
- Optional bootstrap administrator credentials are blank by default.
- V1 through V8 are present once each and are ordered sequentially.
- Static entity/migration review found matching scan-job, finding, crawl-page,
  target, organization, and user foreign keys and indexes.

### Runtime result

The following could not be verified because no isolated MySQL 8 server was
available:

- MySQL version and connection.
- `flyway_schema_history` rows.
- Applying V1 through V8 to a clean MySQL schema.
- Hibernate validation against MySQL.
- Spring Boot startup and listening port.
- Live API health, authentication, scan persistence, restart persistence, and
  MySQL-backed tenant authorization.

No migration repair or schema correction is indicated by the available evidence.
If Docker is started, use a separately named validation database/container and
inspect the migration history before considering any repair action.

### Phase 6C completion attempt

At the follow-up validation attempt, `docker version` was executed again. The
Docker CLI reported version `29.8.2`, but the Docker Desktop Linux engine was
still unavailable:

```text
failed to connect to the docker API at
npipe:////./pipe/dockerDesktopLinuxEngine
```

Per the runtime safety requirements, validation stopped at the environment
check. No validation database was created, no MySQL server was contacted, and
no application runtime process was started with temporary credentials.

Phase 6C status: **BLOCKED**. The H2 compile/test results remain valid but do not
constitute MySQL, Flyway, Hibernate-runtime, startup, restart-persistence, or
live tenant-isolation evidence.

### Phase 6C successful isolated-runtime validation

The later validation run used Docker Desktop's Linux engine and a disposable
container named `vulnscanner-mysql-validation-6c`. It did not connect to or
modify the existing `scanner` database.

| Check | Status | Evidence |
|---|---|---|
| Docker/MySQL environment | VERIFIED | `docker version` succeeded; `mysql:8.0` reported MySQL `8.0.46` on host port `13306` |
| Clean Flyway sequence | VERIFIED | The isolated database recorded successful versions `1` through `8` in `flyway_schema_history` |
| Hibernate schema validation | VERIFIED | Spring Boot started with `spring.jpa.hibernate.ddl-auto=validate` against the migrated MySQL schema |
| Backend startup and health | VERIFIED | Spring Boot listened on port `18080`; `GET /actuator/health` returned `{"status":"UP"}` |
| Authentication | VERIFIED | A temporary bootstrap Super Admin authenticated through `POST /api/auth/login`; credentials were not included in this report |
| Approval workflow | VERIFIED | A temporary organization, Organization Admin, analyst, approved target, and approved scan were created through supported APIs |
| Bounded live scan | VERIFIED | The authorized local `HttpListener` fixture completed scan `1` with status `COMPLETED`, six persisted findings, and two persisted crawl pages |
| MySQL persistence | VERIFIED | Direct MySQL queries returned `scan_jobs=1`, `scan_findings=6`, and `scan_crawl_pages=2`; foreign keys and indexes remained present |
| Restart persistence | VERIFIED | After stopping and starting Spring Boot against the same database, scan `1` remained `COMPLETED` and returned six findings and two crawl pages |
| Cross-tenant access | VERIFIED | A separate approved tenant's authenticated admin received non-success responses when requesting scan `1`, its findings, and crawl pages; no records were disclosed |

Sanitized commands executed included `docker version`, `docker run mysql:8.0`,
`docker exec ... mysqladmin ping`, `docker exec ... mysql`, `mvn spring-boot:run`,
and HTTP requests to the documented authentication, organization, target, scan,
findings, crawl-page, and health endpoints. Temporary secrets were supplied
through process environment variables and were not printed. No `flyway repair`,
database drop, migration deletion, or production/staging connection was used.

This successful run supersedes the earlier environment-only `BLOCKED` attempts
for the checks listed above. The live scan used a local fixture and therefore
does not establish coverage against arbitrary external applications.

### Latest LocalHost timeout investigation

The currently running backend returned `200` from `GET /actuator/health`, and
the authenticated frontend session loaded successfully. The analyst workspace
showed the approved target as `http://[::1]:5173/`. Existing LocalHost scan
records consistently show:

- progress `10%`;
- status `FAILED`;
- failure reason `TIME_BUDGET_EXCEEDED`;
- status message `Target request timed out`;
- no persisted crawl pages or findings.

The source path confirms that this failure is produced when the initial
`HttpClient` request exceeds the configured `scanner.request-timeout-seconds`
value (15 seconds), before the crawler can persist a page. There is no separate
whole-scan deadline in the worker. A direct reachability check performed during
this investigation returned HTTP `200` for both
`http://127.0.0.1:5173/` and `http://[::1]:5173/`, so the historical timeout
cause is not conclusively isolated to the current fixture. The target's IPv6
address and the prior IPv4/IPv6 binding differences remain a plausible
environmental cause, not a confirmed application defect.

The current authenticated account is a `SECURITY_ANALYST`; it created a
validation scan through the supported UI, but organization-admin approval is
required before execution. That pending request was cancelled through the
supported endpoint. No source code or database schema changes were made for
this investigation. Current status: **NOT VERIFIED** for a new end-to-end
LocalHost execution, final persistence, restart persistence, and timeout root
cause. The prior isolated MySQL validation above remains the verified runtime
evidence.

### Authenticated OWASP runtime evidence

A second disposable analyst account for the OWASP organization authenticated
successfully through the login UI. The protected workspace loaded and returned
the existing approved target `https://owasp.org/projects/juice-shop`. The
latest persisted scan (scan `25`) was inspected through the supported scan
details page:

| Check | Status | Evidence |
|---|---|---|
| Login and protected route | VERIFIED | Login succeeded; the workspace loaded as `SECURITY_ANALYST` in organization `OWASP` |
| Persisted scan lifecycle | VERIFIED | Scan `25` was `COMPLETED` with progress `100%` |
| Persisted findings | VERIFIED | Two findings were returned: `COOKIE_MISSING_HTTP_ONLY` and `COOKIE_MISSING_SECURE` |
| Cookie classification | VERIFIED | Both findings were `OBSERVED`, with cookie name and attributes only; no cookie value was exposed |
| Persisted crawl pages | VERIFIED | Six HTML pages were returned with HTTP 200, depths 0/1, response sizes, and discovered-link counts |
| Target scope | VERIFIED | All six recorded URLs use the configured `https://owasp.org` origin |
| New LocalHost execution | NOT VERIFIED | The OWASP analyst account could not approve the separate LocalHost scan; the pending request was cancelled |

The inspected target is an OWASP project information page, not evidence that a
running Juice Shop application was scanned. The scan records are real
persisted results and were not fabricated by the frontend.

The final regression commands for this continuation were:

- `mvn compile`: **VERIFIED**, `BUILD SUCCESS`.
- `mvn test`: **VERIFIED**, 39 tests run, 0 failures, 0 errors, 0 skipped,
  `BUILD SUCCESS`.

## Active detector limits

- `PASSIVE_HEADERS` does not submit SQLi/XSS payloads.
- The explicit `ZAP_ACTIVE` route runs native bounded GET-parameter probes and ZAP active scan; `ZAP_PASSIVE` only spiders and imports passive alerts.
- `scanner.max-requests` controls the native crawler budget (default 10); `scanner.max-detection-requests` limits native active probes (default 6); `scanner.request-timeout-seconds` (default 15) is an explicit full-response deadline with a 1 MiB response cap.
- At most three non-sensitive query parameters are considered per crawled URL. Password, secret, token, session, cookie, auth, and key-like parameter names are skipped.
- Each eligible parameter receives two quote-based SQL checks and one unique-marker reflection check. Requests remain GET-only, same-origin, redirect-free, DNS-pinned, response-size bounded, and cancellation-aware.
- SQLi findings require a clean baseline plus database-error evidence and a differential signal. XSS findings require raw marker reflection in the tested SVG-tag context; encoded reflection is not reported.
- ZAP uses a temporary context restricted to the exact target origin, spider depth 2 / 10 children per node, active-scan duration/rule limits, an alert cap, and a 90-second worker deadline. ZAP `ZAP_ACTIVE` never falls back to native-only scanning.
- Crawl scope is the configured target origin: scheme, host, and effective port must all match. Relative URLs are normalized and fragments removed. Redirects are not followed, so a `Location` destination is never requested. `discoveredLinks` counts accepted normalized links extracted from HTML documents only; CSS, JavaScript, image, font, and other non-HTML responses are requested only within the normal budget and are not persisted as crawl-page records.

## Frontend integration requirements

- Send the JWT returned by `POST /api/auth/login` as `Authorization: Bearer <token>`; do not infer permissions from client-side route guards.
- Use the standard `{ success, message, data }` envelope. Paginated organization-user and scan responses expose Spring page `content` and page metadata.
- Render `GET /api/organizations/me/dashboard` only for `ADMIN`, `GET /api/scans/me/dashboard` only for `SECURITY_ANALYST`, and `GET /api/organizations/platform-dashboard` only for `SUPER_ADMIN`.
- Treat scan lifecycle values as persisted state (`PENDING_APPROVAL`, `QUEUED`, `CRAWLING`, `SCANNING`, `COMPLETED`, `FAILED`, `CANCELLED`, `REJECTED`); do not synthesize progress. Refresh `GET /api/scans/{scanId}` and use `progress` only as returned by the worker.
- After completion, fetch `GET /api/scans/{scanId}/findings` and `GET /api/scans/{scanId}/crawl-pages`. Crawl-page responses contain metadata only, not response bodies.
- Handle `401` by requiring re-authentication and `403`/`404` without exposing cross-tenant resource details. A `409` indicates an invalid lifecycle operation or findings requested before completion.
- Findings with `verificationStatus` `SUSPECTED` or `POTENTIAL` are not confirmed exploitability claims and should be presented as requiring manual verification.
- DNS validation occurs immediately before each request and redirects are disabled. A residual race remains between final DNS resolution and the HTTP client’s connection because the JDK HTTP client does not expose a per-request pinned-address resolver in this implementation; production deployments should isolate scanner egress and use network-level destination controls.
- The legacy `CUSTOMER` enum and database role/user assignments remain to preserve existing database compatibility. Customer-only accounts cannot authenticate or be managed via the application. Removing persisted assignments and the role row would require a separate data migration and explicit disposition of those users.
- The legacy invitation table from V4 remains installed and may contain historical records; no runtime endpoint or Java persistence model uses it.
- MySQL Flyway V4–V6 migration compatibility and Hibernate schema validation require verification in an isolated MySQL 8 environment.

## Exact implementation files

- `src/main/java/com/vulnscanner/application/organization/OrganizationController.java`
- `src/main/java/com/vulnscanner/application/organization/OrganizationService.java`
- `src/main/java/com/vulnscanner/application/organization/OrganizationDashboardResponse.java`
- `src/main/java/com/vulnscanner/application/organization/OrganizationUserResponse.java`
- `src/main/java/com/vulnscanner/application/organization/MembershipResponse.java`
- `src/main/java/com/vulnscanner/application/organization/OrganizationRepository.java`
- `src/main/java/com/vulnscanner/application/organization/OrganizationApprovalRequest.java`
- `src/main/java/com/vulnscanner/application/organization/OrganizationDashboardResponse.java`
- `src/main/java/com/vulnscanner/application/auth/AuthService.java`
- `src/main/java/com/vulnscanner/application/security/JwtService.java`
- `src/main/java/com/vulnscanner/application/security/UserPrincipal.java`
- `src/main/java/com/vulnscanner/application/user/UserController.java`
- `src/main/java/com/vulnscanner/application/role/RoleInitializer.java`
- `src/main/java/com/vulnscanner/application/role/RoleName.java`
- `src/main/java/com/vulnscanner/application/user/UserRepository.java`
- `src/main/java/com/vulnscanner/application/user/UserStatus.java`
- `src/main/java/com/vulnscanner/application/user/UserAccountActionRequest.java`
- `src/main/resources/db/migration/V3__Add_user_management_indexes.sql`
- `src/test/java/com/vulnscanner/application/OrganizationManagementIntegrationTest.java`
- `src/test/java/com/vulnscanner/application/RegistrationApprovalTenantIntegrationTest.java`
- `src/test/java/com/vulnscanner/application/AuthSecurityIntegrationTest.java`
- `src/main/java/com/vulnscanner/application/target/Target.java`
- `src/main/java/com/vulnscanner/application/target/TargetRepository.java`
- `src/main/java/com/vulnscanner/application/target/TargetService.java`
- `src/main/java/com/vulnscanner/application/target/TargetController.java`
- `src/main/java/com/vulnscanner/application/target/TargetStatus.java`
- `src/main/java/com/vulnscanner/application/target/TargetType.java`
- `src/main/java/com/vulnscanner/application/target/TargetDecision.java`
- `src/main/java/com/vulnscanner/application/target/TargetCreateRequest.java`
- `src/main/java/com/vulnscanner/application/target/TargetDecisionRequest.java`
- `src/main/java/com/vulnscanner/application/target/TargetResponse.java`
- `src/main/resources/db/migration/V5__Add_organization_targets.sql`
- `src/test/java/com/vulnscanner/application/TargetManagementIntegrationTest.java`
- `src/main/java/com/vulnscanner/application/scan/ScanJob.java`
- `src/main/java/com/vulnscanner/application/scan/ScanFinding.java`
- `src/main/java/com/vulnscanner/application/scan/ScanJobRepository.java`
- `src/main/java/com/vulnscanner/application/scan/ScanFindingRepository.java`
- `src/main/java/com/vulnscanner/application/scan/ScanService.java`
- `src/main/java/com/vulnscanner/application/scan/ScanController.java`
- `src/main/resources/db/migration/V6__Add_persistent_scan_jobs_and_findings.sql`
- `src/main/resources/db/migration/V7__Add_scan_approval_workflow.sql`
- `src/main/java/com/vulnscanner/application/scan/ScanExecutionService.java`
- `src/main/java/com/vulnscanner/application/scan/ScanCrawlPage.java`
- `src/main/java/com/vulnscanner/application/scan/ScanCrawlPageRepository.java`
- `src/main/resources/db/migration/V8__Add_scan_crawl_pages.sql`
- `src/test/java/com/vulnscanner/application/ScanManagementIntegrationTest.java`
- `src/test/java/com/vulnscanner/application/scan/ScanExecutionServiceTest.java`
- `RBAC_PERMISSION_MATRIX.md`
- `RUNNING.md`
- `BACKEND_AUDIT.md`
- `BACKEND_SECURITY_REPORT.md`

Removed obsolete invitation runtime types: `OrganizationInvitation.java`, `OrganizationInvitationRepository.java`, `OrganizationInvitationRequest.java`, `OrganizationInvitationResponse.java`, and `OrganizationInvitationToken.java`. Flyway `V4__Add_organization_invitations.sql` was not edited or deleted.

## Current backend security hardening pass

- Bootstrap Super Admin provisioning has no email or password fallback. No email skips provisioning; a configured email without a nonblank password fails startup; an explicitly configured account is saved with a password hash.
- `PASSIVE_HEADERS` is passive-only. Native bounded SQLi/XSS probes run only for explicit `ZAP_ACTIVE` jobs; the ZAP active scan uses a temporary exact-origin context. Active ZAP requests do not fall back to native-only scanning.
- Worker claiming and state/progress writes use short transactions; the target HTTP, ZAP polling, and NVD requests execute outside scan-row-lock transactions. Workers re-read the persisted cancellation flag between requests and polling operations.
- ZAP missing IDs/status, malformed alert responses, polling failures, and incomplete/time-expired scans fail rather than completing successfully. Scoped ZAP spider/active work has bounded depth, response size, alert count, API read deadline, and worker time budget; the integration does not enforce a strict aggregate outbound-request-count quota.
- Native and ZAP findings are sanitized before storage; finding and report responses also redact historical sensitive strings. CSV formula-leading fields are neutralized. The one-page PDF summary reports the exact count omitted when its display budget is reached.
- Password-reset delivery is not implemented. Both reset endpoints return `503 Service Unavailable` and do not persist raw reset tokens.
- NVD results are cached in a 256-entry LRU only after valid successful responses. Keyword-search results are labeled low-severity candidates with unverified applicability, not confirmed affected-product findings.
- Native and ZAP/NVD HTTP response reads have explicit deadlines and response-size caps. Unexpected scan-worker logs include only scan ID and exception class, not exception text or target response content.
- No database schema migration was added. The API change is limited to password-reset requests returning `503`; scan and finding response shapes are unchanged.
- Current verification: `mvn compile` **BUILD SUCCESS**; `mvn test` **75 tests, 0 failures, 0 errors, 0 skipped**; `mvn package` **BUILD SUCCESS** with the same 75-test result. Tests use H2 and controlled local HTTP/ZAP fixtures.
- Live MySQL/Flyway, live OWASP ZAP, live NVD, and restart persistence are not established by the local regression tests in this pass. ZAP API behavior and parameter compatibility are also not verified against a live ZAP instance.
