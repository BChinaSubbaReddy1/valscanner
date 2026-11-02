# Implementation status

## Implemented against the supplied backend

- Public registration offers only Organization Admin (`ADMIN`) and Security Analyst (`SECURITY_ANALYST`). Admins submit organization name and optional contact email; analysts submit an approved organization name. No invitation-token or organization-ID fields are shown or sent.
- Backend registration creates pending accounts/organization requests, rejects `CUSTOMER`, `SUPER_ADMIN`, and unknown fields. Analyst registration resolves the approved organization from the submitted organization name; no organization ID or invitation token is sent.
- Login hydrates `/api/users/me`, protected requests attach the bearer token, logout clears local state, and authenticated 401 responses expire the session.
- Super Admin can review pending organization registrations, approve/reject with confirmation, view the approved metadata registry, see their own organization metadata when returned, request guarded deactivation, and manage Organization Admin account status through the backend admin-account endpoints. Successful operations refresh backend data.
- Organization Admin user management uses authenticated `/api/organizations/me/...` endpoints for statistics, analyst listing/details, pending analyst membership requests, pagination, search/status filtering, and approve/reject/suspend/restore/deactivate actions. The related backend lifecycle endpoints require no reason request body.
- Organization Admin target management uses `/api/targets` for target lifecycle and explicit analyst assignment, reassignment, and removal. The analyst dropdown is populated with same-organization active analyst display names. Backend APIs enforce assignment access for targets and associated scan data.
- The analyst workspace refreshes `/api/users/me`, requires active account and approved membership, and displays only assigned approved targets returned by the backend.
- Analyst scan submission/history/status/cancellation/findings use the implemented `/api/scans` endpoints. Scan details also render the authorized report, JSON/CSV/PDF exports, NVD-sourced finding metadata, and exact same-scan native/ZAP overlap signals; overlap is included in report exports but is not presented as exploitability proof.
- The analyst scan details route consumes `/api/scans/{scanId}/crawl-pages` and renders persisted URL/depth/status/size/link-count/timestamp fields only. Supported selectable scan modes are `PASSIVE_HEADERS`, `ZAP_PASSIVE`, and `ZAP_ACTIVE`.
- Scan-detail reload failures now clear the scan, findings, and crawl-page state, preventing stale private data from remaining visible after an authorization or resource-access error. A target URL is shown only when the backend supplies one; the current `ScanJobResponse` supplies target name and ID but not URL.
- Scan-detail polling now prevents overlapping refresh requests, and failed-scan rendering is covered with backend status, progress, status message, and failure-reason assertions.
- User-name fallbacks use neutral "Name unavailable" text rather than exposing email addresses when the backend omits a display name.
- Dashboard routing now refuses to fetch data for an authenticated profile without a recognized role. In addition to aggregate cards, dashboards display role-scoped 30/90-day historical charts and a daily data table from persisted backend records.
- Existing React 18/Vite/Router app organization and neutral CSS presentation remain in place. Related contract detail is in `API_INTEGRATION.md`.

## Backend integration blockers

- The backend now includes a scan executor that transitions jobs, persists crawl pages, and produces findings. Live browser-to-backend execution still has not been run from this frontend workspace.
- The organization registry returns approved organizations and pending requests separately; it has no rejected-organization history endpoint.
- No live HTTP end-to-end run was performed. Frontend API/component tests use mocks; backend ScanManagement MockMvc tests are separate and do not verify the browser-to-server workflow.
- No authenticated browser-to-backend scan verification was performed because no usable test credentials were available in this session.

## Verification

- `npm test -- --reporter=dot --pool=threads --maxWorkers=1`: passed; 3 test files, 63 tests.
- `npm run lint`: passed with no warnings.
- `npm run build`: passed; Vite production bundle generated.
- Live Compose backend health check: `GET http://localhost:8081/actuator/health` returned HTTP 200.
- Live protected-endpoint check: unauthenticated `GET http://localhost:8081/api/scans/1` returned HTTP 401.
- Backend `mvn test`: 218 tests passed with no failures, errors, or skips. This includes H2-backed authentication, assignment, analytics, report/export, scan integration, and evaluation-metric tests; it does not validate production MySQL migrations or live network services.
- Frontend API/component tests mock API calls. No live HTTP end-to-end run was performed.
- No live frontend-to-backend scan workflow was verified. API and policy limitations remain documented.
