# Implementation status

## Implemented against the supplied backend

- Public registration offers only Organization Admin (`ADMIN`) and Security Analyst (`SECURITY_ANALYST`). Admins submit organization name and optional contact email; analysts submit an approved organization name. No invitation-token or organization-ID fields are shown or sent.
- Backend registration creates pending accounts/organization requests, rejects `CUSTOMER`, `SUPER_ADMIN`, and unknown fields. Analyst registration resolves the approved organization from the submitted organization name; no organization ID or invitation token is sent.
- Login hydrates `/api/users/me`, protected requests attach the bearer token, logout clears local state, and authenticated 401 responses expire the session.
- Super Admin can review pending organization registrations, approve/reject with confirmation, view the approved metadata registry, see their own organization metadata when returned, request guarded deactivation, and manage Organization Admin account status through the backend admin-account endpoints. Successful operations refresh backend data.
- Organization Admin user management uses authenticated `/api/organizations/me/...` endpoints for statistics, analyst listing/details, pending analyst membership requests, pagination, search/status filtering, and approve/reject/suspend/restore/deactivate actions. The UI no longer collects or submits reasons; the backend's current required-reason validation blocks those actions until its contract is updated.
- Organization Admin target management uses the implemented `/api/targets` controller for listing, creation, approval/rejection, soft deactivation, and refresh. Security Analysts receive the backend-authorized approved-target list.
- The analyst workspace refreshes `/api/users/me`, requires active account, approved membership, and approved organization status before displaying scan controls, and lists only API-returned approved targets.
- Analyst scan submission/history/status/cancellation/findings use the implemented `/api/scans` endpoints. The details route renders only backend-returned scan fields and findings. No report API or CVE data exists in the supplied backend.
- The analyst scan details route consumes the verified `/api/scans/{scanId}/crawl-pages` endpoint and renders only its persisted URL/depth/status/size/link-count/timestamp fields. `PASSIVE_HEADERS` remains the only selectable profile; SQL injection and reflected XSS are backend execution checks represented by returned finding types, not frontend options.
- Scan-detail reload failures now clear the scan, findings, and crawl-page state, preventing stale private data from remaining visible after an authorization or resource-access error. A target URL is shown only when the backend supplies one; the current `ScanJobResponse` supplies target name and ID but not URL.
- Scan-detail polling now prevents overlapping refresh requests, and failed-scan rendering is covered with backend status, progress, status message, and failure-reason assertions.
- User-name fallbacks use neutral "Name unavailable" text rather than exposing email addresses when the backend omits a display name.
- Dashboard routing now refuses to fetch data for an authenticated profile without a recognized application role, and analyst aggregate cards show `Unavailable` when required backend fields are absent instead of treating missing values as zero.
- Existing React 18/Vite/Router app organization and neutral CSS presentation remain in place. Related contract detail is in `API_INTEGRATION.md`.

## Backend integration blockers

- The backend now includes a scan executor that transitions jobs, persists crawl pages, and produces findings. Live browser-to-backend execution still has not been run from this frontend workspace.
- Report/export endpoints and CVE data are not implemented.
- Organization Admin analyst approval/lifecycle and Super Admin Admin-account lifecycle endpoints require a nonblank `reason` via `UserAccountActionRequest`. The frontend sends no reason per requirement, so these actions need a backend validation/DTO change before they can succeed without a reason. Organization approval/deletion and target decision endpoints accept optional reasons.
- The organization registry returns approved organizations and pending requests separately; it has no rejected-organization history endpoint.
- No live HTTP end-to-end run was performed. Frontend API/component tests use mocks; backend ScanManagement MockMvc tests are separate and do not verify the browser-to-server workflow.
- No authenticated browser-to-backend scan verification was performed because no usable test credentials were available in this session.

## Verification

- `npm test -- --reporter=dot --pool=threads --maxWorkers=1`: passed; 1 test file, 45 tests.
- `npm run lint`: passed with no warnings.
- `npm run build`: passed; Vite production bundle generated.
- Live backend health check: `GET http://localhost:8080/actuator/health` returned HTTP 200.
- Live protected-endpoint check: unauthenticated `GET http://localhost:8080/api/scans/2` returned HTTP 401.
- Backend `mvn -Dtest=ScanManagementIntegrationTest test`: 4 tests passed; exercises request DTOs, organization scoping, cancellation, and findings availability through Spring MockMvc/H2, not a live network integration test.
- Frontend API/component tests mock API calls. No live HTTP end-to-end run was performed.
- No live frontend-to-backend scan workflow was verified. API and policy limitations remain documented.
