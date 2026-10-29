# Backend security report

## Result summary

The existing registration and approval security was reviewed and retained. New organization-admin dashboard and user-management APIs are scoped to the authenticated administrator's persisted, approved organization. User-management responses expose display names and omit email, credentials, tokens, and other authentication secrets.

Suspension is distinct from deactivation. Only active accounts can authenticate; therefore a suspended account's existing JWT stops working on its next protected request. Deactivation is soft and retains database relationships and historical records.

## Findings addressed

| Finding | Severity | Resolution |
|---|---|---|
| Analyst organization association needed server-side resolution | High | Registration resolves a unique approved organization by normalized name and creates a pending membership tied to its persisted record |
| Organization Admin user-management and analyst approval APIs needed tenant restrictions | High | Scoped list/detail and approval APIs enforce organization, analyst role, status, and self-approval rules |
| Membership response exposed email to dashboard callers | Medium | Dashboard, member, approval, and admin-account DTOs now use display names and omit email |
| No restorable account suspension state existed | High | Added `SUSPENDED`; JWT filter/login continue to reject every non-active identity |
| Account deletion could invalidate historical relationships | Medium | Added status-based soft deactivation; no user row or organization relationship is physically deleted |
| Super Admin had no isolated Organization Admin account-management workflow | Medium | Added Super Admin-only list and account actions; scanner-data access is not implied and last active admin is protected |

## Existing controls confirmed

- Public registration allows only Organization Admin or Security Analyst, rejects client-supplied organization IDs/approval state, and creates a pending account.
- Organization Admin application creates its pending organization and explicitly linked registration admin; only a Super Admin may approve/reject it.
- Security Analyst registration targets an existing uniquely matched, approved organization by name and remains pending until an Admin in that organization approves or rejects it.
- Super Admin registry reads approved organizations from the database query. An integration test approves an organization named OWASP through the real workflow and verifies it appears with APPROVED status.
- Invitation endpoints and Java invitation models are removed. V4 and its legacy table remain immutable and retained. The legacy CUSTOMER role enum is retained solely to parse existing assignments; it is not seeded, accepted at registration, granted as an authority, or allowed to authenticate when it is the only role.
- Current database roles/account/organization state is reloaded for JWT requests; JWT signature, expiration, and blacklist validation remain in place.
- Organization membership routes verify the requesting admin's organization again in the service.
- Password reset does not reactivate disabled accounts; bootstrap Super Admin has no synthetic organization.

## API security boundaries

- Organization Admin `/api/organizations/me/**` APIs derive tenant identity from the authenticated user, never a request organization ID.
- Organization Admins can approve, suspend, restore, or deactivate eligible Security Analyst accounts only within their organization. They cannot manage their own account, any Super Admin, Organization Admin accounts, or legacy Customer accounts.
- Super Admin account-management endpoints target only Organization Admin accounts in approved organizations. They do not expose scanner data or grant organization membership.
- State-changing user actions require no user-supplied reason and create an audit event with actor, target, organization, event, and timestamp.
- Dashboard, user, approval, and account-management DTOs contain no email, password/hash, token, reset token, or organization identifier.
- Deactivation sets `DISABLED`; it cannot be reversed by the suspension restoration route. Suspension sets `SUSPENDED` and restoration is allowed only from that state.

## Residual risks and unverified scope

1. **Scanner scope is bounded, not comprehensive**: each supported scan type runs native checks, ZAP spidering, and ZAP passive analysis; only explicit `ZAP_ACTIVE` requests add native GET-parameter probes and ZAP active scanning. JSON, CSV, and PDF reports are available. Native crawling parses static HTML without JavaScript execution; ZAP spider counts do not guarantee dynamic SPA or authenticated-flow coverage. Native execution is bounded and blocks redirects to other origins, private/link-local/multicast/cloud-metadata destinations by default while pinning validated DNS addresses. ZAP traffic is routed through Squid. Controlled live proxy checks passed after Compose refreshed its stale lab-IP ACL, but a live ZAP scan was not performed. Multi-replica ZAP alert attribution and recovery are unsupported.
2. **Migration environment**: tests use H2 and do not execute Flyway against MySQL. Run the current Flyway migrations and schema validation in an isolated MySQL 8 staging environment before deployment.
3. **Legacy data**: review existing organization/user associations and pending organization ownership before rollout. No existing tenant association is inferred from names.
4. **Legacy data**: existing Customer and invitation rows are retained but unsupported by application workflows. Decide their archival/deactivation disposition before any future data-cleanup migration.
5. **Production identity provisioning**: configure bootstrap credentials through protected environment settings and rotate/remove initial credentials as required by operations policy.

## Verification

- Current validation (2026-10-29): backend `mvn test` passed, 172 tests, 0 failures, 0 errors, 0 skipped; frontend `npm test` passed, 53 tests; `npm run build` succeeded.
- Focused scan execution and report tests passed, 50 tests, 0 failures, 0 errors, 0 skipped.
- Existing target-management integration tests exercise tenant isolation, role-specific visibility, target creation, approval, soft deletion, URL validation, and audit persistence.
- Tests use H2 with Flyway disabled. MySQL 8 Flyway migration execution was not performed because no isolated MySQL test database was confirmed.
- These results are local test/build evidence only; they do not establish live ZAP/Squid behavior or production database migration success.
- Controlled egress checks on 2026-10-29 confirmed loopback and IPv4/IPv6 metadata denials (403), and allowed lab/host-bridge GETs (Juice Shop 200 after one transient 503; host bridge 200; DVWA 302). The full policy harness was not run because it probes a public IP. The current recovery runner assumes a single backend instance; startup of another instance could fail jobs active on the first instance.
