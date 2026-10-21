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

1. **Scanner scope is intentionally limited**: the queue worker, same-origin bounded crawler, passive response-header checks, finding persistence, and cancellation handling are implemented for `PASSIVE_HEADERS`. There is no report/export API or active vulnerability testing. Outbound requests are bounded, do not follow redirects, reject private/link-local/multicast/cloud-metadata destinations by default, and pin each hostname to a stable public DNS address set for the duration of a scan. A future production deployment should still add network-level egress controls because application-level DNS validation cannot eliminate every race in an untrusted network.
2. **Migration environment**: tests use H2 and do not execute Flyway against MySQL. Run Flyway V4–V6 and schema validation in an isolated MySQL 8 staging environment before deployment.
3. **Legacy data**: review existing organization/user associations and pending organization ownership before rollout. No existing tenant association is inferred from names.
4. **Legacy data**: existing Customer and invitation rows are retained but unsupported by application workflows. Decide their archival/deactivation disposition before any future data-cleanup migration.
5. **Production identity provisioning**: configure bootstrap credentials through protected environment settings and rotate/remove initial credentials as required by operations policy.

## Verification

- `mvn test`: passed, 28 tests, 0 failures, 0 errors, 0 skipped.
- `mvn clean package`: passed; 28 tests, 0 failures, 0 errors, 0 skipped, executable JAR produced.
- Focused target-management integration tests passed. They exercise tenant isolation, role-specific visibility, target creation, approval, soft deletion, URL validation, and audit persistence.
- Tests use H2 with Flyway disabled. MySQL 8 Flyway migration execution was not possible because the Docker engine was unavailable and no isolated MySQL test database was confirmed.
