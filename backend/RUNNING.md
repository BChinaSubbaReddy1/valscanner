# Running this backend

The application code builds with Maven and the integration tests run against
the test-scoped H2 database (see `target/surefire-reports/`). The only reason it
won't start standalone is that it needs a real MySQL 8 database — H2 is
intentionally test-scoped only (see `pom.xml`), matching production practice.

## Fastest path: Docker Compose (new)

This zip adds `docker-compose.yml` and `Dockerfile` so you can run the whole
stack (MySQL + backend) with one command:

```bash
cp .env.example .env   # edit values if you want non-default creds
docker compose up --build
```

This will:
1. Start MySQL 8 and create the `scanner` database.
2. Build the Spring Boot app in a Maven container.
3. Run Flyway migrations (`V1` through `V8`) against that database automatically.
4. Optionally bootstrap a `SUPER_ADMIN` account using
   `INITIAL_SUPER_ADMIN_EMAIL` / `INITIAL_SUPER_ADMIN_PASSWORD`. Both values
   are blank by default; set them through an untracked `.env` file or a
   deployment secret manager when bootstrap provisioning is required. Both must
   be explicitly set and nonblank to create a new account; startup fails if a
   password is missing when a new account needs to be created. A matching existing
   account is left unchanged and does not require the password.
5. Expose the API on `http://localhost:8081` by default (host port configurable
   with `BACKEND_HOST_PORT`; the container listens on port 8080).

Health check:
```bash
curl http://localhost:8081/actuator/health
```

After authenticating as an Organization Admin or Security Analyst and approving a target,
create and verify a passive scan:
```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"targetId":1,"scanType":"PASSIVE_HEADERS"}'
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/scans
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/scans/1/findings
```
Organization Admin approval:
```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/api/scans/pending-approval
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/api/scans/1/approve
```
To reject instead:
```bash
curl -X POST http://localhost:8080/api/scans/1/reject \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason":"Target is not ready"}'
```
Public HTTP and HTTPS targets do not need to be added to `.env`. The worker resolves
each hostname at scan time, rejects unsafe DNS answers, and connects to a validated
address. It follows only same-origin redirects and validates each destination before
following it. Loopback, private, link-local, multicast, unspecified, metadata, and
other special-use destinations are blocked by default. Private Docker labs are
authorized only by exact entries in `SCANNER_ALLOWED_PRIVATE_TARGET_ORIGINS`
(the Compose defaults are the `juice-shop:3000` and `dvwa:80` service origins); this
setting does not allow arbitrary private addresses.

Every newly submitted scan runs its selected native checks followed by the ZAP spider
and passive analysis. `PASSIVE_HEADERS` and `ZAP_PASSIVE` do not enable active probes;
`ZAP_ACTIVE` additionally sends bounded ZAP active scan requests. Analyst scan
requests require organization-admin approval before execution. Run the ZAP Compose
overlay, set an API key in the untracked `.env`, and keep the ZAP API available for
ZAP execution:

```bash
docker compose -f docker-compose.yml -f docker-compose.zap.yml up --build
```

The backend reaches ZAP at the internal `http://zap:8090` address. The ZAP host port
is bound to loopback, and its readiness check uses the authenticated API version
endpoint. ZAP scans use a temporary context restricted to the exact target origin.
ZAP outbound HTTP(S) requests use the `zap-egress` Squid proxy. It blocks loopback,
private, link-local, metadata, multicast, and special-use destination ranges; exact
private lab host-and-port origins from `SCANNER_ALLOWED_PRIVATE_TARGET_ORIGINS` are
the only private-destination exceptions, and are further bound to the addresses
resolved when the proxy starts. Restart the proxy after changing a lab target's
address. Explicit special-use and IPv6 metadata denials take precedence over those
exceptions. The proxy is internal to the Compose network and
does not publish a host port. ZAP itself is attached only to the internal API and proxy
networks, so it has no direct route to targets or the internet. Only the egress proxy
joins the isolated target network and the outbound network. Juice Shop and DVWA are
also joined to the isolated ZAP target network.
Spidering is limited to depth 2 and 10 children per node; ZAP active scan rule and
duration limits, alert caps, the worker deadline, and API timeouts are configured.
Reports retain distinct native and ZAP engine and stage statuses. If ZAP is disabled,
unavailable, times out, or fails, the overall scan may retain native results, but its
ZAP status and failure reason report that ZAP did not complete successfully.
The native scanner has configured request and response limits; ZAP has separate
spider/active scan limits.
POST-body, authenticated-account, and browser-execution coverage is not provided by
the native scanner.

Password-reset endpoints return `503 Service Unavailable` until a delivery integration
is configured. They do not create or store reset tokens in this configuration.
NVD keyword lookups are displayed only as low-severity candidates; product/version
applicability must be verified independently. Scan execution summaries distinguish
NVD lookup outcomes such as candidates found, no candidates, timeout, rate limit,
invalid response, unavailable service, and partial results. A failed lookup is not
reported as a successful no-candidate result. PDF exports are one-page summaries and
include the omitted-finding count when the 25-line findings budget is reached.

## Running without Docker

If you already have MySQL 8 running locally:

```bash
export DB_USERNAME=root
export DB_PASSWORD=your_password
export JWT_SECRET=your_persistent_random_secret
# Optional only when intentionally provisioning a new Super Admin:
export INITIAL_SUPER_ADMIN_EMAIL=admin@example.com
export INITIAL_SUPER_ADMIN_PASSWORD=use_a_unique_random_password
mvn spring-boot:run
```

On Windows PowerShell, generate a strong key once and persist it in your user
environment before starting the backend:

```powershell
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
$jwtSecret = [Convert]::ToBase64String($bytes)
[Environment]::SetEnvironmentVariable('JWT_SECRET', $jwtSecret, 'User')
$env:JWT_SECRET = $jwtSecret

$env:DB_USERNAME = 'root'
$env:DB_PASSWORD = 'your_mysql_password'
mvn spring-boot:run
```

The application uses the `app.security.jwt.secret` property, supplied by the
`JWT_SECRET` environment variable. Its current HS256 implementation treats the
value as literal UTF-8 bytes; it does not Base64-decode it. The generated
Base64-encoded random key is therefore used as a stable 44-byte UTF-8 string.
Keep the same value across restarts to preserve validation of unexpired tokens.
The user-scoped environment variable is available in newly opened terminals;
do not generate a new key on each start or commit it to the repository.

Make sure a `scanner` database exists (or change
`spring.datasource.url` in `src/main/resources/application.properties`);
Flyway will create the schema in it on startup.

### Recovering from the original V8 migration failure

If this database was started before the MySQL-compatible V8 fix, Flyway may
contain a failed version-8 history row. Confirm it first:

```sql
SELECT installed_rank, version, description, success
FROM flyway_schema_history
ORDER BY installed_rank;
```

After confirming `version = '8'` and `success = 0`, run `flyway repair` with
the same JDBC URL and credentials used by the application, then start the
backend again. Do not edit `flyway_schema_history` manually and do not delete
application tables or scan data. The corrected V8 migration stores the full
crawl URL and uses a SHA-256 URL key for the unique index, which is compatible
with MySQL 8 `utf8mb4` index limits.

## Running the test suite only (no MySQL needed)

```bash
mvn test
```

This uses the H2 in-memory database (`src/test/resources/application-test.yml`),
which is why it doesn't need MySQL installed.

## Recovering existing local accounts

The dedicated recovery utility updates the existing Super Admin, Lab
Organization Admin, and Docker Organization Admin accounts in one transaction.
It changes only each account's email and BCrypt password hash, verifies role and
account associations before and after the update, and aborts if an account or
requested email conflicts. If the old Super Admin email is absent, it can
recover an existing account already at the requested Super Admin email, after
verifying its role; it never creates a user. It accepts only loopback MySQL or
in-memory H2 databases. The utility is not part of normal application startup.

Run it from an interactive terminal in this directory:

```bash
mvn spring-boot:run -Dspring-boot.run.main-class=com.vulnscanner.localrecovery.LocalOrganizationAdminRecoveryApplication
```

It requires a real console and prompts without echo for each new password and
confirmation. Set `DB_USERNAME` and `DB_PASSWORD` in the current process
environment as needed; do not pass passwords as command-line arguments. The
utility does not print passwords or password hashes.

Security Analyst registration supplies an approved `organizationName`; no
organization ID or invitation token is required. The Super Admin registry is
available at `GET /api/organizations/registry`;
`DELETE /api/organizations/{id}` performs a guarded soft deactivation and
preserves organization users and historical records. See
[`RBAC_PERMISSION_MATRIX.md`](./RBAC_PERMISSION_MATRIX.md) for the response
DTOs, role requirements, and error behavior.
