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
   be explicitly set and nonblank; startup fails if an email is configured without
   a password.
5. Expose the API on `http://localhost:8080`.

Health check:
```bash
curl http://localhost:8080/actuator/health
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
The worker makes one bounded request to the approved target, does not follow redirects,
and rejects private or cloud-metadata destinations by default. For a controlled internal
test target only, set `SCANNER_ALLOW_PRIVATE_TARGETS=true`; approval and organization
authorization are still mandatory.

`PASSIVE_HEADERS` performs passive checks only and does not send SQL injection or XSS
test inputs. `ZAP_PASSIVE` and `ZAP_ACTIVE` require the configured ZAP service;
`ZAP_ACTIVE` never falls back to the native passive scanner. ZAP runs in a temporary
context restricted to the exact target origin. Spidering is limited to depth 2 and
10 children per node; active scanning is limited by ZAP rule/scan duration settings,
10 alerts per rule, a 90-second worker budget, and configured ZAP API timeouts.
There is no strict aggregate outbound-request-count quota, and live ZAP API behavior
has not been verified in this environment.
POST-body, authenticated-account, and browser-execution coverage is not provided by
the native scanner.

Password-reset endpoints return `503 Service Unavailable` until a delivery integration
is configured. They do not create or store reset tokens in this configuration.
NVD keyword lookups are displayed only as low-severity candidates; product/version
applicability must be verified independently. PDF exports are one-page summaries and
include the omitted-finding count when the 25-line findings budget is reached.

## Running without Docker

If you already have MySQL 8 running locally:

```bash
export DB_USERNAME=root
export DB_PASSWORD=your_password
export JWT_SECRET=replace_with_a_strong_secret_at_least_32_chars
# Optional only when intentionally provisioning a new Super Admin:
export INITIAL_SUPER_ADMIN_EMAIL=admin@example.com
export INITIAL_SUPER_ADMIN_PASSWORD=use_a_unique_random_password
mvn spring-boot:run
```

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

Security Analyst registration supplies an approved `organizationName`; no
organization ID or invitation token is required. The Super Admin registry is
available at `GET /api/organizations/registry`;
`DELETE /api/organizations/{id}` performs a guarded soft deactivation and
preserves organization users and historical records. See
[`RBAC_PERMISSION_MATRIX.md`](./RBAC_PERMISSION_MATRIX.md) for the response
DTOs, role requirements, and error behavior.
