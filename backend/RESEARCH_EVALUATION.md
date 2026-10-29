# Provisional Research Evaluation Framework

## Status and scope

This is a provisional engineering-evaluation framework, not a reconstruction of
an approved research proposal. No original research question, hypothesis,
acceptance criteria, baseline, or target population was found in the workspace.
Consequently, this document defines evaluation questions and measurable
procedures only; it reports no comparative effectiveness or research-gap
closure.

The system under evaluation is the tenant-scoped web application scanner in
this repository. Its current scan path performs bounded native checks and
requests OWASP ZAP spidering/passive analysis for every supported scan type.
Only `ZAP_ACTIVE` enables the active scan and native GET-parameter probes.
Reports expose distinct native/ZAP states and stage counters.

## Provisional evaluation questions

1. **Lifecycle correctness:** Do successful, failed, timed-out, cancelled, and
   unavailable ZAP stages produce accurate persisted statuses and report
   fields without losing already-collected native findings?
2. **Attribution:** Does scan-level alert filtering avoid attributing stale
   alerts to a new scan when scans against the same origin execute through the
   same ZAP instance?
3. **Isolation and safety:** Do tenant authorization, target approval,
   same-origin scope, DNS/address checks, and the configured ZAP egress boundary
   constrain every executed scan?
4. **Coverage transparency:** Do native crawl counts, ZAP spider counts, and
   report limitations distinguish bounded observation from comprehensive
   application coverage?

These are candidate evaluation questions; they require approval before being
treated as research objectives.

## Evidence available in this workspace

| Area | Existing evidence | What it establishes | What it does not establish |
|---|---|---|---|
| Backend behavior | `mvn test`: 172 passed, 0 failures/errors/skips (2026-10-29) | Current H2-backed regression suite passes | Production MySQL migrations, live ZAP behavior, or external-target effectiveness |
| Frontend behavior | `npm test`: 53 passed; `npm run build`: succeeded (2026-10-29) | Current frontend tests and production bundle build | Browser behavior against a live deployment |
| ZAP attribution | `ZapIntegrationTest` stale-alert, cross-origin/malformed alert URL, and concurrent same-origin cases; `ZapClientServiceTest` alert-ID parsing | Process-level behavior with controlled fixtures and origin filtering | Coordination among backend replicas or external users of the ZAP daemon |
| Scan output | `ScanReportIntegrationTest` JSON, CSV, PDF structure and empty-report checks | Report serialization for tested fixtures | Broad PDF reader interoperability or production-scale report performance |
| Historical scan artifact | Existing `scan-report-16.json`, `.csv`, and `.pdf` artifacts | A persisted report snapshot can be inspected | Current code-path behavior; the snapshot's `NOT_REQUESTED` ZAP state predates/does not demonstrate the current all-scan request path |
| Egress controls | Compose, Squid policy, generated ACLs, and effective proxy parse were checked; after Compose restart propagation, proxy GETs returned loopback/metadata 403, Juice Shop/host bridge 200, and DVWA 302 | Controlled destination allow/deny behavior through the running proxy after refreshing IP pinning | Live ZAP scanning, all deployed redirect/DNS cases, general public egress, or the full policy harness (which probes a public IP) |

The regression tests use isolated H2/local fixtures. They are not evidence of
production database, multi-replica, live ZAP, or broad vulnerability-detection
performance.

## Metrics and measurement protocol

Use only authorized isolated lab targets and record raw per-run artifacts.
Repeat each deterministic scenario enough times to expose concurrency or
recovery instability; choose and document the sample count before collecting
results.

| Metric | Definition |
|---|---|
| ZAP request accuracy | Number of newly submitted scans with persisted `zapRequested=true`, divided by newly submitted scans in the tested scenarios |
| ZAP stage-state accuracy | Per-stage agreement between the controlled ZAP outcome and persisted engine, spider, passive, and (when authorized) active statuses |
| Failure-reason accuracy | Agreement between injected failure type and the persisted failure/skip reason |
| Native-result retention | Findings present after a controlled ZAP failure compared with native findings collected before that failure |
| Alert-attribution precision | Alerts attributed to a scan that were introduced by that scan's controlled ZAP run divided by all alerts attributed to it |
| Tenant-isolation result | Whether direct cross-organization requests return the existing denial response and omit foreign data for every covered route/export |
| Egress-policy result | Allow/deny outcome for each approved and prohibited destination case, recorded with proxy logs and destination identity |
| Coverage-counter consistency | Agreement among discovered, visited, tested, and persisted counts with the corresponding crawler/ZAP fixture events |
| Runtime overhead | Elapsed scan-stage times and resource use under fixed lab conditions, reported per scan type without extrapolating beyond the tested setup |

For CVE enrichment, distinguish NVD CVSS from scanner finding severity:
keyword-only candidate findings remain LOW and POTENTIAL until applicability is
verified; CVSS values are evidence about the NVD candidate, not an asserted score
for the scanned target. Missing CVSS data is unavailable, not zero. Also record
whether response evidence was collected by native direct-socket checks or by ZAP
through Squid, whose response can include intermediary-added `Via` and
`Cache-Status` headers.

For each run, retain the code revision, configuration, target fixture version,
scan mode, authorization identity, expected outcome, persisted scan/report
output, relevant test logs, and any proxy/ZAP logs. Do not mix historical
artifacts with current runs.

## Required follow-up experiments

1. **Lifecycle matrix:** Exercise all three scan types with mocked ZAP success,
   health-check failure, timeout, malformed response, cancellation, and worker
   recovery. Verify persisted records and JSON/CSV/PDF output after each case.
2. **Attribution contention:** Run sequential and concurrent same-origin jobs
   against one controlled ZAP instance, including pre-existing alerts. Then
   repeat with two backend instances; the current fair lock is JVM-local, so
   multi-instance behavior must not be assumed safe without shared coordination
   or isolated ZAP daemons.
3. **Authorization matrix:** With two organizations, attempt scan details,
   findings, crawl pages, cancellation, mutations, and JSON/CSV/PDF exports
   using foreign IDs. Preserve the existing same-tenant positive cases.
4. **SSRF/egress matrix:** In a controlled private lab, test mixed DNS answers,
   IPv4/IPv6 prohibited ranges, redirects, proxy-only routing, address pinning,
   and approved lab exceptions. Record the post-refresh proxy ACL and verify
   both allowed lab access and prohibited destination denial. Do not use
   arbitrary public targets.
5. **Coverage validation:** Compare a static multi-page target and a
   JavaScript-driven SPA. Report native HTML-link discovery separately from
   ZAP spider discovery and state which execution engines visited each route.
6. **Scale and report robustness:** Use synthetic isolated datasets of stated
   sizes to evaluate CSV parsing/formula neutralization, PDF structural validity,
   report latency, and memory use. No large-report performance claim is currently
   supported.
7. **Database deployment:** Apply Flyway migrations and validate schema against
   an isolated MySQL 8 instance before claiming production database
   compatibility.

## Limitations and decision gates

- The original research goals and acceptance thresholds remain unknown.
- Current alert serialization is process-local; there is no distributed lock
  for multiple backend replicas sharing a ZAP daemon.
- The stale lab-IP ACL was refreshed by restarting the lab target through Compose;
  controlled proxy GET checks then confirmed the configured Juice Shop, host bridge,
  and DVWA routes and loopback/metadata denials. This does not establish a live ZAP
  scan or general public egress behavior.
- Startup recovery marks all nonterminal jobs failed. Without a persisted worker
  lease, this is unsafe for multiple backend replicas sharing a database; use only
  one backend instance until distributed worker ownership is implemented.
- The policy harness includes a public-IP request and was not run. No public
  target or live vulnerability scan was used for this evaluation.
- Results must distinguish automated test evidence, static configuration
  inspection, controlled runtime evidence, and production validation.

Do not present this framework as a completed research evaluation until the
research objectives, comparison baseline, protocols, and acceptance thresholds
are explicitly approved and the required measurements have been collected.
