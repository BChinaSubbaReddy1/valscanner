# Provisional Research Evaluation Framework

## Status and scope

This is a provisional engineering-evaluation framework, not a reconstruction of
an approved research proposal. No original research question, hypothesis,
acceptance criteria, baseline, or target population was found in the workspace.
Consequently, this document defines evaluation questions and measurable
procedures; its local fixture results are regression evidence only and do not
establish comparative or general scanner effectiveness.

The system under evaluation is the tenant-scoped web application scanner in
this repository. Its current scan path performs bounded native checks and
requests OWASP ZAP spidering/passive analysis for every supported scan type.
Only `ZAP_ACTIVE` enables active checks. The native SQL/XSS checks are selected
deterministically from observed endpoints, input names, response headers, and
media type, with POST forms requiring explicit allowlisting. Reports expose
distinct native/ZAP states, stage counters, and the sanitized check-selection
summary.
Role-scoped dashboard analytics now aggregate persisted scan and finding
history. Scan reports distinguish exact duplicates, same-endpoint related
findings, and findings without an observed relationship. These are measurement
and triage aids, not evidence that a finding is correct, exploitable, or part
of an attack path.

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
| Backend behavior | `mvn test`: 231 passed, 0 failures/errors/skips (2026-11-02) | H2-backed regression suite passes, including assignment-scoped analytics, bounded adaptive selection, structured finding metadata, correlation, cookie assessment/redaction, report exports, and evaluation formulas | Production MySQL migration execution, live ZAP behavior, or external-target effectiveness |
| Backend packaging | `mvn package -DskipTests`: succeeded (2026-11-02) | Java compilation and Spring Boot packaging complete | Runtime deployment and production configuration |
| Frontend behavior | `npm test`: 63 passed; `npm run build` and `npm run lint` succeeded (2026-11-02) | Frontend tests, production bundle, and lint pass, including relationship/metadata rendering and failure-state handling | Browser behavior against a live deployment |
| Local scanner evaluation fixture | `evaluatesAdditionalLabeledLocalFixturesFromPersistedScannerFindings`: 8 loopback cases across four categories | The actual scanner execution persisted detections that were compared with separately configured vulnerable/protected fixture labels; each category produced TP=1, FP=0, FN=0, TN=1 and 100% fixture coverage | Eight deterministic regression cases are not a representative dataset or evidence of general scanner effectiveness |
| ZAP attribution | `ZapIntegrationTest` stale-alert, cross-origin/malformed alert URL, and concurrent same-origin cases; `ZapClientServiceTest` alert-ID parsing | Process-level behavior with controlled fixtures and origin filtering | Coordination among backend replicas or external users of the ZAP daemon |
| Scan output | `ScanReportIntegrationTest` JSON, CSV, PDF structure, empty-report, structured finding metadata, and relationship-export checks | Report serialization and read-time relationship fields for tested fixtures | Broad PDF reader interoperability or production-scale report performance |
| Native assessment | `ScanExecutionServiceTest` positive SQL probe, generic database error/inert textarea reflection, adaptive selection, cookie attributes, and local evaluation fixtures | SQL/XSS selection remains bounded; generic errors and inert text are not elevated; cookie attribute observations omit values | No production targets, server-side session semantics, or representative measured false-positive rate |
| Historical analytics | Role-scoped H2 integration checks and frontend chart/API tests | Charts use persisted daily scan, finding, and organization-registration counts and analyst target assignments | Live MySQL time-zone behavior, large-data performance, or production history correctness |
| Finding relationships | `ScanReportIntegrationTest` exact duplicate, related endpoint, independent finding, authorization, and export checks | Matching preserves original findings and reports the relationship rationale in JSON, CSV, PDF, and UI | Causal attack paths, exploitability, or demonstrated false-positive reduction |
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
| Cross-engine overlap | Exact finding groups sharing check type and affected component across native and ZAP sources, reported as overlap only; this does not measure precision, recall, or exploitability |

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

## Finding-assessment evaluation status

The current finding model keeps severity separate from verification status and
the original ZAP confidence. Native response observations and ZAP source
metadata are retained in findings and reports. SQL/XSS checks remain suspected
or potential unless manually verified; NVD keyword-search results remain
potential candidates and do not establish product/version applicability.
Native SQL probes require a recognized database error signature on the
positive payload and not on the baseline or negative control. Reflected XSS
markers must appear as parsed SVG elements rather than inert text; neither
automated check is marked confirmed. HTTP `Set-Cookie` headers now produce a
low-severity observation with the cookie value omitted; cookie purpose and
session sensitivity remain unknown. When an attribute observation is emitted,
its evidence also includes the observed `Expires`, `Max-Age`, `Domain`, and
`Path` attribute states and validated scope/lifetime classifications, alongside
the existing `Secure`, `HttpOnly`, and `SameSite` flags. Raw attribute values
are not included. Conflicting duplicate attributes are marked ambiguous;
malformed lifetime values are not interpreted as persistent or session
cookies. This metadata alone does not establish authentication purpose or
server-side session semantics, and severity is not raised based on inferred
purpose.
Native frame-protection assessment accepts only exact `DENY` or `SAMEORIGIN`
X-Frame-Options values, or an exact CSP `frame-ancestors` directive; invalid
X-Frame-Options values are retained as evidence rather than treated as protection.

### Technical triage priority

Finding responses and reports include an additive `priorityScore`,
`priorityLevel`, and `priorityExplanation`. The deterministic technical-triage
heuristic uses only existing severity, verification status, and scanner source
confidence:

| Factor | Points |
|---|---|
| Severity HIGH / MEDIUM / LOW / unknown | 60 / 35 / 10 / 0 |
| Verification CONFIRMED / SUSPECTED / POTENTIAL / other or unknown | 15 / 8 / 3 / 0 |
| Source confidence HIGH / MEDIUM / LOW or unknown | 10 / 5 / 0 |

The score is the sum (capped at 100); levels are HIGH at 60+, MEDIUM at 30+,
and LOW below 30. Each response explains the factor values used. This is a
transparent triage heuristic, not a calibrated probability or business risk
model. Business impact, target exposure, and authentication context are not
scored unless structured evidence is added; they are currently treated as
unknown. The original severity and NVD CVSS are not changed or conflated with
this score. This policy has unit and report/frontend regression coverage, but
has not been validated against an independently labeled dataset.

`FindingEvaluationMetrics` is a test-only calculator for precision, recall,
accuracy, false-positive rate, false-negative rate, and F1 over an explicit
universe of finding-instance IDs. Its case-row entry point also groups results
by labeled vulnerability category and engine and reports execution coverage
against the declared planned rows, while separately counting executed, skipped,
unsupported, and failed rows. It rejects duplicate category/engine/case rows,
missing labels, and detections for cases not marked executed. Its tests cover
formulas, undefined zero-denominator cases, and validation rules. Each case
must be labeled against an independently verified reference set before it is
included. The calculator itself does not run the scanner pipeline. The
`evaluatesAdditionalLabeledLocalFixturesFromPersistedScannerFindings` test runs
the real native scanner against eight controlled loopback cases and derives
detections from persisted findings. It covers vulnerable/protected pairs for
security misconfiguration, cookie HttpOnly configuration, SQL injection, and
reflected XSS. Each category produced TP=1, FP=0, FN=0, TN=1; precision,
recall, F1, accuracy, and execution coverage were each 1.0, with false-positive
and false-negative rates of 0.0. These are fixture-only results, not estimates
of real-target effectiveness. There is no representative independently
labeled dataset or baseline comparison. The authenticated scan correlations
endpoint (`GET /api/scans/{scanId}/correlations`) distinguishes evidence-
identical duplicates, same-endpoint related findings, and findings without an
observed relationship; it does not change stored findings or their
verification status. It is intentionally not an attack-path graph and must
not be used as a substitute for a manually verified reference set.

Duplicate counts must be reported separately from false-positive metrics.
Native and ZAP findings remain attributed to their source; exact duplicate ZAP
evidence may be suppressed within a scan, while distinct evidence is retained.
Cross-engine overlap groups are derived at read time from the authorized scan's
persisted finding set and are included in the report response and JSON, CSV,
and PDF exports. No historical finding rewrite, automatic severity change, or
verification-status promotion is performed.

## Controlled scanner experiment: local fixtures measured; lab validation blocked

The evaluation unit is one pre-registered case consisting of a target image
digest, application state, route/resource, vulnerability category, and scan
configuration. Ground truth must be established before scanning from the lab's
documented vulnerable/non-vulnerable configuration and an independent manual
check. Do not use scanner alerts to label cases. For access-control cases,
ground truth requires two explicitly controlled identities and a non-destructive
read-only resource check. If that context is unavailable, exclude that
category and report it as blocked rather than treating scanner RBAC tests as
target-application results.

Use one primary scan per case for the confusion matrix. Predeclare repetitions
as reproducibility trials and report each trial and per-case consistency
separately; do not silently count retries as independent cases. Before running,
define the category/endpoint matching rule for a positive scanner result. A
finding is an observation to adjudicate, not its own ground truth. Preserve
both positive and negative cases for every category evaluated. Distinguish an
observed finding from its `CONFIRMED`, `SUSPECTED`, `POTENTIAL`, or
`UNVERIFIED` status; a scanner observation is never promoted to confirmed only
to improve a metric.

Record one row per case/run with at least:

`case_id, category, target_image_digest, application_version, route_or_resource,
ground_truth, ground_truth_source, scan_mode, scanner_git_revision,
scanner_image_digest, zap_version, run_id, started_at, elapsed_ms,
expected_detection, actual_detection, matched_finding_ids, evidence_reference,
adjudication`

Keep evidence local and access-controlled. Store references or hashes instead
of credentials, cookies, session tokens, or sensitive response bodies. Record
the exact sanitized configuration, target state, request/response evidence
needed for independent review, and scanner/ZAP logs with secrets removed.
Pin mutable `latest` target images to their inspected image digests before
comparing runs. For an OWASP ZAP comparison, use the same target state, scope,
case, and comparable spider/passive/active settings; report non-equivalent
coverage instead of comparing the scores.

For each category, define the reference universe as all pre-registered case
IDs. Independently label vulnerable cases as positives and non-vulnerable
cases as negatives. Mark a case as detected only when the predeclared matching
rule finds an in-scope alert for that case. Then calculate:

- `TP`: vulnerable cases detected; `FP`: non-vulnerable cases detected.
- `FN`: vulnerable cases not detected; `TN`: non-vulnerable cases not detected.
- `Precision = TP / (TP + FP)`; `Recall = TP / (TP + FN)`.
- `F1 = 2 * Precision * Recall / (Precision + Recall)`.
- `Accuracy = (TP + TN) / (TP + FP + FN + TN)`.
- `False-positive rate = FP / (FP + TN)`.
- `False-negative rate = FN / (FN + TP)`.

The test-only `FindingEvaluationMetrics` utility calculates these ratios from
explicit labeled ID sets and rejects observations outside the declared
universe. A zero denominator is undefined (`OptionalDouble.empty()`), not zero;
report it as N/A. Formula-only tests validate arithmetic, while the separate
eight-case loopback test above records a narrow real-execution fixture result.

### Environment observed, 2026-11-01

The local Compose lab containers were running. Juice Shop and DVWA returned
HTTP 200 on their loopback-published ports; the backend root returned HTTP 401,
as expected for an unauthenticated request. Inspected target image digests were
`sha256:42843723a7bf4246aa5d63c324978b17ef296ac78434aeddd34c427bfb5853f4`
(Juice Shop) and
`sha256:8029450682bd70e2e8cd1ffe8e46dd1885ff2a913296091cebfa8ba0a7d36498`
(DVWA). ZAP used `zaproxy/zap-stable:2.16.1`, image
`sha256:7840969c7c9fead565bf9734b12f49f6886db90b1d35b1f74d79710bbd081dab`,
and its container health was healthy. The target image tags are mutable
`latest`; record the inspected digest in any subsequent run.

No authenticated test analyst, approved/assigned target, case-level independent
ground-truth labels, or confirmed version of the running backend image matching
the current modified worktree was available. No scan was submitted to the
running Juice Shop or DVWA targets. Therefore external-lab TP/FP/TN/FN and
effectiveness metrics are blocked, not zero. The separate loopback fixture
metrics below are reported only for those controlled cases. The observed
external-target HTTP responses and container health establish service
availability only, not scanner effectiveness.

## Current research-gap status

| Research gap | Final status | Existing evidence and tests | Remaining limitation |
|---|---|---|---|
| False-positive reduction and experimental validation | IMPLEMENTED — EXTERNAL VALIDATION PENDING | Category/engine/coverage metric tests and an eight-case local scan fixture across four categories, with persisted scanner output and asserted TP/FP/FN/TN metrics | Fixture results are not representative; no independently labeled external lab dataset or baseline comparison |
| Cookie and session security | IMPLEMENTED — EXTERNAL VALIDATION PENDING | `HttpOnly`, `Secure`, `SameSite`, `Expires`, `Max-Age`, `Domain`, `Path`, duplicate/malformed attribute handling, and value-redaction tests | Cookie purpose and server-side session semantics remain unknown; no HTTPS fixture validates secure transport behavior |
| Context-aware risk prioritization | PARTIALLY IMPLEMENTED | Additive deterministic technical-priority score/level/explanation in finding API responses and JSON/CSV/PDF reports; unit and integration coverage | Heuristic weights are not empirically calibrated; business impact, authentication context, and exposure are not scored when unknown |
| Target-application IDOR/BOLA testing | NOT IMPLEMENTED | The scanner's own tenant/assignment authorization is covered separately by API integration tests; scan summaries list target authorization checks as out of scope | No authorized cross-identity target-application test context; scanner RBAC is not evidence of target-app BOLA coverage |
| Explainable findings | IMPLEMENTED — EXTERNAL VALIDATION PENDING | Available endpoint, method, parameter, component, engine, evidence, rationale, impact, remediation, and priority explanation are exposed through finding responses, details UI, JSON, CSV, and PDF; query values and cookie secrets are redacted | Detector-specific evidence is limited to what native checks or ZAP actually provide; no independent user study validates explanation usefulness |
| Advanced vulnerability correlation | IMPLEMENTED — EXTERNAL VALIDATION PENDING | Exact duplicates, same-endpoint related findings, and independent findings use normalized category, endpoint path, parameter, component, and evidence; rationale/confidence are available in API, UI, and exports | Deterministic heuristic relationships are not causal proof and have not been evaluated against an independently adjudicated corpus |
| Attack-path analysis | NOT IMPLEMENTED | Existing overlap output explicitly disclaims attack-path or exploitability conclusions | Verified prerequisite/dependency evidence is unavailable; overlap alone cannot justify a path |
| Adaptive vulnerability testing | IMPLEMENTED — EXTERNAL VALIDATION PENDING | Deterministic SQL/XSS selection uses observed endpoint, input names, response technology headers, and HTML media type; the bounded policy is integrated into active GET and explicitly allowlisted POST execution and records sanitized decisions | It selects only supported native checks; no external lab measures adaptive coverage or detection benefit |
| AI reasoning evaluation | EXCLUDED FROM SCOPE | No AI service, provider integration, or dependency was added | AI reasoning is excluded by the current directive; no AI API keys were searched for or used |

These statuses describe verified code and tests, not empirical scanner
effectiveness. The eight labeled cases are isolated loopback fixtures, not a
live Juice Shop or DVWA evaluation. Target-application cross-identity probing
and attack-path analysis are outside this task; AI reasoning is excluded from
scope. No AI provider request or API-key access was made.

The local end-to-end fixture test produced, for each of the four categories
(`SECURITY_MISCONFIGURATION`, `COOKIE_SECURITY`, `SQL_INJECTION`, `XSS`) and
the `NATIVE` engine, TP=1, FP=0, FN=0, TN=1. Precision, recall, F1, accuracy,
and execution coverage were each 1.0; false-positive and false-negative rates
were 0.0. This result is specific to the eight controlled loopback cases and
must not be reported as real-target or general scanner performance.
