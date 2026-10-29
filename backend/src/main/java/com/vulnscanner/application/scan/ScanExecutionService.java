package com.vulnscanner.application.scan;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpTimeoutException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import com.vulnscanner.application.audit.AuditEvent;
import com.vulnscanner.application.audit.AuditEventRepository;
import com.vulnscanner.application.target.TargetStatus;

@Service
public class ScanExecutionService {
    private static final Logger LOG = LoggerFactory.getLogger(ScanExecutionService.class);
    private static final int MAX_RESPONSE_BYTES = 1_048_576;
    private static final int MAX_PARAMETERS_PER_URL = 3;
    private static final int MAX_CRAWL_DEPTH = 2;
    private static final int MAX_DISCOVERED_FORMS_PER_PAGE = 50;
    private static final int MAX_FORM_FIELDS = 50;
    private static final int MAX_FORM_BODY_BYTES = 8_192;
    private static final int MAX_REDIRECTS = 5;
    private static final int DEFAULT_MAX_REQUESTS = 10;
    private static final int DEFAULT_MAX_DETECTION_REQUESTS = 6;
    private static final int DEFAULT_REQUEST_TIMEOUT_SECONDS = 15;
    private static final Set<Long> CLAIMED = ConcurrentHashMap.newKeySet();
    private static final ReentrantLock ZAP_EXECUTION_LOCK = new ReentrantLock(true);

    private final ScanJobRepository scanJobRepository;
    private final ScanFindingRepository findingRepository;
    @Value("${scanner.allowed-private-target-origins:}")
    private String allowedPrivateTargetOrigins = "";
    @Value("${scanner.localhost-target-origin-mapping:}")
    private String localhostTargetOriginMapping = "";
    @Value("${scanner.active-post-form-allowlist:}")
    private String activePostFormAllowlist = "";
    private final TransactionTemplate transactionTemplate;
    private final AuditEventRepository auditEventRepository;
    private final ScanCrawlPageRepository crawlPageRepository;
    private final int maxRequests;
    private final int maxDetectionRequests;
    private final Duration requestTimeout;
    private final HttpClient httpClient;
    private final NvdCveService nvdCveService;
    private final ZapClientService zapClientService;
    private final ZapScanAdapter zapScanAdapter;
    private final Duration zapMaxDuration;

    @org.springframework.beans.factory.annotation.Autowired
    public ScanExecutionService(ScanJobRepository scanJobRepository,
                                ScanFindingRepository findingRepository,
                                @Value("false") boolean allowPrivateTargets,
                                TransactionTemplate transactionTemplate,
                                AuditEventRepository auditEventRepository,
                                ScanCrawlPageRepository crawlPageRepository,
                                @Value("${scanner.max-requests:10}") int maxRequests,
                                @Value("${scanner.max-detection-requests:6}") int maxDetectionRequests,
                                @Value("${scanner.request-timeout-seconds:15}") int requestTimeoutSeconds,
                                org.springframework.beans.factory.ObjectProvider<NvdCveService> nvdCveServiceProvider,
                                org.springframework.beans.factory.ObjectProvider<ZapClientService> zapClientServiceProvider,
                                org.springframework.beans.factory.ObjectProvider<ZapScanAdapter> zapScanAdapterProvider,
                                @Value("${scanner.zap.max-duration-seconds:90}") int zapMaxDurationSeconds) {
        this(scanJobRepository, findingRepository, allowPrivateTargets, transactionTemplate,
                auditEventRepository, crawlPageRepository, maxRequests, maxDetectionRequests,
                requestTimeoutSeconds, null,
                nvdCveServiceProvider != null ? nvdCveServiceProvider.getIfAvailable() : null,
                zapClientServiceProvider != null ? zapClientServiceProvider.getIfAvailable() : null,
                zapScanAdapterProvider != null ? zapScanAdapterProvider.getIfAvailable() : null,
                zapMaxDurationSeconds);
    }

    public ScanExecutionService(ScanJobRepository scanJobRepository,
                                ScanFindingRepository findingRepository,
                                @Value("false") boolean allowPrivateTargets,
                                TransactionTemplate transactionTemplate,
                                AuditEventRepository auditEventRepository,
                                ScanCrawlPageRepository crawlPageRepository,
                                @Value("${scanner.max-requests:10}") int maxRequests,
                                @Value("${scanner.max-detection-requests:6}") int maxDetectionRequests,
                                @Value("${scanner.request-timeout-seconds:15}") int requestTimeoutSeconds) {
        this(scanJobRepository, findingRepository, allowPrivateTargets, transactionTemplate,
                auditEventRepository, crawlPageRepository, maxRequests, maxDetectionRequests,
                requestTimeoutSeconds, null, null, null, null, 90);
    }

    ScanExecutionService(ScanJobRepository scanJobRepository,
                         ScanFindingRepository findingRepository,
                         boolean allowPrivateTargets,
                         TransactionTemplate transactionTemplate,
                         AuditEventRepository auditEventRepository,
                         ScanCrawlPageRepository crawlPageRepository,
                         int maxRequests,
                         int maxDetectionRequests,
                         int requestTimeoutSeconds,
                         HttpClient httpClient,
                         NvdCveService nvdCveService) {
        this(scanJobRepository, findingRepository, allowPrivateTargets, transactionTemplate,
                auditEventRepository, crawlPageRepository, maxRequests, maxDetectionRequests,
                requestTimeoutSeconds, httpClient, nvdCveService, null, null, 90);
    }

    public ScanExecutionService(ScanJobRepository scanJobRepository,
                                ScanFindingRepository findingRepository,
                                boolean allowPrivateTargets,
                                TransactionTemplate transactionTemplate,
                                AuditEventRepository auditEventRepository,
                                ScanCrawlPageRepository crawlPageRepository,
                                int maxRequests,
                                int maxDetectionRequests,
                                int requestTimeoutSeconds,
                                HttpClient httpClient,
                                NvdCveService nvdCveService,
                                ZapClientService zapClientService,
                                ZapScanAdapter zapScanAdapter) {
        this(scanJobRepository, findingRepository, allowPrivateTargets, transactionTemplate,
                auditEventRepository, crawlPageRepository, maxRequests, maxDetectionRequests,
                requestTimeoutSeconds, httpClient, nvdCveService, zapClientService, zapScanAdapter,
                90);
    }

    public ScanExecutionService(ScanJobRepository scanJobRepository,
                                ScanFindingRepository findingRepository,
                                boolean allowPrivateTargets,
                                TransactionTemplate transactionTemplate,
                                AuditEventRepository auditEventRepository,
                                ScanCrawlPageRepository crawlPageRepository,
                                int maxRequests,
                                int maxDetectionRequests,
                                int requestTimeoutSeconds,
                                HttpClient httpClient,
                                NvdCveService nvdCveService,
                                ZapClientService zapClientService,
                                ZapScanAdapter zapScanAdapter,
                                int zapMaxDurationSeconds) {
        this.scanJobRepository = scanJobRepository;
        this.findingRepository = findingRepository;
        this.transactionTemplate = transactionTemplate;
        this.auditEventRepository = auditEventRepository;
        this.crawlPageRepository = crawlPageRepository;
        this.maxRequests = requirePositive(maxRequests, "scanner.max-requests");
        this.maxDetectionRequests = requirePositive(maxDetectionRequests, "scanner.max-detection-requests");
        this.requestTimeout = Duration.ofSeconds(requirePositive(requestTimeoutSeconds,
                "scanner.request-timeout-seconds"));
        this.nvdCveService = nvdCveService;
        this.zapClientService = zapClientService;
        this.zapScanAdapter = zapScanAdapter != null ? zapScanAdapter : new ZapScanAdapter();
        this.zapMaxDuration = Duration.ofSeconds(requirePositive(zapMaxDurationSeconds,
                "scanner.zap.max-duration-seconds"));
        if (httpClient != null && httpClient.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("Scanner HTTP client must not follow redirects");
        }
        this.httpClient = httpClient != null ? httpClient : HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(this.requestTimeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    public ScanExecutionService(ScanJobRepository scanJobRepository,
                                ScanFindingRepository findingRepository,
                                boolean allowPrivateTargets,
                                TransactionTemplate transactionTemplate) {
        this(scanJobRepository, findingRepository, allowPrivateTargets, transactionTemplate, null, null,
                DEFAULT_MAX_REQUESTS, DEFAULT_MAX_DETECTION_REQUESTS, DEFAULT_REQUEST_TIMEOUT_SECONDS);
    }

    public ScanExecutionService(ScanJobRepository scanJobRepository,
                                ScanFindingRepository findingRepository,
                                boolean allowPrivateTargets,
                                TransactionTemplate transactionTemplate,
                                AuditEventRepository auditEventRepository,
                                ScanCrawlPageRepository crawlPageRepository) {
        this(scanJobRepository, findingRepository, allowPrivateTargets, transactionTemplate,
                auditEventRepository, crawlPageRepository,
                DEFAULT_MAX_REQUESTS, DEFAULT_MAX_DETECTION_REQUESTS, DEFAULT_REQUEST_TIMEOUT_SECONDS);
    }

    public void execute(Long scanId) {
        if (!CLAIMED.add(scanId)) {
            return;
        }
        try {
            runClaimed(scanId);
        } finally {
            CLAIMED.remove(scanId);
        }
    }

    protected void runClaimed(Long scanId) {
        ScanJob job = claimForExecution(scanId);
        if (job == null) {
            return;
        }
        if (job.getRequestedBy() == null || job.getRequestedBy().getStatus() != com.vulnscanner.application.user.UserStatus.ACTIVE
                || job.getRequestedBy().getOrganization() == null
                || job.getRequestedBy().getOrganization().getStatus() != com.vulnscanner.application.organization.OrganizationStatus.APPROVED
                || job.getRequestedBy().getOrganization().getId() == null
                || !job.getRequestedBy().getOrganization().getId().equals(job.getOrganization().getId())
                || job.getRequestedBy().getRoles().stream().noneMatch(role ->
                role.getName() == com.vulnscanner.application.role.RoleName.SECURITY_ANALYST)) {
            fail(job, ScanFailureReason.TARGET_URL_INVALID, "Requesting analyst is no longer eligible");
            return;
        }

        if (job.getReviewedBy() == null || job.getReviewedAt() == null
                || job.getTarget().getStatus() != TargetStatus.APPROVED
                || job.getTarget().getOrganization().getId() == null
                || !job.getTarget().getOrganization().getId().equals(job.getOrganization().getId())) {
            fail(job, ScanFailureReason.TARGET_URL_INVALID, "Approved target is no longer available");
            return;
        }

        try {
            runZapScan(job);
        } catch (ScanExecutionException exception) {
            markUnfinishedEnginesFailed(job);
            fail(job, exception.reason(), exception.getMessage());
        } catch (Exception exception) {
            LOG.warn("Scan worker failed for scan {} with {}", scanId, exception.getClass().getSimpleName());
            markUnfinishedEnginesFailed(job);
            fail(job, ScanFailureReason.OUTBOUND_REQUEST_FAILED, "Scan could not inspect the target");
        }
    }

    private void markUnfinishedEnginesFailed(ScanJob job) {
        boolean changed = false;
        if ("RUNNING".equals(job.getNativeEngineStatus())) {
            job.updateNativeEngineStatus("FAILED");
            changed = true;
        }
        if ("RUNNING".equals(job.getZapEngineStatus())) {
            job.updateZapEngineStatus("FAILED");
            job.updateZapFailureReason("ZAP_EXECUTION_FAILED");
            markRunningZapStages(job, "FAILED");
            changed = true;
        }
        if (changed) {
            persistExecutionState(job);
        }
    }

    private ScanJob claimForExecution(Long scanId) {
        ScanJob[] claimed = new ScanJob[1];
        Runnable claim = () -> {
            ScanJob candidate = scanJobRepository.findByIdForExecutionUpdate(scanId).orElse(null);
            if (candidate == null
                    || (candidate.getStatus() != ScanStatus.QUEUED && candidate.getStatus() != ScanStatus.CREATED)
                    || candidate.isCancellationRequested()) {
                return;
            }
            candidate.transitionTo(ScanStatus.RUNNING, Math.max(candidate.getProgress(), 1),
                    "Scan worker claimed the job", null);
            ScanJob saved = scanJobRepository.save(candidate);
            claimed[0] = saved == null ? candidate : saved;
        };
        if (transactionTemplate == null) {
            claim.run();
        } else {
            transactionTemplate.executeWithoutResult(status -> claim.run());
        }
        return claimed[0];
    }

    private void runNativeStages(ScanJob job, Map<String, Set<String>> resolvedAddressesByHost)
            throws ScanExecutionException {
        job.updateNativeEngineStatus("RUNNING");
        persistExecutionState(job);
        job.transitionTo(ScanStatus.CRAWLING, 10, "Discovering same-origin pages", null);
        persistExecutionState(job);

        CrawlResult crawl = crawl(job, resolvedAddressesByHost);
        if (cancellationRequested(job)) {
            job.updateNativeEngineStatus("CANCELLED");
            if (job.isZapRequested() && "NOT_STARTED".equals(job.getZapEngineStatus())) {
                job.updateZapFailureReason("CANCELLED_BEFORE_ZAP");
            }
            job.transitionTo(ScanStatus.CANCELLED, job.getProgress(), "Scan cancelled during execution", null);
            persistExecutionState(job);
            audit(job, "SCAN_JOB_CANCELLED", "Scan cancelled during execution");
            return;
        }
        job.transitionTo(ScanStatus.SCANNING, 70, "Running passive response checks", null);
        persistExecutionState(job);
        Set<String> findingKeys = new HashSet<>();
        int testedPages = 0;
        for (CrawledPage page : crawl.pages()) {
            if (cancelIfRequested(job, "Scan cancelled during passive response checks")) {
                return;
            }
            persistFindings(job, page.response(), page.uri(), findingKeys);
            testedPages++;
            job.updateCrawlCounts(crawl.discoveredPageCount(), crawl.visitedPageCount(), testedPages);
        }
        job.updateNativeEngineStatus("COMPLETED");
        persistExecutionState(job);
    }

    private void runZapScan(ScanJob job) throws ScanExecutionException {
        // Enforce SSRF validation before contacting ZAP or dispatching scan
        URI origin;
        URI zapOrigin;
        String targetUrl;
        Map<String, Set<String>> resolvedAddressesByHost = new HashMap<>();
        try {
            origin = new URI(job.getTarget().getUrl());
            validateResolvedAddresses(origin, resolvedAddressesByHost);
            TargetOriginMapping mapping = localhostTargetOriginMapping(origin);
            zapOrigin = mapping == null ? origin : mapping.destinationOrigin();
            if (mapping != null) {
                validateResolvedAddresses(zapOrigin, resolvedAddressesByHost);
            }
            targetUrl = targetUrlForOrigin(origin, mapping);
        } catch (UnknownHostException exception) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                    "Target hostname could not be resolved");
        } catch (URISyntaxException exception) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID, "Target URL is not safe to scan");
        } catch (IOException exception) {
            throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED, "Target could not be resolved");
        }

        if (job.getStatus() == ScanStatus.CREATED) {
            job.transitionTo(ScanStatus.QUEUED, 0, "Queued for OWASP ZAP scanning", null);
            persistExecutionState(job);
        }

        runNativeStages(job, resolvedAddressesByHost);
        if (job.getStatus() != ScanStatus.SCANNING) {
            return;
        }
        if (zapClientService == null) {
            job.updateZapEngineStatus("NOT_CONFIGURED");
            job.updateZapFailureReason("ZAP_CLIENT_NOT_CONFIGURED");
            persistExecutionState(job);
            completeWithPartialZapResults(job,
                    "Native checks completed; OWASP ZAP is not configured, so ZAP findings are omitted");
            return;
        }
        if (!zapClientService.isEnabled()) {
            job.updateZapEngineStatus("DISABLED");
            job.updateZapFailureReason("ZAP_DISABLED_BY_CONFIGURATION");
            persistExecutionState(job);
            completeWithPartialZapResults(job,
                    "Native checks completed; OWASP ZAP is disabled, so ZAP findings are omitted");
            return;
        }
        try {
            if (!acquireZapExecutionLock(job)) {
                return;
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            if (!cancelIfRequested(job, "Scan cancelled while waiting for OWASP ZAP")) {
                job.updateZapEngineStatus("FAILED");
                job.updateZapFailureReason("ZAP_EXECUTION_WAIT_INTERRUPTED");
                completeWithPartialZapResults(job,
                        "Native checks completed; OWASP ZAP failed (ZAP_EXECUTION_WAIT_INTERRUPTED)");
            }
            return;
        }
        String spiderScanId = null;
        String activeScanId = null;
        boolean spiderFinished = false;
        boolean activeFinished = false;
        ZapClientService.ScopeContext context = null;
        try {
            ZapClientService.AvailabilityStatus availability = zapClientService.checkAvailability();
            if (availability != ZapClientService.AvailabilityStatus.AVAILABLE) {
                boolean timedOut = availability == ZapClientService.AvailabilityStatus.TIMED_OUT;
                job.updateZapEngineStatus(timedOut ? "TIMED_OUT" : "UNAVAILABLE");
                job.updateZapFailureReason(timedOut
                        ? "ZAP_HEALTH_CHECK_TIMEOUT" : "ZAP_HEALTH_CHECK_FAILED");
                persistExecutionState(job);
                completeWithPartialZapResults(job,
                        timedOut
                                ? "Native checks completed; OWASP ZAP health check timed out"
                                : "Native checks completed; OWASP ZAP is unavailable, so ZAP findings are omitted");
                return;
            }
            job.updateZapEngineStatus("RUNNING");
            persistExecutionState(job);
            Set<String> existingAlertIds = zapClientService.getAlerts(targetUrl).stream()
                    .map(ZapAlert::id)
                    .filter(id -> id != null && !id.isBlank())
                    .collect(java.util.stream.Collectors.toUnmodifiableSet());
            context = zapClientService.createTargetContext(
                    zapOrigin, "scanner-" + job.getId() + "-" + UUID.randomUUID());
            long deadline = System.nanoTime() + zapMaxDuration.toNanos();
            job.updateProgress(job.getProgress(), "OWASP ZAP spider discovering pages");
            persistExecutionState(job);
            if (cancelIfRequested(job, "Scan cancelled before OWASP ZAP spider")) {
                return;
            }
            job.updateZapSpiderStatus("RUNNING");
            persistExecutionState(job);
            spiderScanId = zapClientService.startSpider(targetUrl, context.name());

            int spiderProgress = 0;
            int pollCount = 0;
            while (spiderProgress < 100 && pollCount < 60 && System.nanoTime() < deadline) {
                if (cancellationRequested(job)) {
                    zapClientService.stopSpider(spiderScanId);
                    spiderFinished = true;
                    job.updateZapEngineStatus("CANCELLED");
                    job.updateZapFailureReason("CANCELLED_DURING_ZAP");
                    job.updateZapSpiderStatus("CANCELLED");
                    job.transitionTo(ScanStatus.CANCELLED, job.getProgress(), "Scan cancelled during ZAP spider", null);
                    persistExecutionState(job);
                    audit(job, "SCAN_JOB_CANCELLED", "Scan cancelled during ZAP spider");
                    return;
                }
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new ScanExecutionException(ScanFailureReason.TIME_BUDGET_EXCEEDED, "Scan interrupted");
                }
                spiderProgress = zapClientService.getSpiderProgress(spiderScanId);
                int calculatedProgress = Math.max(job.getProgress(), 72 + (int) (spiderProgress * 0.12));
                job.updateProgress(calculatedProgress, "OWASP ZAP spider discovering pages (" + spiderProgress + "%)");
                persistExecutionState(job);
                pollCount++;
            }
            if (spiderProgress < 100 || System.nanoTime() > deadline) {
                throw new ScanExecutionException(ScanFailureReason.TIME_BUDGET_EXCEEDED,
                        "OWASP ZAP spider did not complete within its time budget");
            }
            spiderFinished = true;
            job.updateZapSpiderStatus("COMPLETED");
            persistExecutionState(job);
            job.updateZapSpiderDiscoveredCount(zapClientService.getSpiderDiscoveredCount(spiderScanId));
            persistExecutionState(job);

            // Active Scan phase if requested
            if (job.getScanType() == ScanType.ZAP_ACTIVE) {
                if (System.nanoTime() > deadline) {
                    throw new ScanExecutionException(ScanFailureReason.TIME_BUDGET_EXCEEDED,
                            "OWASP ZAP spider exceeded its time budget");
                }
                if (cancelIfRequested(job, "Scan cancelled before OWASP ZAP active scan")) {
                    return;
                }
                job.updateProgress(job.getProgress(), "OWASP ZAP running active vulnerability scan");
                job.updateZapActiveStatus("RUNNING");
                persistExecutionState(job);
                activeScanId = zapClientService.startActiveScan(targetUrl, context);

                int ascanProgress = 0;
                pollCount = 0;
                while (ascanProgress < 100 && pollCount < 120 && System.nanoTime() < deadline) {
                    if (cancellationRequested(job)) {
                        zapClientService.stopActiveScan(activeScanId);
                        activeFinished = true;
                        job.updateZapEngineStatus("CANCELLED");
                        job.updateZapFailureReason("CANCELLED_DURING_ZAP");
                        job.updateZapActiveStatus("CANCELLED");
                        job.transitionTo(ScanStatus.CANCELLED, job.getProgress(), "Scan cancelled during ZAP active scan", null);
                        persistExecutionState(job);
                        audit(job, "SCAN_JOB_CANCELLED", "Scan cancelled during ZAP active scan");
                        return;
                    }
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new ScanExecutionException(ScanFailureReason.TIME_BUDGET_EXCEEDED, "Scan interrupted");
                    }
                    ascanProgress = zapClientService.getActiveScanProgress(activeScanId);
                    int calculatedProgress = Math.max(job.getProgress(), 88 + (int) (ascanProgress * 0.08));
                    job.updateProgress(calculatedProgress, "OWASP ZAP active vulnerability scan (" + ascanProgress + "%)");
                    persistExecutionState(job);
                    pollCount++;
                }
                if (ascanProgress < 100 || System.nanoTime() > deadline) {
                    throw new ScanExecutionException(ScanFailureReason.TIME_BUDGET_EXCEEDED,
                            "OWASP ZAP active scan did not complete within its time budget");
                }
                activeFinished = true;
                job.updateZapActiveStatus("COMPLETED");
                persistExecutionState(job);
            }

            job.updateZapPassiveStatus("RUNNING");
            persistExecutionState(job);
            job.updateProgress(job.getProgress(), "Waiting for OWASP ZAP passive analysis");
            persistExecutionState(job);
            while (zapClientService.getPassiveScanRecordsToScan() > 0
                    && System.nanoTime() < deadline) {
                if (cancelIfRequested(job, "Scan cancelled during ZAP passive analysis")) {
                    return;
                }
                try {
                    Thread.sleep(500);
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw new ScanExecutionException(ScanFailureReason.TIME_BUDGET_EXCEEDED, "Scan interrupted");
                }
            }
            if (System.nanoTime() > deadline) {
                throw new ScanExecutionException(ScanFailureReason.TIME_BUDGET_EXCEEDED,
                        "OWASP ZAP passive analysis exceeded its time budget");
            }
            job.updateZapPassiveStatus("COMPLETED");
            persistExecutionState(job);

            // Process alerts
            if (System.nanoTime() > deadline) {
                throw new ScanExecutionException(ScanFailureReason.TIME_BUDGET_EXCEEDED,
                        "OWASP ZAP scan exceeded its time budget");
            }
            if (cancelIfRequested(job, "Scan cancelled before OWASP ZAP alert processing")) {
                return;
            }
            List<ZapAlert> alerts = zapClientService.getAlerts(targetUrl).stream()
                    .filter(alert -> alert.id() != null && !alert.id().isBlank())
                    .filter(alert -> !existingAlertIds.contains(alert.id()))
                    .filter(alert -> isSameOriginZapAlert(zapOrigin, alert))
                    .map(alert -> restoreSavedTargetOrigin(alert, origin, zapOrigin))
                    .toList();
            if (System.nanoTime() > deadline) {
                throw new ScanExecutionException(ScanFailureReason.TIME_BUDGET_EXCEEDED,
                        "OWASP ZAP scan exceeded its time budget");
            }
            if (cancelIfRequested(job, "Scan cancelled during OWASP ZAP alert processing")) {
                return;
            }
            persistZapFindings(job, alerts);

            job.updateZapAlertCount(alerts.size());
            job.updateZapEngineStatus("COMPLETED");
            job.transitionTo(ScanStatus.COMPLETED, 100, "Native and OWASP ZAP scans completed successfully", null);
            persistExecutionState(job);
            audit(job, "SCAN_JOB_COMPLETED", job.getStatusMessage());
        } catch (ScanExecutionException exception) {
            LOG.warn("OWASP ZAP scan {} did not complete: {}", job.getId(), exception.reason());
            String failedStatus = exception.reason() == ScanFailureReason.TIME_BUDGET_EXCEEDED
                    ? "TIMED_OUT" : "FAILED";
            job.updateZapEngineStatus(failedStatus);
            job.updateZapFailureReason(exception.reason().name());
            markRunningZapStages(job, failedStatus);
            completeWithPartialZapResults(job,
                    "Native checks completed; OWASP ZAP " + failedStatus.toLowerCase(Locale.ROOT)
                            + " (" + exception.reason().name() + ")");
        } catch (IOException e) {
            LOG.warn("OWASP ZAP API communication failed for scan {}", job.getId());
            boolean timedOut = e instanceof HttpTimeoutException;
            String failedStatus = timedOut ? "TIMED_OUT" : "FAILED";
            String failureReason = timedOut ? "ZAP_REQUEST_TIMEOUT" : "ZAP_COMMUNICATION_FAILED";
            job.updateZapEngineStatus(failedStatus);
            job.updateZapFailureReason(failureReason);
            markRunningZapStages(job, failedStatus);
            completeWithPartialZapResults(job,
                    "Native checks completed; OWASP ZAP " + failedStatus.toLowerCase(Locale.ROOT)
                            + " (" + failureReason + ")");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.warn("OWASP ZAP scan {} was interrupted", job.getId());
            if (job.isCancellationRequested()) {
                job.updateZapEngineStatus("CANCELLED");
                job.updateZapFailureReason("CANCELLED_DURING_ZAP");
                markRunningZapStages(job, "CANCELLED");
                job.transitionTo(ScanStatus.CANCELLED, job.getProgress(),
                        "Scan cancelled during OWASP ZAP execution", null);
                persistExecutionState(job);
                audit(job, "SCAN_JOB_CANCELLED", job.getStatusMessage());
            } else {
                job.updateZapEngineStatus("FAILED");
                job.updateZapFailureReason("ZAP_INTERRUPTED");
                markRunningZapStages(job, "FAILED");
                completeWithPartialZapResults(job,
                        "Native checks completed; OWASP ZAP failed (ZAP_INTERRUPTED)");
            }
        } finally {
            if (activeScanId != null && !activeFinished) {
                zapClientService.stopActiveScan(activeScanId);
            }
            if (spiderScanId != null && !spiderFinished) {
                zapClientService.stopSpider(spiderScanId);
            }
            zapClientService.removeContext(context);
            ZAP_EXECUTION_LOCK.unlock();
        }
    }

    private boolean acquireZapExecutionLock(ScanJob job) throws InterruptedException {
        long deadline = System.nanoTime() + zapMaxDuration.toNanos();
        while (true) {
            if (cancelIfRequested(job, "Scan cancelled while waiting for OWASP ZAP")) {
                return false;
            }
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) {
                job.updateZapEngineStatus("TIMED_OUT");
                job.updateZapFailureReason("ZAP_EXECUTION_WAIT_TIMEOUT");
                persistExecutionState(job);
                completeWithPartialZapResults(job,
                        "Native checks completed; OWASP ZAP timed out waiting for an execution slot");
                return false;
            }
            if (ZAP_EXECUTION_LOCK.tryLock(Math.min(remaining, TimeUnit.MILLISECONDS.toNanos(250)),
                    TimeUnit.NANOSECONDS)) {
                return true;
            }
        }
    }

    private void completeWithPartialZapResults(ScanJob job, String statusMessage) {
        job.transitionTo(ScanStatus.COMPLETED, 100, statusMessage, null);
        persistExecutionState(job);
        audit(job, "SCAN_JOB_PARTIALLY_COMPLETED", statusMessage);
    }

    private void markRunningZapStages(ScanJob job, String status) {
        if ("RUNNING".equals(job.getZapSpiderStatus())) {
            job.updateZapSpiderStatus(status);
        }
        if ("RUNNING".equals(job.getZapPassiveStatus())) {
            job.updateZapPassiveStatus(status);
        }
        if ("RUNNING".equals(job.getZapActiveStatus())) {
            job.updateZapActiveStatus(status);
        }
    }

    private void persistZapFindings(ScanJob job, List<ZapAlert> alerts) {
        if (alerts == null || alerts.isEmpty()) {
            return;
        }
        Set<FindingDeduplicationKey> existingKeys = new HashSet<>();
        List<ScanFinding> existingFindings = findingRepository.findByScanJob_Id(job.getId());
        if (existingFindings != null) {
            for (ScanFinding f : existingFindings) {
                existingKeys.add(findingDeduplicationKey(f));
            }
        }

        for (ZapAlert alert : alerts) {
            ScanFinding candidate = zapScanAdapter.toFinding(job, alert);
            FindingDeduplicationKey key = findingDeduplicationKey(candidate);
            if (existingKeys.add(key)) {
                findingRepository.save(candidate);
            }
        }
    }

    private FindingDeduplicationKey findingDeduplicationKey(ScanFinding finding) {
        return new FindingDeduplicationKey(
                finding.getDetectionSource(),
                finding.getCheckType(),
                finding.getSourceRuleId(),
                finding.getAffectedComponent(),
                finding.getEvidence(),
                finding.getSeverity(),
                finding.getVerificationStatus(),
                finding.getSourceConfidence(),
                finding.getSourceReference(),
                finding.getSourceCweId(),
                finding.getSourceWascId());
    }

    public void markRejected(Long scanId) {
        transactionTemplate.executeWithoutResult(status -> {
            ScanJob job = scanJobRepository.findById(scanId).orElse(null);
            if (job != null && job.getStatus() == ScanStatus.QUEUED) {
                fail(job, ScanFailureReason.EXECUTOR_UNAVAILABLE, "Scan queue is full; try again later");
            }
        });
    }

    private CrawlResult crawl(ScanJob job, Map<String, Set<String>> resolvedAddressesByHost)
            throws ScanExecutionException {
        URI origin;
        try {
            origin = new URI(job.getTarget().getUrl());
        } catch (URISyntaxException exception) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID, "Target URL is not safe to scan");
        }
        Deque<CrawlRequest> queue = new ArrayDeque<>();
        Set<URI> visited = new LinkedHashSet<>();
        Set<URI> discovered = new LinkedHashSet<>();
        List<CrawledPage> pages = new ArrayList<>();
        ScanContext context = new ScanContext(maxRequests, maxDetectionRequests, resolvedAddressesByHost);
        int duplicateRequestsSkipped = 0;
        int outOfScopeRequestsSkipped = 0;
        URI normalizedOrigin = normalize(origin);
        discovered.add(normalizedOrigin);
        queue.add(new CrawlRequest(normalizedOrigin, 0));
        while (!queue.isEmpty() && visited.size() < maxRequests) {
            if (cancellationRequested(job)) {
                break;
            }
            CrawlRequest next = queue.removeFirst();
            URI uri = normalize(next.uri());
            if (!sameOrigin(origin, uri)) {
                outOfScopeRequestsSkipped++;
                continue;
            }
            if (!visited.add(uri)) {
                duplicateRequestsSkipped++;
                continue;
            }
            ScanResponse response = requestTarget(uri, context, false);
            URI responseUri = normalize(response.finalUri());
            discovered.add(responseUri);
            boolean htmlDocument = isHtmlDocument(response);
            PageDiscovery discovery = htmlDocument
                    ? discoverPage(origin, responseUri, firstHeader(response.headers(), "content-type"),
                            response.body())
                    : new PageDiscovery(List.of(), List.of(), List.of(), LinkDiscoveryStats.EMPTY);
            boolean depthLimitReached = next.depth() >= MAX_CRAWL_DEPTH;
            int linksOmittedByDepthLimit = depthLimitReached ? discovery.links().size() : 0;
            LOG.info("Native crawler page analyzed: scan={} depth={} html={} candidateLinks={} "
                            + "acceptedSameOriginLinks={} rejectedCrossOriginLinks={} rejectedInvalidLinks={} "
                            + "duplicateLinks={} depthLimitReached={} linksOmittedByDepthLimit={}",
                    job.getId(), next.depth(), htmlDocument, discovery.linkStats().candidateLinks(),
                    discovery.linkStats().acceptedSameOriginLinks(),
                    discovery.linkStats().rejectedCrossOriginLinks(),
                    discovery.linkStats().rejectedInvalidLinks(), discovery.linkStats().duplicateLinks(),
                    depthLimitReached, linksOmittedByDepthLimit);
            pages.add(new CrawledPage(responseUri, response));
            if (!cancellationRequested(job) && crawlPageRepository != null && htmlDocument) {
                crawlPageRepository.save(new ScanCrawlPage(job, responseUri.toString(), next.depth(),
                        response.statusCode(), response.body().length, discovery.links().size(),
                        discovery.forms()));
            }
            if (!cancellationRequested(job) && job.getScanType() == ScanType.ZAP_ACTIVE) {
                persistParameterFindings(job, responseUri, response, context);
                probePostForms(job, origin, discovery.postForms(), context);
            }
            if (next.depth() < MAX_CRAWL_DEPTH) {
                for (URI link : discovery.links()) {
                    discovered.add(link);
                    queue.addLast(new CrawlRequest(link, next.depth() + 1));
                }
            }
        }
        boolean requestLimitReached = visited.size() >= maxRequests && !queue.isEmpty();
        LOG.info("Native crawler finished: scan={} discoveredPages={} visitedPages={} "
                        + "duplicateRequestsSkipped={} outOfScopeRequestsSkipped={} requestLimitReached={} "
                        + "queuedLinksNotVisited={}",
                job.getId(), discovered.size(), visited.size(), duplicateRequestsSkipped,
                outOfScopeRequestsSkipped, requestLimitReached,
                requestLimitReached ? queue.size() : 0);
        if (pages.isEmpty()) {
            if (cancellationRequested(job)) {
                return new CrawlResult(List.of(), discovered.size(), 0);
            }
            throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED,
                    "Target response could not be inspected");
        }
        int discoveredCount = discovered.size();
        int visitedCount = pages.size();
        job.updateCrawlCounts(discoveredCount, visitedCount, 0);
        persistExecutionState(job);
        return new CrawlResult(List.copyOf(pages), discoveredCount, visitedCount);
    }

    private ScanResponse requestTarget(URI uri, ScanContext context, boolean detectionRequest)
            throws ScanExecutionException {
        URI current = uri;
        Set<URI> redirectChain = new HashSet<>();
        redirectChain.add(normalize(uri));
        for (int redirects = 0; ; redirects++) {
            InetAddress[] addresses;
            try {
                addresses = validateResolvedAddresses(current, context.resolvedAddressesByHost());
            } catch (UnknownHostException exception) {
                throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                        "Target hostname could not be resolved");
            } catch (IOException exception) {
                throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED,
                        "Target could not be resolved");
            }

            if (!context.tryConsumeRequest(detectionRequest)) {
                throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED,
                        "Request budget is exhausted");
            }
            PinnedHttpResponse.Response response;
            try {
                response = PinnedHttpResponse.send(current, addresses, requestTimeout, MAX_RESPONSE_BYTES,
                        "Automated-Web-Scanner-Passive/1.0");
            } catch (java.net.SocketTimeoutException exception) {
                throw new ScanExecutionException(ScanFailureReason.TIME_BUDGET_EXCEEDED,
                        "Target request timed out");
            } catch (PinnedHttpResponse.ResponseTooLargeException exception) {
                throw new ScanExecutionException(ScanFailureReason.RESPONSE_LIMIT_EXCEEDED,
                        "Target response exceeded the permitted size");
            } catch (IOException exception) {
                throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED,
                        "Target request failed");
            }

            if (!isRedirect(response.statusCode())) {
                return new ScanResponse(response.statusCode(), response.headers(), response.body(), current);
            }
            List<String> locations = response.headers().getOrDefault("location", List.of());
            if (locations.size() > 1) {
                throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                        "Target returned ambiguous redirect destinations");
            }
            String location = locations.isEmpty() ? null : locations.getFirst();
            if (location == null || location.isBlank()) {
                return new ScanResponse(response.statusCode(), response.headers(), response.body(), current);
            }
            if (redirects >= MAX_REDIRECTS) {
                throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                        "Target exceeded the permitted redirect limit");
            }
            URI destination;
            try {
                destination = normalize(current.resolve(new URI(location)).normalize());
                if (!redirectChain.add(destination)) {
                    throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                            "Target returned a redirect loop");
                }
                if (!sameOrigin(uri, destination)) {
                    throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                            "Redirect destination is outside the authorized target origin");
                }
                validateResolvedAddresses(destination, context.resolvedAddressesByHost());
            } catch (ScanExecutionException exception) {
                throw exception;
            } catch (URISyntaxException | IllegalArgumentException exception) {
                throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                        "Target returned an invalid redirect destination");
            } catch (UnknownHostException exception) {
                throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                        "Redirect destination hostname could not be resolved");
            } catch (IOException exception) {
                throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED,
                        "Redirect destination could not be validated");
            }
            current = destination;
        }
    }

    private ScanResponse requestPostTarget(URI origin, URI uri, byte[] body, ScanContext context)
            throws ScanExecutionException {
        if (!sameOrigin(origin, uri) || !isConfiguredPostAction(uri)) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                    "POST form action is no longer within the approved scan scope");
        }
        InetAddress[] addresses;
        try {
            addresses = validateResolvedAddresses(uri, context.resolvedAddressesByHost());
        } catch (UnknownHostException exception) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                    "Target hostname could not be resolved");
        } catch (IOException exception) {
            throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED,
                    "Target could not be resolved");
        }
        context.tryConsumeRequest(true);
        PinnedHttpResponse.Response response;
        try {
            response = PinnedHttpResponse.sendPost(uri, addresses, requestTimeout, MAX_RESPONSE_BYTES,
                    "Automated-Web-Scanner-Active/1.0", body);
        } catch (java.net.SocketTimeoutException exception) {
            throw new ScanExecutionException(ScanFailureReason.TIME_BUDGET_EXCEEDED,
                    "Target request timed out");
        } catch (PinnedHttpResponse.ResponseTooLargeException exception) {
            throw new ScanExecutionException(ScanFailureReason.RESPONSE_LIMIT_EXCEEDED,
                    "Target response exceeded the permitted size");
        } catch (IOException exception) {
            throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED,
                    "Target request failed");
        }
        return new ScanResponse(response.statusCode(), response.headers(), response.body(), uri);
    }

    private void probePostForms(ScanJob job, URI origin, List<PostFormCandidate> forms, ScanContext context)
            throws ScanExecutionException {
        for (PostFormCandidate form : forms) {
            if (cancellationRequested(job) || !context.canConsumeDetectionRequests(4)) {
                return;
            }
            byte[] baselineBody = encodeForm(form.parameters(), -1, "");
            if (baselineBody == null) {
                continue;
            }
            Set<String> keys = new HashSet<>();
            ScanResponse baseline = requestPostTarget(origin, form.action(), baselineBody, context);
            persistFindings(job, baseline, form.action(), keys);
            for (int index = 0; index < form.parameters().size(); index++) {
                if (cancellationRequested(job) || !context.canConsumeDetectionRequests(3)) {
                    break;
                }
                FormParameter parameter = form.parameters().get(index);
                String sqlTrue = "' OR '1'='1";
                String sqlFalse = "' OR '1'='2";
                byte[] sqlTrueBody = encodeForm(form.parameters(), index, sqlTrue);
                byte[] sqlFalseBody = encodeForm(form.parameters(), index, sqlFalse);
                if (sqlTrueBody == null || sqlFalseBody == null) {
                    break;
                }
                ScanResponse sqlPositive = requestPostTarget(origin, form.action(), sqlTrueBody, context);
                ScanResponse sqlNegative = requestPostTarget(origin, form.action(), sqlFalseBody, context);
                if (isSqlError(sqlPositive.body()) && !isSqlError(baseline.body())
                        && (isSqlError(sqlNegative.body())
                        || (sqlPositive.statusCode() >= 500 && baseline.statusCode() < 500))) {
                    String errorSnippet = extractSqlErrorSnippet(sqlPositive.body());
                    addFinding(job, keys, "SQL_INJECTION_SUSPECTED",
                            form.action() + " [" + parameter.name() + "]", "HIGH",
                            "Allowlisted POST form parameter '" + bounded(parameter.name())
                                    + "' triggered a database error signature (" + errorSnippet
                                    + "); manual verification is required.",
                            "Use parameterized queries and validate input before database access.",
                            "ACTIVE_POST_FORM", "SUSPECTED");
                }
                String marker = "vscanxss" + Integer.toHexString(
                        Objects.hash(form.action(), parameter.name(), index));
                String xssPayload = "\"><svg data-vscan=\"" + marker + "\">";
                byte[] xssBody = encodeForm(form.parameters(), index, xssPayload);
                if (xssBody == null) {
                    break;
                }
                ScanResponse xssResponse = requestPostTarget(origin, form.action(), xssBody, context);
                if (isPotentialHtml(xssResponse) && containsRaw(xssResponse.body(), xssPayload)
                        && appearsExecutableReflection(xssResponse.body(), marker)) {
                    addFinding(job, keys, "REFLECTED_XSS_POTENTIAL",
                            form.action() + " [" + parameter.name() + "]", "MEDIUM",
                            "The unique test marker was reflected unencoded in an HTML tag context for "
                                    + "allowlisted POST form parameter '" + bounded(parameter.name())
                                    + "'; no script was executed and manual verification is required.",
                            "Encode output for its HTML context and validate input.",
                            "ACTIVE_POST_FORM", "POTENTIAL");
                }
            }
        }
    }

    private byte[] encodeForm(List<FormParameter> parameters, int replacedIndex, String replacement) {
        List<String> encoded = new ArrayList<>(parameters.size());
        for (int index = 0; index < parameters.size(); index++) {
            FormParameter parameter = parameters.get(index);
            String value = index == replacedIndex ? replacement : parameter.value();
            encoded.add(URLEncoder.encode(parameter.name(), StandardCharsets.UTF_8)
                    + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8));
        }
        byte[] body = String.join("&", encoded).getBytes(StandardCharsets.UTF_8);
        return body.length <= MAX_FORM_BODY_BYTES ? body : null;
    }

    private boolean isRedirect(int statusCode) {
        return statusCode == 301 || statusCode == 302 || statusCode == 303
                || statusCode == 307 || statusCode == 308;
    }

    InetAddress[] validateResolvedAddresses(URI uri, Map<String, Set<String>> resolvedAddressesByHost)
            throws IOException, ScanExecutionException {
        if (!uri.isAbsolute() || uri.isOpaque() || uri.getRawAuthority() == null
                || (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme()))) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID, "Only HTTP and HTTPS targets are supported");
        }
        if (uri.getUserInfo() != null || uri.getHost() == null || uri.getHost().isBlank()
                || (uri.getPort() != -1 && (uri.getPort() < 1 || uri.getPort() > 65535))
                || !hasValidRawAuthority(uri)) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID, "Target URL is not safe to scan");
        }
        TargetOriginMapping mapping = localhostTargetOriginMapping(uri);
        String resolutionHost = mapping == null ? uri.getHost() : mapping.destinationOrigin().getHost();
        InetAddress[] addresses = resolveAddresses(resolutionHost);
        if (addresses.length == 0) {
            throw new UnknownHostException("Target did not resolve to an address");
        }
        Set<String> resolvedAddresses = new HashSet<>();
        boolean explicitlyAllowedPrivateTarget = isAllowedPrivateTargetOrigin(uri);
        for (InetAddress address : addresses) {
            boolean unsafeAddress = isUnsafeAddress(address);
            boolean privateAddressNotAllowed = !unsafeAddress
                    && isPrivate(address) && !explicitlyAllowedPrivateTarget;
            if (unsafeAddress || privateAddressNotAllowed) {
                String category = unsafeAddress ? "UNSAFE_ADDRESS" : "PRIVATE_ADDRESS_NOT_ALLOWED";
                String origin = uri.getScheme().toLowerCase(Locale.ROOT) + "://" + uri.getRawAuthority();
                LOG.warn("Target address validation rejected: category={} origin={} address={}",
                        category, origin, address.getHostAddress());
                throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                        "Target resolves to a disallowed network address");
            }
            resolvedAddresses.add(address.getHostAddress().toLowerCase(Locale.ROOT));
        }
        String hostKey = resolutionHost.toLowerCase(Locale.ROOT);
        Set<String> previouslyResolved = resolvedAddressesByHost.putIfAbsent(hostKey, resolvedAddresses);
        if (previouslyResolved != null && !previouslyResolved.equals(resolvedAddresses)) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                    "Target DNS resolution changed during the scan");
        }
        return addresses;
    }

    InetAddress[] resolveAddresses(String host) throws UnknownHostException {
        return InetAddress.getAllByName(host);
    }

    private boolean hasValidRawAuthority(URI uri) {
        String host = uri.getHost();
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        String authorityHost = host.contains(":") ? "[" + host + "]" : host;
        String expected = uri.getPort() == -1 ? authorityHost : authorityHost + ":" + uri.getPort();
        return expected.equalsIgnoreCase(uri.getRawAuthority());
    }


    private boolean isAllowedPrivateTargetOrigin(URI target) {
        if (allowedPrivateTargetOrigins == null || allowedPrivateTargetOrigins.isBlank()) {
            return false;
        }
        int targetPort = target.getPort() == -1
                ? ("https".equalsIgnoreCase(target.getScheme()) ? 443 : 80)
                : target.getPort();
        boolean matchesTarget = false;
        for (String configuredOrigin : allowedPrivateTargetOrigins.split(",")) {
            if (configuredOrigin.isBlank()) {
                continue;
            }
            URI allowedOrigin;
            try {
                allowedOrigin = URI.create(configuredOrigin.trim());
            } catch (IllegalArgumentException exception) {
                throw new IllegalStateException("Invalid scanner.allowed-private-target-origins entry", exception);
            }
            String allowedScheme = allowedOrigin.getScheme();
            int configuredPort = allowedOrigin.getPort();
            if (!allowedOrigin.isAbsolute() || allowedOrigin.getHost() == null ||
                    allowedOrigin.getRawUserInfo() != null ||
                    (allowedOrigin.getRawPath() != null && !allowedOrigin.getRawPath().isEmpty()
                            && !"/".equals(allowedOrigin.getRawPath())) ||
                    allowedOrigin.getRawQuery() != null || allowedOrigin.getRawFragment() != null ||
                    (configuredPort != -1 && (configuredPort < 1 || configuredPort > 65535)) ||
                    (!"http".equalsIgnoreCase(allowedScheme) && !"https".equalsIgnoreCase(allowedScheme))) {
                throw new IllegalStateException(
                        "scanner.allowed-private-target-origins entries must be HTTP(S) origins");
            }
            int allowedPort = allowedOrigin.getPort() == -1
                    ? ("https".equalsIgnoreCase(allowedScheme) ? 443 : 80)
                    : allowedOrigin.getPort();
            if (target.getScheme().equalsIgnoreCase(allowedScheme) &&
                    target.getHost().equalsIgnoreCase(allowedOrigin.getHost()) &&
                    targetPort == allowedPort) {
                matchesTarget = true;
            }
        }
        return matchesTarget;
    }

    private TargetOriginMapping localhostTargetOriginMapping(URI target) {
        if (localhostTargetOriginMapping == null || localhostTargetOriginMapping.isBlank()) {
            return null;
        }
        String[] origins = localhostTargetOriginMapping.split("=", -1);
        if (origins.length != 2) {
            throw new IllegalStateException(
                    "scanner.localhost-target-origin-mapping must contain source=destination origins");
        }
        URI source = parseConfiguredOrigin(origins[0]);
        URI destination = parseConfiguredOrigin(origins[1]);
        if (!"localhost".equalsIgnoreCase(source.getHost())
                || !"host.docker.internal".equalsIgnoreCase(destination.getHost())
                || !source.getScheme().equalsIgnoreCase(destination.getScheme())
                || effectivePort(source) != effectivePort(destination)) {
            throw new IllegalStateException(
                    "scanner.localhost-target-origin-mapping must map localhost to host.docker.internal "
                            + "using the same scheme and port");
        }
        return sameOrigin(target, source) ? new TargetOriginMapping(source, destination) : null;
    }

    private URI parseConfiguredOrigin(String configuredOrigin) {
        URI origin;
        try {
            origin = URI.create(configuredOrigin.trim());
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException(
                    "scanner.localhost-target-origin-mapping contains an invalid origin", exception);
        }
        String scheme = origin.getScheme();
        int port = origin.getPort();
        if (!origin.isAbsolute() || origin.isOpaque() || origin.getRawAuthority() == null
                || origin.getHost() == null || origin.getHost().isBlank()
                || origin.getRawUserInfo() != null
                || (port != -1 && (port < 1 || port > 65535))
                || (origin.getRawPath() != null && !origin.getRawPath().isEmpty()
                        && !"/".equals(origin.getRawPath()))
                || origin.getRawQuery() != null || origin.getRawFragment() != null
                || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))
                || !hasValidRawAuthority(origin)) {
            throw new IllegalStateException(
                    "scanner.localhost-target-origin-mapping entries must be HTTP(S) origins");
        }
        return origin;
    }

    private String targetUrlForOrigin(URI target, TargetOriginMapping mapping) {
        if (mapping == null) {
            return target.toString();
        }
        String targetValue = target.toString();
        int authorityStart = targetValue.indexOf("://") + 3;
        int suffixStart = authorityStart + target.getRawAuthority().length();
        return mapping.destinationOrigin().getScheme() + "://"
                + mapping.destinationOrigin().getRawAuthority() + targetValue.substring(suffixStart);
    }

    private ZapAlert restoreSavedTargetOrigin(ZapAlert alert, URI savedOrigin, URI zapOrigin) {
        if (sameOrigin(savedOrigin, zapOrigin) || alert.url() == null || alert.url().isBlank()) {
            return alert;
        }
        URI alertUri = URI.create(alert.url());
        int schemeSeparator = alert.url().indexOf("://");
        int authorityStart = schemeSeparator + 3;
        int suffixStart = authorityStart + alertUri.getRawAuthority().length();
        String savedUrl = savedOrigin.getScheme() + "://" + savedOrigin.getRawAuthority()
                + alert.url().substring(suffixStart);
        return new ZapAlert(alert.pluginId(), alert.alert(), alert.risk(), alert.confidence(), savedUrl,
                alert.param(), alert.attack(), alert.evidence(), alert.description(), alert.solution(),
                alert.reference(), alert.cweid(), alert.wascid(), alert.id());
    }

    boolean isCloudMetadata(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            return (bytes[0] & 0xff) == 169 && (bytes[1] & 0xff) == 254
                    && (((bytes[2] & 0xff) == 169 && (bytes[3] & 0xff) == 254)
                    || ((bytes[2] & 0xff) == 170 && (bytes[3] & 0xff) == 2));
        }
        byte[] ipv6MetadataAddress = {
                (byte) 0xfd, 0x00, 0x0e, (byte) 0xc2,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x54
        };
        return Arrays.equals(bytes, ipv6MetadataAddress);
    }

    boolean isUnsafeAddress(InetAddress address) {
        if (isCloudMetadata(address) || address.isAnyLocalAddress()
                || address.isLinkLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            long value = ((long) (bytes[0] & 0xff) << 24)
                    | ((long) (bytes[1] & 0xff) << 16)
                    | ((long) (bytes[2] & 0xff) << 8)
                    | (bytes[3] & 0xffL);
            return inIpv4Range(value, 0x00000000L, 8)
                    || inIpv4Range(value, 0x64400000L, 10)
                    || inIpv4Range(value, 0xc0000000L, 24)
                    || inIpv4Range(value, 0xc0000200L, 24)
                    || inIpv4Range(value, 0xc0586300L, 24)
                    || inIpv4Range(value, 0xc6120000L, 15)
                    || inIpv4Range(value, 0xc6336400L, 24)
                    || inIpv4Range(value, 0xcb007100L, 24)
                    || inIpv4Range(value, 0xe0000000L, 4)
                    || inIpv4Range(value, 0xf0000000L, 4);
        }
        if (address.isLoopbackAddress() || isUniqueLocalAddress(address)) {
            return false;
        }
        return !hasIpv6Prefix(bytes, new byte[]{0x20}, 3)
                || hasIpv6Prefix(bytes, new byte[]{0x20, 0x01, 0x0d, (byte) 0xb8}, 32)
                || hasIpv6Prefix(bytes, new byte[]{0x20, 0x01, 0x00}, 23)
                || hasIpv6Prefix(bytes, new byte[]{0x20, 0x02}, 16)
                || hasIpv6Prefix(bytes, new byte[]{0x00, 0x64, (byte) 0xff, (byte) 0x9b}, 96)
                || hasIpv6Prefix(bytes, new byte[]{0x00, 0x64, (byte) 0xff, (byte) 0x9b, 0, 1}, 48)
                || hasIpv6Prefix(bytes, new byte[]{0x01, 0x00}, 64)
                || hasIpv6Prefix(bytes, new byte[]{0x3f, (byte) 0xff}, 20);
    }

    private boolean inIpv4Range(long address, long network, int prefixLength) {
        long mask = 0xffffffffL << (32 - prefixLength) & 0xffffffffL;
        return (address & mask) == (network & mask);
    }

    private boolean hasIpv6Prefix(byte[] address, byte[] network, int prefixLength) {
        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;
        for (int index = 0; index < fullBytes; index++) {
            if (address[index] != network[index]) {
                return false;
            }
        }
        if (remainingBits == 0) {
            return true;
        }
        int mask = 0xff << (8 - remainingBits) & 0xff;
        return ((address[fullBytes] & 0xff) & mask)
                == ((network[fullBytes] & 0xff) & mask);
    }

    private boolean isPrivate(InetAddress address) {
        return address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()
                || isUniqueLocalAddress(address);
    }

    private boolean isUniqueLocalAddress(InetAddress address) {
        byte[] bytes = address.getAddress();
        return bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc;
    }

    private void persistFindings(ScanJob job, ScanResponse response, URI pageUri, Set<String> keys) {
        Map<String, List<String>> headers = response.headers();
        addMissingHeader(job, keys, headers, "MISSING_CONTENT_SECURITY_POLICY", "Content-Security-Policy",
                "MEDIUM", "Content-Security-Policy is absent", "Add a restrictive Content-Security-Policy.", pageUri);
        if ("https".equalsIgnoreCase(pageUri.getScheme())) {
            addMissingHeader(job, keys, response.headers(), "MISSING_STRICT_TRANSPORT_SECURITY", "Strict-Transport-Security",
                    "MEDIUM", "Strict-Transport-Security is absent on an HTTPS response",
                    "Enable HSTS with an appropriate max-age and includeSubDomains policy.", pageUri);
        }
        addMissingHeader(job, keys, response.headers(), "MISSING_CONTENT_TYPE_OPTIONS", "X-Content-Type-Options",
                "LOW", "X-Content-Type-Options is absent", "Send X-Content-Type-Options: nosniff.", pageUri);
        addMissingHeader(job, keys, response.headers(), "MISSING_REFERRER_POLICY", "Referrer-Policy",
                "LOW", "Referrer-Policy is absent", "Set an explicit Referrer-Policy appropriate for the application.", pageUri);
        addMissingHeader(job, keys, response.headers(), "MISSING_PERMISSIONS_POLICY", "Permissions-Policy",
                "LOW", "Permissions-Policy is absent", "Restrict unnecessary browser capabilities with Permissions-Policy.", pageUri);
        if (firstHeader(headers, "x-frame-options") == null && !containsFrameAncestors(headers)) {
            addFinding(job, keys, "MISSING_FRAME_PROTECTION",
                    pageComponent(pageUri, "X-Frame-Options/CSP frame-ancestors"), "MEDIUM",
                    "Neither X-Frame-Options nor CSP frame-ancestors was present",
                    "Use X-Frame-Options or a CSP frame-ancestors directive to prevent framing.");
        }
        for (String cookie : allHeaders(headers, "set-cookie")) {
            CookieObservation observation = parseCookie(cookie);
            if (observation == null) {
                continue;
            }
            if (!observation.secure() && "https".equalsIgnoreCase(pageUri.getScheme())) {
                addCookieFinding(job, keys, "COOKIE_MISSING_SECURE", observation.name(), pageUri,
                        "Set-Cookie '" + bounded(observation.name())
                                + "' was observed on an HTTPS response without the Secure attribute. "
                                + "The cookie value was not retained; this configuration observation does not prove "
                                + "that the cookie is transmitted over an insecure connection.",
                        "Set Secure on cookies that must only travel over HTTPS.");
            }
            if (!observation.httpOnly()) {
                addCookieFinding(job, keys, "COOKIE_MISSING_HTTP_ONLY", observation.name(), pageUri,
                        "Set-Cookie '" + bounded(observation.name())
                                + "' was observed without the HttpOnly attribute. The cookie value was not retained; "
                                + "this observation alone does not establish exploitability, and preference cookies "
                                + "may be intentionally JavaScript-readable.",
                        "Set HttpOnly on cookies that do not need JavaScript access.");
            }
            if (!observation.sameSite()) {
                addCookieFinding(job, keys, "COOKIE_MISSING_SAMESITE", observation.name(), pageUri,
                        "Set-Cookie '" + bounded(observation.name())
                                + "' was observed without a SameSite attribute. The cookie value was not retained; "
                                + "impact depends on cookie purpose and request context.",
                        "Set an explicit SameSite policy appropriate for the application.");
            }
        }
        addDisclosureFinding(job, keys, headers, "Server", pageUri);
        addDisclosureFinding(job, keys, headers, "X-Powered-By", pageUri);
    }

    private void persistParameterFindings(ScanJob job, URI uri, ScanResponse baseline,
                                          ScanContext context) throws ScanExecutionException {
        List<QueryParameter> parameters = queryParameters(uri);
        if (parameters.isEmpty()) {
            return;
        }
        Set<String> keys = new HashSet<>();
        int tested = 0;
        for (QueryParameter parameter : parameters) {
            if (tested++ >= MAX_PARAMETERS_PER_URL || cancellationRequested(job)) {
                break;
            }
            if (isSensitiveParameter(parameter.name())) {
                continue;
            }
            if (!context.canConsumeDetectionRequests(3)) {
                break;
            }
            String sqlTrue = "' OR '1'='1";
            String sqlFalse = "' OR '1'='2";
            ScanResponse sqlPositive = requestParameter(uri, parameter, sqlTrue, context);
            ScanResponse sqlNegative = requestParameter(uri, parameter, sqlFalse, context);
            if (isSqlError(sqlPositive.body()) && !isSqlError(baseline.body())
                    && (isSqlError(sqlNegative.body()) || (sqlPositive.statusCode() >= 500 && baseline.statusCode() < 500))) {
                String errorSnippet = extractSqlErrorSnippet(sqlPositive.body());
                addFinding(job, keys, "SQL_INJECTION_SUSPECTED",
                        uri + " [" + parameter.name() + "]", "HIGH",
                        "Parameter '" + bounded(parameter.name())
                                + "' triggered a database error signature (" + errorSnippet + "); manual verification is required.",
                        "Use parameterized queries and validate input before database access.",
                        "ACTIVE_QUERY_PARAMETER", "SUSPECTED");
            }
            String marker = "vscanxss" + Integer.toHexString(Objects.hash(uri, parameter.name()));
            String xssPayload = "\"><svg data-vscan=\"" + marker + "\">";
            ScanResponse xssResponse = requestParameter(uri, parameter, xssPayload, context);
            if (isPotentialHtml(xssResponse) && containsRaw(xssResponse.body(), xssPayload)
                    && appearsExecutableReflection(xssResponse.body(), marker)) {
                addFinding(job, keys, "REFLECTED_XSS_POTENTIAL",
                        uri + " [" + parameter.name() + "]", "MEDIUM",
                        "The unique test marker was reflected unencoded in an HTML tag context for parameter '"
                                + bounded(parameter.name()) + "'; no script was executed and manual verification is required.",
                        "Encode output for its HTML context and validate input.",
                        "ACTIVE_QUERY_PARAMETER", "POTENTIAL");
            }
        }
    }

    private ScanResponse requestParameter(URI uri, QueryParameter parameter, String value,
                                          ScanContext context) throws ScanExecutionException {
        URI testUri;
        try {
            String[] queryParts = uri.getRawQuery().split("&", -1);
            String encodedName = URLEncoder.encode(parameter.name(), StandardCharsets.UTF_8)
                    .replace("+", "%20");
            String encodedValue = URLEncoder.encode(value, StandardCharsets.UTF_8)
                    .replace("+", "%20");
            queryParts[parameter.rawPartIndex()] = encodedName + "=" + encodedValue;
            String rawPath = uri.getRawPath() == null ? "" : uri.getRawPath();
            testUri = URI.create(uri.getScheme() + "://" + uri.getRawAuthority()
                    + rawPath + "?" + String.join("&", queryParts));
        } catch (IllegalArgumentException exception) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                    "Test parameter URL is not safe to scan");
        }
        return requestTarget(testUri, context, true);
    }

    private List<QueryParameter> queryParameters(URI uri) {
        if (uri.getRawQuery() == null || uri.getRawQuery().isBlank()) {
            return List.of();
        }
        List<QueryParameter> parameters = new ArrayList<>();
        String[] queryParts = uri.getRawQuery().split("&", -1);
        for (int index = 0; index < queryParts.length; index++) {
            String part = queryParts[index];
            String[] pieces = part.split("=", 2);
            try {
                String name = URLDecoder.decode(pieces[0], StandardCharsets.UTF_8);
                String value = pieces.length == 2
                        ? URLDecoder.decode(pieces[1], StandardCharsets.UTF_8) : "";
                if (!name.isBlank() && name.length() <= 100 && value.length() <= 500) {
                    parameters.add(new QueryParameter(name, value, index));
                }
            } catch (IllegalArgumentException ignored) {
                // Malformed query encoding is not a safe candidate for active checks.
            }
        }
        return parameters;
    }

    private boolean isSensitiveParameter(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.contains("password") || lower.contains("passwd") || lower.contains("secret")
                || lower.contains("token") || lower.contains("session") || lower.contains("cookie")
                || lower.contains("auth") || lower.contains("key");
    }

    private boolean isSqlError(byte[] body) {
        String lower = new String(body, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
        return lower.contains("sql syntax") || lower.contains("sqlstate")
                || lower.contains("mysql_fetch") || lower.contains("ora-")
                || lower.contains("sqlite error") || lower.contains("postgresql")
                || lower.contains("odbc sql");
    }

    private boolean containsRaw(byte[] body, String value) {
        return new String(body, StandardCharsets.UTF_8).contains(value);
    }

    private boolean appearsExecutableReflection(byte[] body, String marker) {
        String html = new String(body, StandardCharsets.UTF_8);
        return html.matches("(?s).*<svg\\s+data-vscan=\"" + java.util.regex.Pattern.quote(marker) + "\"[^>]*>.*");
    }

    private void addMissingHeader(ScanJob job, Set<String> keys, Map<String, List<String>> headers, String type,
                                  String header, String severity, String evidence, String remediation, URI pageUri) {
        if (firstHeader(headers, header) == null) {
            addFinding(job, keys, type, pageComponent(pageUri, header), severity, evidence, remediation);
        }
    }

    private String pageComponent(URI pageUri, String component) {
        return pageUri + " [" + component + "]";
    }

    private boolean containsFrameAncestors(Map<String, List<String>> headers) {
        return allHeaders(headers, "content-security-policy").stream()
                .anyMatch(value -> value.toLowerCase(Locale.ROOT).contains("frame-ancestors"));
    }

    private void addDisclosureFinding(ScanJob job, Set<String> keys, Map<String, List<String>> headers, String header,
                                      URI pageUri) {
        for (String value : allHeaders(headers, header.toLowerCase(Locale.ROOT))) {
            if (value.matches(".*\\d.*")) {
                addFinding(job, keys, "INFORMATION_DISCLOSURE_" + header.toUpperCase(Locale.ROOT),
                        pageComponent(pageUri, header), "LOW",
                        header + " exposes a version-bearing value: " + bounded(value),
                        "Remove version details from response headers.");

                if (nvdCveService != null) {
                    NvdCveService.SoftwareVersion sv = nvdCveService.parseSoftwareVersion(value);
                    if (sv != null) {
                        NvdLookupResult lookup = nvdCveService.lookupCves(sv.software(), sv.version());
                        job.recordNvdLookupStatus(lookup.status());
                        for (CveMatch match : lookup.candidates()) {
                            String cveComponent = pageComponent(pageUri,
                                    header + ": " + sv.software() + "/" + sv.version() + " [" + match.cveId() + "]");
                            String cvssEvidence = "UNKNOWN".equals(match.cvssSeverity())
                                    ? "NVD CVSS metrics unavailable."
                                    : String.format("NVD CVSS: %.1f (%s; %s).", match.cvssScore(),
                                            match.cvssSeverity(), match.cvssVector());
                            String cveEvidence = String.format("NVD keyword-search candidate only: '%s' version '%s' disclosed in '%s' was returned with %s. Product and version applicability are not verified. %s %s",
                                    sv.software(), sv.version(), header, match.cveId(), cvssEvidence,
                                    bounded(match.description()));
                            addFinding(job, keys, "CVE_KEYWORD_CANDIDATE", cveComponent, "LOW",
                                    cveEvidence, "Verify product identity and affected-version ranges against the vendor advisory before remediation.",
                                    "NVD_CVE_LOOKUP", "POTENTIAL");
                        }
                    }
                }
            }
        }
    }

    private String extractSqlErrorSnippet(byte[] body) {
        String lower = new String(body, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
        for (String sig : List.of("sql syntax", "sqlstate", "mysql_fetch", "ora-", "sqlite error", "postgresql", "odbc sql")) {
            int idx = lower.indexOf(sig);
            if (idx != -1) {
                int start = Math.max(0, idx - 10);
                int end = Math.min(lower.length(), idx + sig.length() + 20);
                return lower.substring(start, end).trim();
            }
        }
        return "database error signature";
    }

    private boolean isPotentialHtml(ScanResponse response) {
        String contentType = Objects.toString(firstHeader(response.headers(), "content-type"), "");
        String mediaType = contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        if ("application/json".equals(mediaType) || "text/plain".equals(mediaType)
                || "application/javascript".equals(mediaType) || "text/css".equals(mediaType)) {
            return false;
        }
        if ("text/html".equals(mediaType) || "application/xhtml+xml".equals(mediaType)) {
            return true;
        }
        String bodyStart = new String(response.body(), 0, Math.min(response.body().length, 256), StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
        return bodyStart.contains("<html") || bodyStart.contains("<!doctype html") || bodyStart.contains("<body");
    }

    private void addFinding(ScanJob job, Set<String> keys, String type, String component, String severity,
                            String evidence, String remediation) {
        addFinding(job, keys, type, component, severity, evidence, remediation,
                "PASSIVE_HEADERS", "OBSERVED");
    }

    private void addFinding(ScanJob job, Set<String> keys, String type, String component, String severity,
                            String evidence, String remediation, String source, String verificationStatus) {
        String key = type + "|" + component;
        if (keys.add(key)) {
            findingRepository.save(new ScanFinding(job, type, severity,
                    bounded(FindingSanitizer.sanitize(component)),
                    bounded(FindingSanitizer.sanitize(evidence)),
                    "Observed in the target HTTP response",
                    bounded(FindingSanitizer.sanitize(remediation)), source, verificationStatus));
        }
    }

    private boolean cancellationRequested(ScanJob job) {
        if (job.isCancellationRequested()) {
            return true;
        }
        if (job.getId() == null) {
            return false;
        }
        Optional<Boolean> requestedState = scanJobRepository.findCancellationRequestedById(job.getId());
        boolean requested = requestedState != null && requestedState.orElse(false);
        if (requested) {
            job.requestCancellation();
        }
        return requested;
    }

    private boolean cancelIfRequested(ScanJob job, String message) {
        if (!cancellationRequested(job)) {
            return false;
        }
        if (job.getStatus() == ScanStatus.CRAWLING || job.getStatus() == ScanStatus.SCANNING
                || job.getStatus() == ScanStatus.RUNNING) {
            if ("RUNNING".equals(job.getNativeEngineStatus())) {
                job.updateNativeEngineStatus("CANCELLED");
            }
            if ("RUNNING".equals(job.getZapEngineStatus())) {
                job.updateZapEngineStatus("CANCELLED");
                job.updateZapFailureReason("CANCELLED_DURING_ZAP");
                markRunningZapStages(job, "CANCELLED");
            } else if (job.isZapRequested() && "NOT_STARTED".equals(job.getZapEngineStatus())) {
                job.updateZapFailureReason("CANCELLED_BEFORE_ZAP");
            }
            job.transitionTo(ScanStatus.CANCELLED, job.getProgress(), message, null);
            persistExecutionState(job);
            audit(job, "SCAN_JOB_CANCELLED", message);
        }
        return true;
    }

    private void persistExecutionState(ScanJob job) {
        if (transactionTemplate == null || job.getId() == null) {
            scanJobRepository.save(job);
            return;
        }
        ScanJob[] persistedState = new ScanJob[1];
        transactionTemplate.executeWithoutResult(status -> {
            ScanJob persisted = scanJobRepository.findByIdForExecutionUpdate(job.getId())
                    .orElseThrow(() -> new IllegalStateException("Scan job disappeared during execution"));
            persisted.mergeExecutionState(job);
            ScanJob saved = scanJobRepository.save(persisted);
            persistedState[0] = saved == null ? persisted : saved;
        });
        if (persistedState[0] != null) {
            job.copyExecutionStateFrom(persistedState[0]);
        }
    }

    private String bounded(String value) {
        return value.length() <= 1000 ? value : value.substring(0, 997) + "...";
    }

    private void fail(ScanJob job, ScanFailureReason reason, String message) {
        if (job.getStatus() == ScanStatus.RUNNING || job.getStatus() == ScanStatus.CRAWLING
                || job.getStatus() == ScanStatus.SCANNING || job.getStatus() == ScanStatus.QUEUED
                || job.getStatus() == ScanStatus.CREATED) {
            if (job.isZapRequested() && "NOT_STARTED".equals(job.getZapEngineStatus())) {
                job.updateZapFailureReason("SCAN_FAILED_BEFORE_ZAP");
            }
            job.transitionTo(ScanStatus.FAILED, job.getProgress(), message, reason);
            persistExecutionState(job);
            audit(job, job.getStatus() == ScanStatus.FAILED ? "SCAN_JOB_FAILED" : "SCAN_JOB_CANCELLED",
                    job.getStatusMessage());
        }
    }

    private void audit(ScanJob job, String eventType, String message) {
        if (auditEventRepository == null) {
            return;
        }
        AuditEvent event = new AuditEvent();
        event.setEventType(eventType);
        event.setEventLevel("INFO");
        event.setMessage("Scan job " + job.getId() + ": " + message);
        event.setOrganization(job.getOrganization());
        event.setActor(job.getRequestedBy());
        auditEventRepository.save(event);
    }

    private void addCookieFinding(ScanJob job, Set<String> keys, String type, String cookieName, URI pageUri,
                                  String evidence, String remediation) {
        String component = pageComponent(pageUri, "Set-Cookie:" + bounded(cookieName));
        String key = type + "|" + component;
        if (keys.add(key)) {
            findingRepository.save(new ScanFinding(job, type, "LOW",
                    bounded(FindingSanitizer.sanitize(component)),
                    bounded(FindingSanitizer.sanitize(evidence)),
                    "Observed cookie-attribute configuration only; risk depends on cookie purpose and context, "
                            + "and exploitability was not verified.",
                    bounded(FindingSanitizer.sanitize(remediation)), "PASSIVE_HEADERS", "OBSERVED"));
        }
    }

    private CookieObservation parseCookie(String headerValue) {
        String[] parts = headerValue.split(";");
        if (parts.length == 0) {
            return null;
        }
        String[] nameValue = parts[0].trim().split("=", 2);
        if (nameValue.length == 0 || nameValue[0].isBlank()) {
            return null;
        }
        boolean secure = false;
        boolean httpOnly = false;
        boolean sameSite = false;
        for (int index = 1; index < parts.length; index++) {
            String attribute = parts[index].trim();
            int equals = attribute.indexOf('=');
            String attributeName = (equals < 0 ? attribute : attribute.substring(0, equals))
                    .trim().toLowerCase(Locale.ROOT);
            if ("secure".equals(attributeName)) {
                secure = true;
            } else if ("httponly".equals(attributeName)) {
                httpOnly = true;
            } else if ("samesite".equals(attributeName)) {
                sameSite = true;
            }
        }
        return new CookieObservation(nameValue[0].trim(), secure, httpOnly, sameSite);
    }

    private boolean isHtmlDocument(ScanResponse response) {
        String contentType = firstHeader(response.headers(), "content-type");
        return contentType != null && isHtmlContentType(contentType);
    }

    private boolean isHtmlContentType(String contentType) {
        String mediaType = contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        return "text/html".equals(mediaType) || "application/xhtml+xml".equals(mediaType);
    }

    private String firstHeader(Map<String, List<String>> headers, String name) {
        List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
        return values == null || values.isEmpty() ? null : values.getFirst();
    }

    private List<String> allHeaders(Map<String, List<String>> headers, String name) {
        return headers.getOrDefault(name.toLowerCase(Locale.ROOT), List.of());
    }

    private PageDiscovery discoverPage(URI origin, URI base, String contentType, byte[] body) {
        Document document = Jsoup.parse(new String(body, responseCharset(contentType)), base.toString());
        Set<URI> links = new LinkedHashSet<>();
        LinkDiscoveryCounters linkCounters = new LinkDiscoveryCounters();
        List<DiscoveredForm> forms = new ArrayList<>();
        List<PostFormCandidate> postForms = new ArrayList<>();
        for (Element element : document.select("a[href], area[href]")) {
            addSameOriginLink(origin, element.absUrl("href"), links, linkCounters);
        }
        for (Element form : document.select("form")) {
            if (forms.size() >= MAX_DISCOVERED_FORMS_PER_PAGE) {
                break;
            }
            String method = form.attr("method").trim().toUpperCase(Locale.ROOT);
            if (method.isEmpty()) {
                method = "GET";
            }
            if (!method.equals("GET") && !method.equals("POST")) {
                continue;
            }
            String actionUrl = form.hasAttr("action") ? form.absUrl("action") : base.toString();
            LinkValidation actionValidation = validateSameOriginLinkDetailed(origin, actionUrl);
            URI action = actionValidation.uri();
            if (method.equals("GET")) {
                recordLinkCandidate(actionValidation, links, linkCounters);
            }
            if (action == null) {
                continue;
            }
            LinkedHashSet<String> names = new LinkedHashSet<>();
            for (Element field : form.select("input[name], textarea[name], select[name], button[name]")) {
                String name = field.attr("name").trim();
                if (!name.isEmpty()) {
                    names.add(bounded(name));
                }
                if (names.size() >= MAX_FORM_FIELDS) {
                    break;
                }
            }
            forms.add(new DiscoveredForm(action.toString(), method, List.copyOf(names)));
            if (method.equals("POST")) {
                List<FormParameter> parameters = postFormParameters(form);
                if (parameters != null && isConfiguredPostAction(action)) {
                    postForms.add(new PostFormCandidate(action, parameters));
                }
            }
        }
        return new PageDiscovery(List.copyOf(links), List.copyOf(forms), List.copyOf(postForms),
                linkCounters.snapshot());
    }

    private Charset responseCharset(String contentType) {
        if (contentType == null) {
            return StandardCharsets.UTF_8;
        }
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(
                "(?i)(?:^|;)\\s*charset\\s*=\\s*(?:\"([^\"]+)\"|'([^']+)'|([^;\\s]+))")
                .matcher(contentType);
        if (!matcher.find()) {
            return StandardCharsets.UTF_8;
        }
        String charsetName = matcher.group(1) != null ? matcher.group(1)
                : matcher.group(2) != null ? matcher.group(2) : matcher.group(3);
        try {
            return Charset.forName(charsetName);
        } catch (IllegalArgumentException exception) {
            return StandardCharsets.UTF_8;
        }
    }

    private List<FormParameter> postFormParameters(Element form) {
        String enctype = form.attr("enctype").trim();
        if ((!enctype.isEmpty() && !enctype.equalsIgnoreCase("application/x-www-form-urlencoded"))
                || form.hasAttr("target")) {
            return null;
        }
        String acceptCharset = form.attr("accept-charset").trim();
        if (!acceptCharset.isEmpty() && !acceptCharset.equalsIgnoreCase("UTF-8")) {
            return null;
        }
        List<FormParameter> parameters = new ArrayList<>();
        for (Element field : form.select("input[name], textarea[name], select[name], button[name]")) {
            if (field.hasAttr("disabled")) {
                continue;
            }
            String name = field.attr("name").trim();
            if (name.isEmpty() || name.length() > 100 || isUnsafeFormFieldName(name)) {
                return null;
            }
            String value;
            if ("input".equals(field.normalName())) {
                String type = field.attr("type").trim().toLowerCase(Locale.ROOT);
                if (!type.isEmpty() && !type.equals("text") && !type.equals("search")) {
                    return null;
                }
                value = field.attr("value");
            } else if ("textarea".equals(field.normalName())) {
                value = field.text();
            } else {
                return null;
            }
            if (value.length() > 500) {
                return null;
            }
            if (parameters.size() >= MAX_FORM_FIELDS) {
                return null;
            }
            parameters.add(new FormParameter(name, value));
        }
        return parameters.isEmpty() ? null : List.copyOf(parameters);
    }

    private boolean isUnsafeFormFieldName(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return isSensitiveParameter(name)
                || lower.contains("user") || lower.contains("login") || lower.contains("identifier")
                || lower.matches(".*(?:^|[^a-z0-9])pin(?:$|[^a-z0-9]).*")
                || lower.contains("email") || lower.contains("account")
                || lower.contains("role") || lower.contains("admin")
                || lower.contains("delete") || lower.contains("remove") || lower.contains("purchase")
                || lower.contains("checkout") || lower.contains("payment") || lower.contains("transfer");
    }

    private boolean isConfiguredPostAction(URI action) {
        if (action.getRawUserInfo() != null || action.getRawFragment() != null
                || isUnsafePostAction(action)) {
            return false;
        }
        if (activePostFormAllowlist == null || activePostFormAllowlist.isBlank()) {
            return false;
        }
        for (String configured : activePostFormAllowlist.split("\\R")) {
            if (configured.isBlank()) {
                continue;
            }
            try {
                URI configuredUri = URI.create(configured.trim());
                if (configuredUri.getRawUserInfo() != null || configuredUri.getRawFragment() != null) {
                    continue;
                }
                URI allowed = normalize(configuredUri);
                String allowedPath = allowed.getRawPath() == null || allowed.getRawPath().isEmpty()
                        ? "/" : allowed.getRawPath();
                String actionPath = action.getRawPath() == null || action.getRawPath().isEmpty()
                        ? "/" : action.getRawPath();
                if (sameOrigin(allowed, action) && allowedPath.equals(actionPath)
                        && Objects.equals(allowed.getRawQuery(), action.getRawQuery())) {
                    return true;
                }
            } catch (IllegalArgumentException ignored) {
                // Invalid allowlist entries do not authorize a form action.
            }
        }
        return false;
    }

    private boolean isUnsafePostAction(URI action) {
        String path = Objects.toString(action.getRawPath(), "").toLowerCase(Locale.ROOT);
        return path.matches(".*(?:^|[/_-])(?:logout|delete|remove|purchase|checkout|payment|transfer"
                + "|account|profile|password|credential|admin|settings|register|signup|subscribe)"
                + "(?:[/_-]|$).*");
    }

    private URI addSameOriginLink(URI origin, String absoluteUrl, Set<URI> links,
                                  LinkDiscoveryCounters linkCounters) {
        return recordLinkCandidate(validateSameOriginLinkDetailed(origin, absoluteUrl), links, linkCounters);
    }

    private URI recordLinkCandidate(LinkValidation validation, Set<URI> links,
                                    LinkDiscoveryCounters linkCounters) {
        linkCounters.candidateLinks++;
        if (validation.uri() == null) {
            if (validation.rejection() == LinkRejection.CROSS_ORIGIN) {
                linkCounters.rejectedCrossOriginLinks++;
            } else {
                linkCounters.rejectedInvalidLinks++;
            }
            return null;
        }
        if (links.add(validation.uri())) {
            linkCounters.acceptedSameOriginLinks++;
        } else {
            linkCounters.duplicateLinks++;
        }
        return validation.uri();
    }

    private URI validateSameOriginLink(URI origin, String absoluteUrl) {
        return validateSameOriginLinkDetailed(origin, absoluteUrl).uri();
    }

    private LinkValidation validateSameOriginLinkDetailed(URI origin, String absoluteUrl) {
        if (absoluteUrl == null || absoluteUrl.isBlank()) {
            return new LinkValidation(null, LinkRejection.INVALID_URL);
        }
        try {
            URI candidate = normalize(URI.create(absoluteUrl));
            if (sameOrigin(origin, candidate)) {
                return new LinkValidation(candidate, null);
            }
            return new LinkValidation(null, LinkRejection.CROSS_ORIGIN);
        } catch (IllegalArgumentException ignored) {
            // Invalid markup is not a scan failure.
            return new LinkValidation(null, LinkRejection.INVALID_URL);
        }
    }

    private URI normalize(URI uri) {
        String scheme = uri.getScheme() == null ? null : uri.getScheme().toLowerCase(Locale.ROOT);
        String host = uri.getHost();
        if (scheme == null || host == null) {
            throw new IllegalArgumentException("Invalid crawl URL");
        }
        int port = uri.getPort();
        boolean defaultPort = ("http".equals(scheme) && port == 80)
                || ("https".equals(scheme) && port == 443);
        String authority = (uri.getRawUserInfo() == null ? "" : uri.getRawUserInfo() + "@")
                + (host.startsWith("[") && host.endsWith("]")
                    ? host.toLowerCase(Locale.ROOT)
                    : host.contains(":") ? "[" + host.toLowerCase(Locale.ROOT) + "]"
                    : host.toLowerCase(Locale.ROOT))
                + (port == -1 || defaultPort ? "" : ":" + port);
        String rawPath = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        String rawQuery = uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery();
        return URI.create(scheme + "://" + authority + rawPath + rawQuery).normalize();
    }

    private boolean sameOrigin(URI left, URI right) {
        return left.getScheme() != null && right.getScheme() != null
                && left.getHost() != null && right.getHost() != null
                && left.getScheme().equalsIgnoreCase(right.getScheme())
                && left.getHost().equalsIgnoreCase(right.getHost())
                && effectivePort(left) == effectivePort(right);
    }

    private boolean isSameOriginZapAlert(URI origin, ZapAlert alert) {
        if (alert.url() == null || alert.url().isBlank()) {
            return false;
        }
        try {
            URI alertUri = URI.create(alert.url());
            String scheme = alertUri.getScheme();
            int port = alertUri.getPort();
            return alertUri.isAbsolute()
                    && !alertUri.isOpaque()
                    && alertUri.getRawAuthority() != null
                    && alertUri.getHost() != null
                    && !alertUri.getHost().isBlank()
                    && (port == -1 || (port >= 1 && port <= 65535))
                    && ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
                    && alertUri.getRawUserInfo() == null
                    && hasValidRawAuthority(alertUri)
                    && sameOrigin(origin, alertUri);
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private int effectivePort(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private int requirePositive(int value, String property) {
        if (value < 1) {
            throw new IllegalArgumentException(property + " must be positive");
        }
        return value;
    }

    private record CrawlRequest(URI uri, int depth) {}
    private record CrawlResult(List<CrawledPage> pages, int discoveredPageCount, int visitedPageCount) {}
    private record CrawledPage(URI uri, ScanResponse response) {}
    private record TargetOriginMapping(URI sourceOrigin, URI destinationOrigin) {}
    private record PageDiscovery(List<URI> links, List<DiscoveredForm> forms,
                                 List<PostFormCandidate> postForms, LinkDiscoveryStats linkStats) {}
    private record LinkDiscoveryStats(int candidateLinks, int acceptedSameOriginLinks,
                                      int rejectedCrossOriginLinks, int rejectedInvalidLinks,
                                      int duplicateLinks) {
        private static final LinkDiscoveryStats EMPTY = new LinkDiscoveryStats(0, 0, 0, 0, 0);
    }
    private static final class LinkDiscoveryCounters {
        private int candidateLinks;
        private int acceptedSameOriginLinks;
        private int rejectedCrossOriginLinks;
        private int rejectedInvalidLinks;
        private int duplicateLinks;

        private LinkDiscoveryStats snapshot() {
            return new LinkDiscoveryStats(candidateLinks, acceptedSameOriginLinks,
                    rejectedCrossOriginLinks, rejectedInvalidLinks, duplicateLinks);
        }
    }
    private enum LinkRejection { CROSS_ORIGIN, INVALID_URL }
    private record LinkValidation(URI uri, LinkRejection rejection) {}
    private record PostFormCandidate(URI action, List<FormParameter> parameters) {}
    private record FormParameter(String name, String value) {}
    private record ScanResponse(int statusCode, Map<String, List<String>> headers, byte[] body, URI finalUri) {}
    private record QueryParameter(String name, String value, int rawPartIndex) {}
    private record FindingDeduplicationKey(String detectionSource, String checkType, String sourceRuleId,
                                           String affectedComponent, String evidence, String severity,
                                           String verificationStatus, String sourceConfidence, String sourceReference,
                                           String sourceCweId, String sourceWascId) {}
    private record CookieObservation(String name, boolean secure, boolean httpOnly, boolean sameSite) {}

    private static final class ScanContext {
        private final Map<String, Set<String>> resolvedAddressesByHost = new HashMap<>();
        private final int maxRequests;
        private final int maxDetectionRequests;
        private int requestCount;
        private int detectionRequestCount;

        private ScanContext(int maxRequests, int maxDetectionRequests,
                            Map<String, Set<String>> resolvedAddressesByHost) {
            this.maxRequests = maxRequests;
            this.maxDetectionRequests = maxDetectionRequests;
            this.resolvedAddressesByHost.putAll(resolvedAddressesByHost);
        }

        private boolean tryConsumeRequest(boolean detectionRequest) throws ScanExecutionException {
            if (requestCount >= maxRequests + maxDetectionRequests
                    || (detectionRequest && detectionRequestCount >= maxDetectionRequests)) {
                throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED,
                        "Request budget is exhausted");
            }
            requestCount++;
            if (detectionRequest) {
                detectionRequestCount++;
            }
            return true;
        }

        private Map<String, Set<String>> resolvedAddressesByHost() {
            return resolvedAddressesByHost;
        }

        private boolean canConsumeDetectionRequests(int requested) {
            return detectionRequestCount + requested <= maxDetectionRequests
                    && requestCount + requested <= maxRequests + maxDetectionRequests;
        }
    }

    static final class ScanExecutionException extends Exception {
        private final ScanFailureReason reason;
        private ScanExecutionException(ScanFailureReason reason, String message) {
            super(message);
            this.reason = reason;
        }
        private ScanFailureReason reason() {
            return reason;
        }
    }
}
