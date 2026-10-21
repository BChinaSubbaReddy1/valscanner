package com.vulnscanner.application.scan;

import com.vulnscanner.application.target.Target;
import com.vulnscanner.application.target.TargetStatus;
import com.vulnscanner.application.audit.AuditEvent;
import com.vulnscanner.application.audit.AuditEventRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ScanExecutionService {
    private static final int MAX_RESPONSE_BYTES = 1_048_576;
    private static final int MAX_PARAMETERS_PER_URL = 3;
    private static final int MAX_CRAWL_DEPTH = 2;
    private static final int DEFAULT_MAX_REQUESTS = 10;
    private static final int DEFAULT_MAX_DETECTION_REQUESTS = 6;
    private static final int DEFAULT_REQUEST_TIMEOUT_SECONDS = 15;
    private static final Set<Long> CLAIMED = ConcurrentHashMap.newKeySet();

    private final ScanJobRepository scanJobRepository;
    private final ScanFindingRepository findingRepository;
    private final boolean allowPrivateTargets;
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
    private final boolean zapFallbackToNative;

    @org.springframework.beans.factory.annotation.Autowired
    public ScanExecutionService(ScanJobRepository scanJobRepository,
                                ScanFindingRepository findingRepository,
                                @Value("${scanner.allow-private-targets:false}") boolean allowPrivateTargets,
                                TransactionTemplate transactionTemplate,
                                AuditEventRepository auditEventRepository,
                                ScanCrawlPageRepository crawlPageRepository,
                                @Value("${scanner.max-requests:10}") int maxRequests,
                                @Value("${scanner.max-detection-requests:6}") int maxDetectionRequests,
                                @Value("${scanner.request-timeout-seconds:15}") int requestTimeoutSeconds,
                                org.springframework.beans.factory.ObjectProvider<NvdCveService> nvdCveServiceProvider,
                                org.springframework.beans.factory.ObjectProvider<ZapClientService> zapClientServiceProvider,
                                org.springframework.beans.factory.ObjectProvider<ZapScanAdapter> zapScanAdapterProvider,
                                @Value("${scanner.zap.fallback-to-native:true}") boolean zapFallbackToNative) {
        this(scanJobRepository, findingRepository, allowPrivateTargets, transactionTemplate,
                auditEventRepository, crawlPageRepository, maxRequests, maxDetectionRequests,
                requestTimeoutSeconds, null,
                nvdCveServiceProvider != null ? nvdCveServiceProvider.getIfAvailable() : null,
                zapClientServiceProvider != null ? zapClientServiceProvider.getIfAvailable() : null,
                zapScanAdapterProvider != null ? zapScanAdapterProvider.getIfAvailable() : null,
                zapFallbackToNative);
    }

    public ScanExecutionService(ScanJobRepository scanJobRepository,
                                ScanFindingRepository findingRepository,
                                @Value("${scanner.allow-private-targets:false}") boolean allowPrivateTargets,
                                TransactionTemplate transactionTemplate,
                                AuditEventRepository auditEventRepository,
                                ScanCrawlPageRepository crawlPageRepository,
                                @Value("${scanner.max-requests:10}") int maxRequests,
                                @Value("${scanner.max-detection-requests:6}") int maxDetectionRequests,
                                @Value("${scanner.request-timeout-seconds:15}") int requestTimeoutSeconds) {
        this(scanJobRepository, findingRepository, allowPrivateTargets, transactionTemplate,
                auditEventRepository, crawlPageRepository, maxRequests, maxDetectionRequests,
                requestTimeoutSeconds, null, null, null, null, true);
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
                requestTimeoutSeconds, httpClient, nvdCveService, null, null, true);
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
                                boolean zapFallbackToNative) {
        this.scanJobRepository = scanJobRepository;
        this.findingRepository = findingRepository;
        this.allowPrivateTargets = allowPrivateTargets;
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
        this.zapFallbackToNative = zapFallbackToNative;
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
            transactionTemplate.executeWithoutResult(status -> runClaimed(scanId));
        } finally {
            CLAIMED.remove(scanId);
        }
    }

    protected void runClaimed(Long scanId) {
        ScanJob job = scanJobRepository.findByIdForExecutionUpdate(scanId).orElse(null);
        if (job == null || (job.getStatus() != ScanStatus.QUEUED && job.getStatus() != ScanStatus.CREATED)
                || job.isCancellationRequested()) {
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
            if (job.getScanType() == ScanType.ZAP_PASSIVE || job.getScanType() == ScanType.ZAP_ACTIVE) {
                runZapScan(job);
            } else {
                runNativeScan(job);
            }
        } catch (ScanExecutionException exception) {
            fail(job, exception.reason(), exception.getMessage());
        } catch (Exception exception) {
            fail(job, ScanFailureReason.OUTBOUND_REQUEST_FAILED, "Scan could not inspect the target");
        }
    }

    private void runNativeScan(ScanJob job) throws ScanExecutionException {
        if (job.getStatus() == ScanStatus.CREATED) {
            job.transitionTo(ScanStatus.QUEUED, 0, "Queued for passive scanning", null);
            scanJobRepository.saveAndFlush(job);
        }
        job.transitionTo(ScanStatus.CRAWLING, 10, "Discovering same-origin pages", null);
        scanJobRepository.saveAndFlush(job);

        CrawlResult crawl = crawl(job);
        if (job.isCancellationRequested()) {
            job.transitionTo(ScanStatus.CANCELLED, job.getProgress(), "Scan cancelled during execution", null);
            scanJobRepository.save(job);
            audit(job, "SCAN_JOB_CANCELLED", "Scan cancelled during execution");
            return;
        }
        job.transitionTo(ScanStatus.SCANNING, 70, "Running passive response checks", null);
        scanJobRepository.saveAndFlush(job);
        persistFindings(job, crawl.initialResponse());
        job.transitionTo(ScanStatus.COMPLETED, 100, "Passive header scan completed", null);
        scanJobRepository.save(job);
        audit(job, "SCAN_JOB_COMPLETED", "Passive header scan completed");
    }

    private void runZapScan(ScanJob job) throws ScanExecutionException {
        // Enforce SSRF validation before contacting ZAP or dispatching scan
        URI origin;
        try {
            origin = new URI(job.getTarget().getUrl());
            validateResolvedAddresses(origin, new HashMap<>());
        } catch (URISyntaxException | UnknownHostException exception) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID, "Target URL is not safe to scan");
        } catch (IOException exception) {
            throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED, "Target could not be resolved");
        }

        if (zapClientService == null || !zapClientService.isAvailable()) {
            if (zapFallbackToNative) {
                audit(job, "ZAP_FALLBACK_TO_NATIVE", "OWASP ZAP is unavailable; falling back to native scanner");
                runNativeScan(job);
                return;
            } else {
                throw new ScanExecutionException(ScanFailureReason.EXECUTOR_UNAVAILABLE, "OWASP ZAP service is unavailable");
            }
        }

        if (job.getStatus() == ScanStatus.CREATED) {
            job.transitionTo(ScanStatus.QUEUED, 0, "Queued for OWASP ZAP scanning", null);
            scanJobRepository.saveAndFlush(job);
        }

        String targetUrl = job.getTarget().getUrl();
        String spiderScanId = null;
        String activeScanId = null;

        try {
            // Spider phase
            job.transitionTo(ScanStatus.CRAWLING, 10, "OWASP ZAP spider discovering pages", null);
            scanJobRepository.saveAndFlush(job);
            spiderScanId = zapClientService.startSpider(targetUrl);

            int spiderProgress = 0;
            int pollCount = 0;
            while (spiderProgress < 100 && pollCount < 60) {
                if (job.isCancellationRequested()) {
                    zapClientService.stopSpider(spiderScanId);
                    job.transitionTo(ScanStatus.CANCELLED, job.getProgress(), "Scan cancelled during ZAP spider", null);
                    scanJobRepository.save(job);
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
                int calculatedProgress = Math.max(job.getProgress(), 10 + (int) (spiderProgress * 0.35)); // 10% -> 45%
                job.updateProgress(calculatedProgress, "OWASP ZAP spider discovering pages (" + spiderProgress + "%)");
                scanJobRepository.save(job);
                pollCount++;
            }

            // Active Scan phase if requested
            if (job.getScanType() == ScanType.ZAP_ACTIVE) {
                job.transitionTo(ScanStatus.SCANNING, 50, "OWASP ZAP running active vulnerability scan", null);
                scanJobRepository.saveAndFlush(job);
                activeScanId = zapClientService.startActiveScan(targetUrl);

                int ascanProgress = 0;
                pollCount = 0;
                while (ascanProgress < 100 && pollCount < 120) {
                    if (job.isCancellationRequested()) {
                        zapClientService.stopActiveScan(activeScanId);
                        job.transitionTo(ScanStatus.CANCELLED, job.getProgress(), "Scan cancelled during ZAP active scan", null);
                        scanJobRepository.save(job);
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
                    int calculatedProgress = Math.max(job.getProgress(), 50 + (int) (ascanProgress * 0.35)); // 50% -> 85%
                    job.updateProgress(calculatedProgress, "OWASP ZAP active vulnerability scan (" + ascanProgress + "%)");
                    scanJobRepository.save(job);
                    pollCount++;
                }
            } else {
                job.transitionTo(ScanStatus.SCANNING, 70, "OWASP ZAP passive alerts processing", null);
                scanJobRepository.saveAndFlush(job);
            }

            // Process alerts
            List<ZapAlert> alerts = zapClientService.getAlerts(targetUrl);
            persistZapFindings(job, alerts);

            job.transitionTo(ScanStatus.COMPLETED, 100, "OWASP ZAP scan completed successfully", null);
            scanJobRepository.save(job);
            audit(job, "SCAN_JOB_COMPLETED", "OWASP ZAP scan completed successfully");
        } catch (IOException e) {
            throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED, "OWASP ZAP API communication error");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScanExecutionException(ScanFailureReason.TIME_BUDGET_EXCEEDED, "Scan interrupted");
        }
    }

    private void persistZapFindings(ScanJob job, List<ZapAlert> alerts) {
        if (alerts == null || alerts.isEmpty()) {
            return;
        }
        Set<String> existingKeys = new HashSet<>();
        List<ScanFinding> existingFindings = findingRepository.findByScanJob_Id(job.getId());
        if (existingFindings != null) {
            for (ScanFinding f : existingFindings) {
                existingKeys.add(f.getCheckType() + "|" + f.getAffectedComponent());
            }
        }

        for (ZapAlert alert : alerts) {
            ScanFinding candidate = zapScanAdapter.toFinding(job, alert);
            String key = candidate.getCheckType() + "|" + candidate.getAffectedComponent();
            if (existingKeys.add(key)) {
                findingRepository.save(candidate);
            }
        }
    }

    public void markRejected(Long scanId) {
        transactionTemplate.executeWithoutResult(status -> {
            ScanJob job = scanJobRepository.findById(scanId).orElse(null);
            if (job != null && job.getStatus() == ScanStatus.QUEUED) {
                fail(job, ScanFailureReason.EXECUTOR_UNAVAILABLE, "Scan queue is full; try again later");
            }
        });
    }

    private CrawlResult crawl(ScanJob job) throws ScanExecutionException {
        URI origin;
        try {
            origin = new URI(job.getTarget().getUrl());
        } catch (URISyntaxException exception) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID, "Target URL is not safe to scan");
        }
        Deque<CrawlRequest> queue = new ArrayDeque<>();
        Set<URI> visited = new LinkedHashSet<>();
        ScanContext context = new ScanContext(maxRequests, maxDetectionRequests);
        queue.add(new CrawlRequest(origin, 0));
        ScanResponse initial = null;
        while (!queue.isEmpty() && visited.size() < maxRequests) {
            if (job.isCancellationRequested()) {
                break;
            }
            CrawlRequest next = queue.removeFirst();
            URI uri = normalize(next.uri());
            if (!sameOrigin(origin, uri) || !visited.add(uri)) {
                continue;
            }
            ScanResponse response = requestTarget(uri, context, false);
            if (initial == null) {
                initial = response;
            }
            boolean htmlDocument = isHtmlDocument(response);
            List<URI> links = htmlDocument ? discoverLinks(origin, uri, response.body()) : List.of();
            if (!job.isCancellationRequested() && crawlPageRepository != null && htmlDocument) {
                crawlPageRepository.save(new ScanCrawlPage(job, uri.toString(), next.depth(),
                        response.statusCode(), response.body().length, links.size()));
            }
            if (!job.isCancellationRequested()) {
                persistParameterFindings(job, uri, response, context);
            }
            if (next.depth() < MAX_CRAWL_DEPTH) {
                links.stream().map(link -> new CrawlRequest(link, next.depth() + 1))
                        .forEach(queue::addLast);
            }
        }
        if (initial == null) {
            throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED,
                    "Target response could not be inspected");
        }
        return new CrawlResult(initial, visited.size());
    }

    private ScanResponse requestTarget(URI uri, ScanContext context, boolean detectionRequest)
            throws ScanExecutionException {
        try {
            validateResolvedAddresses(uri, context.resolvedAddressesByHost());
        } catch (UnknownHostException exception) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID, "Target URL is not safe to scan");
        } catch (IOException exception) {
            throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED, "Target could not be resolved");
        }

        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(requestTimeout)
                .header("User-Agent", "Automated-Web-Scanner-Passive/1.0")
                .GET().build();
        try {
            if (!context.tryConsumeRequest(detectionRequest)) {
                throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED, "Request budget is exhausted");
            }
            HttpResponse<InputStream> response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
            byte[] body = readBounded(response.body());
            return new ScanResponse(response.statusCode(), response.headers(), body);
        } catch (java.net.http.HttpTimeoutException exception) {
            throw new ScanExecutionException(ScanFailureReason.TIME_BUDGET_EXCEEDED, "Target request timed out");
        } catch (IOException exception) {
            throw new ScanExecutionException(ScanFailureReason.OUTBOUND_REQUEST_FAILED, "Target request failed");
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new ScanExecutionException(ScanFailureReason.TIME_BUDGET_EXCEEDED, "Scan interrupted");
        }
    }

    private byte[] readBounded(InputStream input) throws IOException, ScanExecutionException {
        try (InputStream body = input) {
            byte[] buffer = new byte[8192];
            int total = 0;
            int read;
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            while ((read = body.read(buffer)) != -1) {
                total += read;
                if (total > MAX_RESPONSE_BYTES) {
                    throw new ScanExecutionException(ScanFailureReason.RESPONSE_LIMIT_EXCEEDED,
                            "Target response exceeded the permitted size");
                }
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }

    private void validateResolvedAddresses(URI uri, Map<String, Set<String>> resolvedAddressesByHost)
            throws IOException, UnknownHostException, ScanExecutionException {
        if (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme())) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID, "Only HTTP and HTTPS targets are supported");
        }
        if (uri.getUserInfo() != null || uri.getHost() == null || uri.getHost().isBlank()
                || (uri.getPort() != -1 && (uri.getPort() < 1 || uri.getPort() > 65535))) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID, "Target URL is not safe to scan");
        }
        InetAddress[] addresses = InetAddress.getAllByName(uri.getHost());
        Set<String> resolvedAddresses = new HashSet<>();
        for (InetAddress address : addresses) {
            if (isCloudMetadata(address) || (!allowPrivateTargets && isPrivate(address))) {
                throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                        "Target resolves to a disallowed network address");
            }
            resolvedAddresses.add(address.getHostAddress().toLowerCase(Locale.ROOT));
        }
        String hostKey = uri.getHost().toLowerCase(Locale.ROOT);
        Set<String> previouslyResolved = resolvedAddressesByHost.putIfAbsent(hostKey, resolvedAddresses);
        if (previouslyResolved != null && !previouslyResolved.equals(resolvedAddresses)) {
            throw new ScanExecutionException(ScanFailureReason.TARGET_URL_INVALID,
                    "Target DNS resolution changed during the scan");
        }
    }

    private boolean isCloudMetadata(InetAddress address) {
        String hostAddress = address.getHostAddress();
        return "169.254.169.254".equals(hostAddress)
                || "169.254.170.2".equals(hostAddress)
                || "fd00:ec2::254".equalsIgnoreCase(hostAddress);
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

    private void persistFindings(ScanJob job, ScanResponse response) {
        Set<String> keys = new HashSet<>();
        java.net.http.HttpHeaders headers = response.headers();
        addMissingHeader(job, keys, headers, "MISSING_CONTENT_SECURITY_POLICY", "Content-Security-Policy",
                "MEDIUM", "Content-Security-Policy is absent", "Add a restrictive Content-Security-Policy.");
        if ("https".equalsIgnoreCase(job.getTarget().getUrl().split(":", 2)[0])) {
            addMissingHeader(job, keys, response.headers(), "MISSING_STRICT_TRANSPORT_SECURITY", "Strict-Transport-Security",
                    "MEDIUM", "Strict-Transport-Security is absent on an HTTPS response",
                    "Enable HSTS with an appropriate max-age and includeSubDomains policy.");
        }
        addMissingHeader(job, keys, response.headers(), "MISSING_CONTENT_TYPE_OPTIONS", "X-Content-Type-Options",
                "LOW", "X-Content-Type-Options is absent", "Send X-Content-Type-Options: nosniff.");
        addMissingHeader(job, keys, response.headers(), "MISSING_REFERRER_POLICY", "Referrer-Policy",
                "LOW", "Referrer-Policy is absent", "Set an explicit Referrer-Policy appropriate for the application.");
        addMissingHeader(job, keys, response.headers(), "MISSING_PERMISSIONS_POLICY", "Permissions-Policy",
                "LOW", "Permissions-Policy is absent", "Restrict unnecessary browser capabilities with Permissions-Policy.");
        if (headers.firstValue("X-Frame-Options").isEmpty() && !containsFrameAncestors(headers)) {
            addFinding(job, keys, "MISSING_FRAME_PROTECTION", "X-Frame-Options/CSP frame-ancestors", "MEDIUM",
                    "Neither X-Frame-Options nor CSP frame-ancestors was present",
                    "Use X-Frame-Options or a CSP frame-ancestors directive to prevent framing.");
        }
        for (String cookie : headers.allValues("Set-Cookie")) {
            CookieObservation observation = parseCookie(cookie);
            if (observation == null) {
                continue;
            }
            if (!observation.secure()) {
                addCookieFinding(job, keys, "COOKIE_MISSING_SECURE", observation.name(),
                        "MEDIUM", "Set-Cookie '" + bounded(observation.name())
                                + "' was observed without the Secure attribute.",
                        "Set Secure on cookies that must only travel over HTTPS.");
            }
            if (!observation.httpOnly()) {
                addCookieFinding(job, keys, "COOKIE_MISSING_HTTP_ONLY", observation.name(),
                        "MEDIUM", "Set-Cookie '" + bounded(observation.name())
                                + "' was observed without the HttpOnly attribute. "
                                + "This observation alone does not verify exploitability; "
                                + "some application preferences are intentionally JavaScript-readable.",
                        "Set HttpOnly on cookies that do not need JavaScript access.");
            }
            if (!observation.sameSite()) {
                addCookieFinding(job, keys, "COOKIE_MISSING_SAMESITE", observation.name(),
                        "LOW", "Set-Cookie '" + bounded(observation.name())
                                + "' was observed without a SameSite attribute.",
                        "Set an explicit SameSite policy appropriate for the application.");
            }
        }
        addDisclosureFinding(job, keys, headers, "Server");
        addDisclosureFinding(job, keys, headers, "X-Powered-By");
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
            if (tested++ >= MAX_PARAMETERS_PER_URL || job.isCancellationRequested()) {
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
            String query = parameter.name() + "=" + value;
            testUri = new URI(uri.getScheme(), uri.getRawAuthority(), uri.getPath(), query, null);
        } catch (URISyntaxException exception) {
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
        for (String part : uri.getRawQuery().split("&", -1)) {
            String[] pieces = part.split("=", 2);
            try {
                String name = URLDecoder.decode(pieces[0], StandardCharsets.UTF_8);
                String value = pieces.length == 2
                        ? URLDecoder.decode(pieces[1], StandardCharsets.UTF_8) : "";
                if (!name.isBlank() && name.length() <= 100 && value.length() <= 500) {
                    parameters.add(new QueryParameter(name, value));
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

    private void addMissingHeader(ScanJob job, Set<String> keys, java.net.http.HttpHeaders headers, String type,
                                  String header, String severity, String evidence, String remediation) {
        if (headers.firstValue(header).isEmpty()) {
            addFinding(job, keys, type, header, severity, evidence, remediation);
        }
    }

    private boolean containsFrameAncestors(java.net.http.HttpHeaders headers) {
        return headers.allValues("Content-Security-Policy").stream()
                .anyMatch(value -> value.toLowerCase(Locale.ROOT).contains("frame-ancestors"));
    }

    private void addDisclosureFinding(ScanJob job, Set<String> keys, java.net.http.HttpHeaders headers, String header) {
        for (String value : headers.allValues(header)) {
            if (value.matches(".*\\d.*")) {
                addFinding(job, keys, "INFORMATION_DISCLOSURE_" + header.toUpperCase(Locale.ROOT),
                        header, "LOW", header + " exposes a version-bearing value: " + bounded(value),
                        "Remove version details from response headers.");

                if (nvdCveService != null) {
                    NvdCveService.SoftwareVersion sv = nvdCveService.parseSoftwareVersion(value);
                    if (sv != null) {
                        List<CveMatch> matches = nvdCveService.findCves(sv.software(), sv.version());
                        for (CveMatch match : matches) {
                            String cveComponent = header + ": " + sv.software() + "/" + sv.version() + " [" + match.cveId() + "]";
                            String cveEvidence = String.format("Software '%s' version '%s' disclosed in '%s' matches %s (CVSS score: %.1f, severity: %s, vector: %s): %s",
                                    sv.software(), sv.version(), header, match.cveId(), match.cvssScore(), match.cvssSeverity(), match.cvssVector(), bounded(match.description()));
                            String localSeverity = mapCvssToLocalSeverity(match.cvssScore(), match.cvssSeverity());
                            addFinding(job, keys, "KNOWN_VULNERABILITY_CVE", cveComponent, localSeverity,
                                    cveEvidence, "Upgrade " + sv.software() + " to a supported, patched version.",
                                    "NVD_CVE_LOOKUP", "POTENTIAL");
                        }
                    }
                }
            }
        }
    }

    private String mapCvssToLocalSeverity(double cvssScore, String cvssSeverity) {
        if ("CRITICAL".equalsIgnoreCase(cvssSeverity) || cvssScore >= 9.0) {
            return "HIGH";
        }
        if ("HIGH".equalsIgnoreCase(cvssSeverity) || cvssScore >= 7.0) {
            return "HIGH";
        }
        if ("MEDIUM".equalsIgnoreCase(cvssSeverity) || cvssScore >= 4.0) {
            return "MEDIUM";
        }
        return "LOW";
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
        String contentType = response.headers().firstValue("Content-Type").orElse("");
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
                "PASSIVE_HEADERS", "VERIFIED");
    }

    private void addFinding(ScanJob job, Set<String> keys, String type, String component, String severity,
                            String evidence, String remediation, String source, String verificationStatus) {
        String key = type + "|" + component;
        if (keys.add(key)) {
            findingRepository.save(new ScanFinding(job, type, severity,
                    bounded(component), bounded(evidence), "Observed in the target HTTP response",
                    bounded(remediation), source, verificationStatus));
        }
    }

    private String bounded(String value) {
        return value.length() <= 1000 ? value : value.substring(0, 997) + "...";
    }

    private void fail(ScanJob job, ScanFailureReason reason, String message) {
        if (job.getStatus() == ScanStatus.RUNNING || job.getStatus() == ScanStatus.CRAWLING
                || job.getStatus() == ScanStatus.SCANNING || job.getStatus() == ScanStatus.QUEUED
                || job.getStatus() == ScanStatus.CREATED) {
            job.transitionTo(ScanStatus.FAILED, job.getProgress(), message, reason);
            scanJobRepository.save(job);
            audit(job, "SCAN_JOB_FAILED", message);
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

    private void addCookieFinding(ScanJob job, Set<String> keys, String type, String cookieName,
                                  String severity, String evidence, String remediation) {
        addFinding(job, keys, type, "Set-Cookie:" + cookieName, severity, evidence, remediation,
                "PASSIVE_HEADERS", "OBSERVED");
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
        return response.headers().firstValue("Content-Type")
                .map(value -> {
                    String mediaType = value.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
                    return "text/html".equals(mediaType) || "application/xhtml+xml".equals(mediaType);
                })
                .orElse(false);
    }

    private List<URI> discoverLinks(URI origin, URI base, byte[] body) {
        String html = new String(body, java.nio.charset.StandardCharsets.UTF_8);
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("(?i)\\b(?:href|action)\\s*=\\s*[\"']([^\"'#]+)")
                .matcher(html);
        List<URI> links = new ArrayList<>();
        while (matcher.find()) {
            try {
                URI candidate = normalize(base.resolve(matcher.group(1)));
                if (sameOrigin(origin, candidate)) {
                    links.add(candidate);
                }
            } catch (IllegalArgumentException ignored) {
                // Invalid markup is not a scan failure.
            }
        }
        return links;
    }

    private URI normalize(URI uri) {
        try {
            String scheme = uri.getScheme() == null ? null : uri.getScheme().toLowerCase(Locale.ROOT);
            String host = uri.getHost() == null ? null : uri.getHost().toLowerCase(Locale.ROOT);
            return new URI(scheme, uri.getUserInfo(), host, uri.getPort(), uri.getPath(),
                    uri.getQuery(), null).normalize();
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException("Invalid crawl URL", exception);
        }
    }

    private boolean sameOrigin(URI left, URI right) {
        return left.getScheme() != null && right.getScheme() != null
                && left.getHost() != null && right.getHost() != null
                && left.getScheme().equalsIgnoreCase(right.getScheme())
                && left.getHost().equalsIgnoreCase(right.getHost())
                && effectivePort(left) == effectivePort(right);
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
    private record CrawlResult(ScanResponse initialResponse, int requestCount) {}
    private record ScanResponse(int statusCode, java.net.http.HttpHeaders headers, byte[] body) {}
    private record QueryParameter(String name, String value) {}
    private record CookieObservation(String name, boolean secure, boolean httpOnly, boolean sameSite) {}

    private static final class ScanContext {
        private final Map<String, Set<String>> resolvedAddressesByHost = new HashMap<>();
        private final int maxRequests;
        private final int maxDetectionRequests;
        private int requestCount;
        private int detectionRequestCount;

        private ScanContext(int maxRequests, int maxDetectionRequests) {
            this.maxRequests = maxRequests;
            this.maxDetectionRequests = maxDetectionRequests;
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

    private static final class ScanExecutionException extends Exception {
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
