package com.vulnscanner.application.scan;

import com.vulnscanner.application.common.UrlSanitizer;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@Service
public class ScanAnalyticsService {
    private static final int MAX_ENDPOINTS = 100;
    private static final int HISTORY_SCAN_LIMIT = 100;
    private static final String UNKNOWN_ENDPOINT = "\u0000";

    private final ScanService scanService;
    private final ScanFindingRepository findingRepository;
    private final ScanCrawlPageRepository crawlPageRepository;
    private final ScanJobRepository scanJobRepository;

    public ScanAnalyticsService(ScanService scanService,
                                ScanFindingRepository findingRepository,
                                ScanCrawlPageRepository crawlPageRepository,
                                ScanJobRepository scanJobRepository) {
        this.scanService = scanService;
        this.findingRepository = findingRepository;
        this.crawlPageRepository = crawlPageRepository;
        this.scanJobRepository = scanJobRepository;
    }

    @Transactional(readOnly = true)
    public ScanAnalyticsResponse analyze(Long scanId) {
        ScanJob job = scanService.accessibleJobForAnalytics(scanId);
        Long organizationId = job.getOrganization().getId();
        Map<String, EndpointAccumulator> endpoints = new LinkedHashMap<>();
        Map<FindingFingerprint, FindingBucket> uniqueFindingBuckets = new LinkedHashMap<>();
        Map<String, Long> severities = new HashMap<>();
        Map<String, Long> findingTypes = new HashMap<>();
        Map<String, Long> detectionSources = new HashMap<>();
        Map<String, Long> findingRules = new HashMap<>();
        Map<String, Long> owaspCategories = new HashMap<>();
        long rawFindingObservations = 0;

        for (Object[] row : findingRepository.groupAnalyticsByScan(scanId, organizationId)) {
            String endpoint = normalizeEndpoint((String) row[0]);
            String endpointKey = endpoint == null ? UNKNOWN_ENDPOINT : endpoint;
            String severity = metricValue(row[1], "UNKNOWN");
            String type = metricValue(row[2], "UNKNOWN");
            String source = metricValue(row[3], "UNKNOWN");
            String ruleId = metricValue(row[4], null);
            String cweId = metricValue(row[5], null);
            String parameter = metricValue(row[6], null);
            String method = metricValue(row[7], null);
            String component = metricValue(row[8], null);
            String evidence = metricValue(row[9], null);
            String verificationStatus = metricValue(row[10], null);
            long count = ((Number) row[11]).longValue();
            rawFindingObservations += count;

            increment(detectionSources, source, count);
            increment(findingRules, source + " / " + (ruleId == null ? type : ruleId), count);

            FindingFingerprint fingerprint = new FindingFingerprint(
                    endpointKey,
                    normalize(type),
                    normalize(parameter),
                    normalize(method),
                    normalize(component),
                    normalize(evidence),
                    normalize(severity),
                    normalize(verificationStatus));
            FindingBucket bucket = uniqueFindingBuckets.computeIfAbsent(
                    fingerprint, ignored -> new FindingBucket(endpoint, severity, type, cweId));
            bucket.observations += count;
            bucket.sources.merge(source, count, Long::sum);
            bucket.engines.add(detectionEngine(source));
        }

        long totalFindings = 0;
        int unmappedOwaspFindings = 0;
        for (FindingBucket bucket : uniqueFindingBuckets.values()) {
            long uniqueCount = bucket.engines.size() > 1 ? 1 : bucket.observations;
            totalFindings += uniqueCount;
            EndpointAccumulator endpointStats = endpoints.computeIfAbsent(
                    bucket.endpoint == null ? UNKNOWN_ENDPOINT : bucket.endpoint,
                    ignored -> new EndpointAccumulator(bucket.endpoint));
            endpointStats.findingCount += uniqueCount;
            increment(endpointStats.severities, bucket.severity, uniqueCount);
            increment(endpointStats.findingTypes, bucket.type, uniqueCount);
            bucket.sources.forEach((source, count) ->
                    increment(endpointStats.detectionSources, source, count));
            increment(severities, bucket.severity, uniqueCount);
            increment(findingTypes, bucket.type, uniqueCount);

            OwaspCategory category = owaspCategory(bucket.type, bucket.cweId);
            if (category == null) {
                unmappedOwaspFindings += Math.toIntExact(uniqueCount);
            } else {
                increment(owaspCategories, category.id() + " " + category.name(), uniqueCount);
            }
        }

        List<ScanCrawlPage> crawlPages = crawlPageRepository
                .findByScanJob_IdAndScanJob_Organization_IdOrderByDepthAscUrlAsc(scanId, organizationId);
        for (ScanCrawlPage page : crawlPages) {
            String endpoint = normalizeEndpoint(page.getUrl());
            if (endpoint == null) {
                continue;
            }
            EndpointAccumulator endpointStats = endpoints.computeIfAbsent(
                    endpoint, ignored -> new EndpointAccumulator(endpoint));
            endpointStats.crawled = true;
            endpointStats.httpStatusCode = page.getStatusCode();
        }

        List<EndpointAccumulator> orderedEndpoints = endpoints.values().stream()
                .sorted(Comparator.comparingLong((EndpointAccumulator item) -> item.findingCount).reversed()
                        .thenComparing(item -> item.url == null ? "" : item.url))
                .toList();
        boolean endpointsTruncated = orderedEndpoints.size() > MAX_ENDPOINTS;
        List<ScanAnalyticsResponse.EndpointMetric> endpointMetrics = orderedEndpoints.stream()
                .limit(MAX_ENDPOINTS)
                .map(EndpointAccumulator::toMetric)
                .toList();
        ScanExecutionSummary summary = ScanExecutionSummary.from(job);
        return new ScanAnalyticsResponse(
                job.getId(),
                job.getTarget().getId(),
                job.getStatus(),
                summary.resultCompleteness(),
                job.getScanType(),
                job.getNativeEngineStatus(),
                job.getZapEngineStatus(),
                Math.toIntExact(totalFindings),
                rawFindingObservations,
                rawFindingObservations - totalFindings,
                crawlPages.size(),
                endpointMetrics,
                endpointsTruncated,
                metrics(severities),
                metrics(findingTypes),
                metrics(owaspCategories),
                unmappedOwaspFindings,
                metrics(detectionSources),
                metrics(findingRules),
                new ScanAnalyticsResponse.RuleCoverage(
                        summary.zapRuleInventoryStatus(),
                        metricsForSource(findingRules, "NATIVE"),
                        metricsForSource(findingRules, "OWASP_ZAP"),
                        job.getScanType() == ScanType.ZAP_ACTIVE,
                        summary.zapPassiveEnabledRules(),
                        summary.zapActiveEnabledRules(),
                        summary.checksOutOfScope(),
                        "Enabled-rule snapshots are configuration evidence only. ZAP does not expose which individual rules ran for this scan."
                ),
                compareWithPrevious(job, organizationId)
        );
    }

    private ScanAnalyticsResponse.HistoryComparison compareWithPrevious(ScanJob current, Long organizationId) {
        if (!isComparable(current)) {
            return new ScanAnalyticsResponse.HistoryComparison(false, null, null, 0, 0, 0, 0,
                    "History comparisons require a fully completed scan; partial or failed engine results are not treated as absence of findings.");
        }
        Page<ScanJob> candidates = scanJobRepository
                .findByTarget_IdAndOrganization_IdAndScanTypeOrderByCreatedAtDesc(
                        current.getTarget().getId(), organizationId, current.getScanType(),
                        PageRequest.of(0, HISTORY_SCAN_LIMIT));
        ScanJob previous = candidates.getContent().stream()
                .filter(candidate -> !candidate.getId().equals(current.getId()))
                .filter(ScanAnalyticsService::isComparable)
                .findFirst()
                .orElse(null);
        if (previous == null) {
            return new ScanAnalyticsResponse.HistoryComparison(true, null, null, 0, 0, 0, 0,
                    "No earlier fully completed scan of the same type was found among the most recent "
                            + HISTORY_SCAN_LIMIT + " scans of this target.");
        }

        Map<HistoryFindingFingerprint, String> currentFindings = fingerprints(current, organizationId);
        Map<HistoryFindingFingerprint, String> previousFindings = fingerprints(previous, organizationId);
        int newCount = 0;
        int resolvedCount = 0;
        int persistentCount = 0;
        int severityChangedCount = 0;
        for (Map.Entry<HistoryFindingFingerprint, String> entry : currentFindings.entrySet()) {
            String previousSeverity = previousFindings.get(entry.getKey());
            if (previousSeverity == null) {
                newCount++;
            } else if (previousSeverity.equals(entry.getValue())) {
                persistentCount++;
            } else {
                severityChangedCount++;
            }
        }
        for (HistoryFindingFingerprint fingerprint : previousFindings.keySet()) {
            if (!currentFindings.containsKey(fingerprint)) {
                resolvedCount++;
            }
        }
        return new ScanAnalyticsResponse.HistoryComparison(true, previous.getId(), previous.getCompletedAt(),
                newCount, resolvedCount, persistentCount, severityChangedCount,
                "Only fully completed scans of the same target and scan type are compared. Finding identity uses normalized endpoint, check type, and parameter; severity changes are reported separately.");
    }

    private Map<HistoryFindingFingerprint, String> fingerprints(ScanJob job, Long organizationId) {
        Map<HistoryFindingFingerprint, String> findings = new LinkedHashMap<>();
        for (ScanFinding finding : findingRepository
                .findByScanJob_IdAndScanJob_Organization_IdOrderByDetectedAtDesc(job.getId(), organizationId)) {
            String endpoint = normalizeEndpoint(finding.getEndpointUrl() == null
                    ? finding.getAffectedComponent() : finding.getEndpointUrl());
            HistoryFindingFingerprint fingerprint = new HistoryFindingFingerprint(
                    endpoint,
                    normalize(finding.getCheckType()),
                    normalize(finding.getParameterName()));
            findings.putIfAbsent(fingerprint, finding.getSeverity());
        }
        return findings;
    }

    private static boolean isComparable(ScanJob job) {
        return job.getStatus() == ScanStatus.COMPLETED
                && "COMPLETED".equals(job.getNativeEngineStatus())
                && (!job.isZapRequested() || "COMPLETED".equals(job.getZapEngineStatus()));
    }

    private String normalizeEndpoint(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String candidate = value;
        int detailStart = candidate.indexOf(" [");
        if (detailStart >= 0) {
            candidate = candidate.substring(0, detailStart);
        }
        String safe = UrlSanitizer.safeEndpoint(candidate);
        if (safe == null) {
            return null;
        }
        try {
            java.net.URI uri = java.net.URI.create(safe);
            String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
            String authority = uri.getRawAuthority().toLowerCase(Locale.ROOT);
            return uri.getScheme().toLowerCase(Locale.ROOT) + "://" + authority + path
                    + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private List<ScanAnalyticsResponse.CountMetric> metrics(Map<String, Long> counts) {
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed()
                        .thenComparing(Map.Entry.comparingByKey()))
                .map(entry -> new ScanAnalyticsResponse.CountMetric(entry.getKey(), entry.getKey(), entry.getValue()))
                .toList();
    }

    private static void increment(Map<String, Long> values, String key, long count) {
        values.merge(key, count, Long::sum);
    }

    private List<String> metricsForSource(Map<String, Long> rules, String engine) {
        return rules.keySet().stream()
                .filter(key -> {
                    int separator = key.indexOf(" / ");
                    return separator > 0 && engine.equals(detectionEngine(key.substring(0, separator)));
                })
                .sorted()
                .toList();
    }

    private static String metricValue(Object value, String fallback) {
        if (value == null || value.toString().isBlank()) {
            return fallback;
        }
        return value.toString().trim();
    }

    private OwaspCategory owaspCategory(String type, String cweId) {
        String normalized = type.toUpperCase(Locale.ROOT);
        if (normalized.contains("SQL_INJECTION") || normalized.contains("XSS")
                || "CWE-89".equalsIgnoreCase(cweId) || "CWE-79".equalsIgnoreCase(cweId)) {
            return new OwaspCategory("A03:2021", "Injection");
        }
        if (normalized.startsWith("MISSING_") || normalized.startsWith("COOKIE_")
                || normalized.startsWith("INFORMATION_DISCLOSURE_")
                || "CWE-16".equalsIgnoreCase(cweId) || "CWE-1004".equalsIgnoreCase(cweId)
                || "CWE-614".equalsIgnoreCase(cweId) || "CWE-693".equalsIgnoreCase(cweId)) {
            return new OwaspCategory("A05:2021", "Security Misconfiguration");
        }
        return null;
    }

    private String normalize(String value) {
        return value == null || value.isBlank() ? null : value.trim().toLowerCase(Locale.ROOT);
    }

    private record OwaspCategory(String id, String name) {
    }

    private String detectionEngine(String source) {
        if ("OWASP_ZAP".equals(source)) {
            return "OWASP_ZAP";
        }
        if ("PASSIVE_HEADERS".equals(source) || "ACTIVE_QUERY_PARAMETER".equals(source)
                || "ACTIVE_POST_FORM".equals(source)) {
            return "NATIVE";
        }
        if ("NVD_CVE_LOOKUP".equals(source)) {
            return "NVD";
        }
        return source;
    }

    private record FindingFingerprint(String endpoint, String checkType, String parameterName,
                                      String method, String component, String evidence,
                                      String severity, String verificationStatus) {
    }

    private record HistoryFindingFingerprint(String endpoint, String checkType, String parameterName) {
    }

    private static final class FindingBucket {
        private final String endpoint;
        private final String severity;
        private final String type;
        private final String cweId;
        private long observations;
        private final Set<String> engines = new java.util.LinkedHashSet<>();
        private final Map<String, Long> sources = new LinkedHashMap<>();

        private FindingBucket(String endpoint, String severity, String type, String cweId) {
            this.endpoint = endpoint;
            this.severity = severity;
            this.type = type;
            this.cweId = cweId;
        }
    }

    private static final class EndpointAccumulator {
        private final String url;
        private long findingCount;
        private boolean crawled;
        private Integer httpStatusCode;
        private final Map<String, Long> severities = new LinkedHashMap<>();
        private final Map<String, Long> findingTypes = new LinkedHashMap<>();
        private final Map<String, Long> detectionSources = new LinkedHashMap<>();

        private EndpointAccumulator(String url) {
            this.url = url;
        }

        private ScanAnalyticsResponse.EndpointMetric toMetric() {
            return new ScanAnalyticsResponse.EndpointMetric(url, Math.toIntExact(findingCount), crawled,
                    httpStatusCode, Map.copyOf(severities), Map.copyOf(findingTypes), Map.copyOf(detectionSources));
        }
    }
}
