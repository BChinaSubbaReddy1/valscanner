package com.vulnscanner.application.scan;

import com.vulnscanner.application.common.UrlSanitizer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
import com.vulnscanner.application.target.TargetAnalystAssignmentRepository;
import com.vulnscanner.application.target.TargetStatus;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@Service
public class ScanReportService {

    private final ScanJobRepository scanJobRepository;
    private final ScanFindingRepository scanFindingRepository;
    private final ScanCrawlPageRepository scanCrawlPageRepository;
    private final UserRepository userRepository;
    private final TargetAnalystAssignmentRepository assignmentRepository;
    private final ObjectMapper objectMapper;
    private final ScanAnalyticsService scanAnalyticsService;

    public ScanReportService(ScanJobRepository scanJobRepository,
                             ScanFindingRepository scanFindingRepository,
                             ScanCrawlPageRepository scanCrawlPageRepository,
                             UserRepository userRepository,
                             TargetAnalystAssignmentRepository assignmentRepository,
                             ObjectMapper objectMapper,
                             ScanAnalyticsService scanAnalyticsService) {
        this.scanJobRepository = scanJobRepository;
        this.scanFindingRepository = scanFindingRepository;
        this.scanCrawlPageRepository = scanCrawlPageRepository;
        this.userRepository = userRepository;
        this.assignmentRepository = assignmentRepository;
        this.objectMapper = objectMapper;
        this.scanAnalyticsService = scanAnalyticsService;
    }

    @Transactional(readOnly = true)
    public ScanReportResponse generateReport(Long scanId) {
        User actor = requireOperationalUser();
        ScanJob job = findAccessible(scanId, actor);

        List<ScanFinding> rawFindings = scanFindingRepository
                .findByScanJob_IdAndScanJob_Organization_IdOrderByDetectedAtDesc(
                        scanId, actor.getOrganization().getId());

        List<ScanFindingResponse> sanitizedFindings = rawFindings.stream()
                .map(this::toSanitizedFindingResponse)
                .toList();

        long high = sanitizedFindings.stream()
                .filter(f -> "HIGH".equalsIgnoreCase(f.severity())).count();
        long medium = sanitizedFindings.stream()
                .filter(f -> "MEDIUM".equalsIgnoreCase(f.severity())).count();
        long low = sanitizedFindings.stream()
                .filter(f -> "LOW".equalsIgnoreCase(f.severity())).count();
        long total = sanitizedFindings.size();

        int crawlPagesCount = (int) scanCrawlPageRepository.countByScanJob_Id(scanId);

        return new ScanReportResponse(
                job.getId(),
                job.getTarget().getId(),
                job.getTarget().getName(),
                UrlSanitizer.safeTargetUrl(job.getTarget().getUrl()),
                job.getScanType(),
                job.getStatus(),
                job.getProgress(),
                job.getStatusMessage(),
                job.getFailureReason(),
                job.isCancellationRequested(),
                job.getCreatedAt(),
                job.getStartedAt(),
                job.getCompletedAt(),
                job.getOrganization().getId(),
                job.getOrganization().getName(),
                new ScanReportResponse.SeveritySummary(high, medium, low, total),
                (int) total,
                crawlPagesCount,
                ScanExecutionSummary.from(job),
                sanitizedFindings,
                correlateFindings(sanitizedFindings),
                scanAnalyticsService.analyze(scanId)
        );
    }

    @Transactional(readOnly = true)
    public List<ScanFindingCorrelationResponse> correlateFindings(Long scanId) {
        return generateReport(scanId).correlations();
    }

    private List<ScanFindingCorrelationResponse> correlateFindings(List<ScanFindingResponse> findings) {
        Map<ExactCorrelationKey, List<ScanFindingResponse>> exactGroups = new LinkedHashMap<>();
        Map<String, List<ScanFindingResponse>> endpointGroups = new LinkedHashMap<>();
        for (ScanFindingResponse finding : findings) {
            String endpoint = normalizeEndpoint(finding.endpointUrl() == null
                    ? finding.affectedComponent() : finding.endpointUrl());
            String component = normalize(finding.affectedComponent());
            String category = normalize(finding.checkType());
            String parameter = normalize(finding.parameterName());
            String evidence = normalize(finding.evidence());
            if (category != null && evidence != null && (endpoint != null || component != null)) {
                ExactCorrelationKey key = new ExactCorrelationKey(category,
                        endpoint == null ? component : endpoint, parameter,
                        endpoint == null ? component : normalize(finding.affectedComponent()), evidence);
                exactGroups.computeIfAbsent(key, ignored -> new ArrayList<>()).add(finding);
            }
            if (endpoint != null) {
                endpointGroups.computeIfAbsent(endpoint, ignored -> new ArrayList<>()).add(finding);
            }
        }

        List<ScanFindingCorrelationResponse> correlations = new ArrayList<>();
        Set<Long> relatedFindingIds = new LinkedHashSet<>();
        for (Map.Entry<ExactCorrelationKey, List<ScanFindingResponse>> entry : exactGroups.entrySet()) {
            List<ScanFindingResponse> group = entry.getValue();
            if (group.size() < 2) {
                continue;
            }
            correlations.add(new ScanFindingCorrelationResponse(
                    entry.getKey().category().toUpperCase(Locale.ROOT),
                    group.getFirst().endpointUrl() == null
                            ? group.getFirst().affectedComponent() : group.getFirst().endpointUrl(),
                    group.stream().map(ScanFindingResponse::id).toList(),
                    detectionEngines(group),
                    "Finding evidence and location fields match exactly. Duplicate classification does not confirm exploitability.",
                    "EXACT_DUPLICATE",
                    "Normalized category, endpoint, parameter, affected component, and evidence matched.",
                    "HIGH"
            ));
            group.stream().map(ScanFindingResponse::id).forEach(relatedFindingIds::add);
        }
        for (Map.Entry<String, List<ScanFindingResponse>> entry : endpointGroups.entrySet()) {
            List<ScanFindingResponse> group = entry.getValue();
            Set<ExactCorrelationKey> signatures = group.stream()
                    .map(finding -> new ExactCorrelationKey(normalize(finding.checkType()),
                            entry.getKey(), normalize(finding.parameterName()),
                            normalize(finding.affectedComponent()), normalize(finding.evidence())))
                    .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
            if (group.size() < 2 || signatures.size() < 2) {
                continue;
            }
            correlations.add(new ScanFindingCorrelationResponse(
                    group.stream().map(ScanFindingResponse::checkType).distinct()
                            .collect(java.util.stream.Collectors.joining("; ")),
                    entry.getKey(),
                    group.stream().map(ScanFindingResponse::id).toList(),
                    detectionEngines(group),
                    "Findings share the same observed endpoint but differ by category, parameter, or component. "
                            + "The shared endpoint is a relationship signal, not proof of a causal attack path.",
                    "RELATED_FINDINGS",
                    "Normalized endpoint matched; finding categories, parameters, or components differ.",
                    "MEDIUM"
            ));
            group.stream().map(ScanFindingResponse::id).forEach(relatedFindingIds::add);
        }
        for (ScanFindingResponse finding : findings) {
            if (relatedFindingIds.contains(finding.id())) {
                continue;
            }
            correlations.add(new ScanFindingCorrelationResponse(
                    finding.checkType(),
                    finding.endpointUrl() == null
                            ? finding.affectedComponent() : finding.endpointUrl(),
                    List.of(finding.id()),
                    detectionEngines(List.of(finding)),
                    "No other persisted finding shared a defensible duplicate or same-endpoint relationship.",
                    "INDEPENDENT",
                    "No matching endpoint/category/component relationship was observed in this scan.",
                    "LOW"
            ));
        }
        return List.copyOf(correlations);
    }

    private List<String> detectionEngines(List<ScanFindingResponse> findings) {
        return findings.stream().map(finding -> correlationEngine(finding.detectionSource()))
                .filter(java.util.Objects::nonNull).distinct().sorted().toList();
    }

    private String normalizeEndpoint(String endpoint) {
        String safe = FindingSanitizer.safeEndpoint(endpoint);
        if (safe == null) {
            return null;
        }
        try {
            java.net.URI uri = java.net.URI.create(safe);
            String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
            return uri.getScheme().toLowerCase(Locale.ROOT) + "://"
                    + uri.getRawAuthority().toLowerCase(Locale.ROOT) + path;
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private String normalize(String value) {
        return value == null || value.isBlank() ? null : value.trim().toLowerCase(Locale.ROOT);
    }

    @Transactional(readOnly = true)
    public byte[] exportReport(Long scanId, String format) {
        ScanReportResponse report = generateReport(scanId);
        String normalizedFormat = format == null ? "json" : format.trim().toLowerCase(Locale.ROOT);

        return switch (normalizedFormat) {
            case "json" -> exportJson(report);
            case "csv" -> exportCsv(report);
            case "pdf" -> exportPdf(report);
            default -> throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Unsupported export format: " + format + ". Supported formats: json, csv, pdf");
        };
    }

    private byte[] exportJson(ScanReportResponse report) {
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(report);
        } catch (IOException exception) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to serialize report to JSON", exception);
        }
    }

    private byte[] exportCsv(ScanReportResponse report) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8))) {
            writer.println("# Scan ID," + report.scanId());
            writer.println("# Target," + escapeCsv(report.targetName()) + "," + escapeCsv(report.targetUrl()));
            writer.println("# Status," + report.status());
            writer.println("# Scan Type," + report.scanType());
            writer.println("# Native Engine Status," + report.executionSummary().nativeEngineStatus());
            writer.println("# OWASP ZAP Status," + report.executionSummary().zapEngineStatus());
            writer.println("# OWASP ZAP Requested," + report.executionSummary().zapRequested());
            writer.println("# OWASP ZAP Failure Reason," + escapeCsv(report.executionSummary().zapFailureReason()));
            writer.println("# ZAP Spider Status," + escapeCsv(report.executionSummary().zapSpiderStatus()));
            writer.println("# ZAP Spider Discovered URLs,"
                    + reportCount(report.executionSummary().zapSpiderDiscoveredCount()));
            writer.println("# ZAP Passive Analysis Status,"
                    + escapeCsv(report.executionSummary().zapPassiveStatus()));
            writer.println("# ZAP Alert Count," + reportCount(report.executionSummary().zapAlertCount()));
            writer.println("# ZAP Active Scan Status,"
                    + escapeCsv(report.executionSummary().zapActiveStatus()));
            writer.println("# NVD Lookup Status," + report.executionSummary().nvdLookupStatus());
            writer.println("# Discovered Same-Origin Pages," + reportCount(report.executionSummary().discoveredPageCount()));
            writer.println("# Visited Pages," + reportCount(report.executionSummary().visitedPageCount()));
            writer.println("# Passively Tested Pages," + reportCount(report.executionSummary().testedPassivePageCount()));
            writer.println("# Persisted HTML Crawl Records," + report.totalCrawlPages());
            writer.println("# Checks In Scope," + escapeCsv(String.join("; ", report.executionSummary().checksInScope())));
            writer.println("# Checks Out Of Scope," + escapeCsv(String.join("; ", report.executionSummary().checksOutOfScope())));
            writer.println("# Adaptive Check Selections,"
                    + escapeCsv(String.join(" | ", report.executionSummary().adaptiveCheckSelections())));
            writer.println("# ZAP Rule Inventory Status,"
                    + escapeCsv(report.executionSummary().zapRuleInventoryStatus()));
            writer.println("# ZAP Passive Rules Enabled,"
                    + escapeCsv(String.join(" | ", report.executionSummary().zapPassiveEnabledRules())));
            writer.println("# ZAP Active Rules Enabled,"
                    + escapeCsv(String.join(" | ", report.executionSummary().zapActiveEnabledRules())));
            writer.println("# Rule Execution Evidence,"
                    + escapeCsv(report.analytics().ruleCoverage().executionEvidence()));
            writer.println("# History Comparison,"
                    + escapeCsv(report.analytics().history().explanation()));
            writer.println("# Link-wise Endpoint Finding Counts");
            writer.println("Endpoint,Findings,Crawled,HTTP Status");
            for (ScanAnalyticsResponse.EndpointMetric endpoint : report.analytics().endpoints()) {
                writer.printf("%s,%d,%s,%s%n",
                        escapeCsv(endpoint.url()),
                        endpoint.findingCount(),
                        endpoint.crawled(),
                        endpoint.httpStatusCode() == null ? "" : endpoint.httpStatusCode());
            }
            appendAnalyticsMetrics(writer, "Severity Distribution", report.analytics().severities());
            appendAnalyticsMetrics(writer, "Finding Type Distribution", report.analytics().findingTypes());
            appendAnalyticsMetrics(writer, "OWASP Categories", report.analytics().owaspCategories());
            appendAnalyticsMetrics(writer, "Detection Sources", report.analytics().detectionSources());
            appendAnalyticsMetrics(writer, "Generated Finding Rules", report.analytics().findingRules());
            writer.println("# Unmapped OWASP Findings," + report.analytics().unmappedOwaspFindings());
            ScanAnalyticsResponse.HistoryComparison history = report.analytics().history();
            writer.printf("# History Counts,New,%d,Resolved,%d,Persistent,%d,Severity Changed,%d%n",
                    history.newFindings(), history.resolvedFindings(),
                    history.persistentFindings(), history.severityChangedFindings());
            writer.println("# Created At," + report.createdAt());
            writer.println("# Completed At," + (report.completedAt() != null ? report.completedAt().toString() : ""));
            writer.println("# High," + report.severitySummary().high() + ",Medium," + report.severitySummary().medium()
                    + ",Low," + report.severitySummary().low() + ",Total," + report.totalFindings());
            writer.println();

            writer.println("Finding ID,Check Type,Severity,Priority Score,Priority Level,Priority Explanation,Endpoint URL,HTTP Method,Parameter,Affected Component,Evidence,Rationale,Remediation,Detection Source,Verification Status,Detected At,Source Rule ID,Source Confidence,Source Reference,Source CWE ID,Source WASC ID");

            for (ScanFindingResponse finding : report.findings()) {
                writer.printf("%d,%s,%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s%n",
                        finding.id(),
                        escapeCsv(finding.checkType()),
                        escapeCsv(finding.severity()),
                        finding.priorityScore(),
                        escapeCsv(finding.priorityLevel()),
                        escapeCsv(finding.priorityExplanation()),
                        escapeCsv(finding.endpointUrl()),
                        escapeCsv(finding.httpMethod()),
                        escapeCsv(finding.parameterName()),
                        escapeCsv(finding.affectedComponent()),
                        escapeCsv(finding.evidence()),
                        escapeCsv(finding.rationale()),
                        escapeCsv(finding.remediation()),
                        escapeCsv(finding.detectionSource()),
                        escapeCsv(finding.verificationStatus()),
                        escapeCsv(finding.detectedAt() != null ? finding.detectedAt().toString() : ""),
                        escapeCsv(finding.sourceRuleId()),
                        escapeCsv(finding.sourceConfidence()),
                        escapeCsv(finding.sourceReference()),
                        escapeCsv(finding.sourceCweId()),
                        escapeCsv(finding.sourceWascId())
                );
            }
            writer.println();
            writer.println("# Finding Relationships," + report.correlations().size());
            writer.println("Categories,Endpoint or Component,Finding IDs,Detection Engines,Relationship Type,Matching Evidence,Confidence,Interpretation");
            for (ScanFindingCorrelationResponse correlation : report.correlations()) {
                writer.printf("%s,%s,%s,%s,%s,%s,%s,%s%n",
                        escapeCsv(correlation.checkType()),
                        escapeCsv(correlation.affectedComponent()),
                        escapeCsv(correlation.findingIds().stream().map(String::valueOf)
                                .collect(java.util.stream.Collectors.joining("; "))),
                        escapeCsv(String.join("; ", correlation.detectionEngines())),
                        escapeCsv(correlation.relationshipType()),
                        escapeCsv(correlation.matchingEvidence()),
                        escapeCsv(correlation.confidence()),
                        escapeCsv(correlation.interpretation()));
            }
            writer.flush();
            return out.toByteArray();
        }
    }

    private void appendAnalyticsMetrics(PrintWriter writer, String heading,
                                        List<ScanAnalyticsResponse.CountMetric> metrics) {
        writer.println("# " + heading);
        writer.println("Category,Count");
        for (ScanAnalyticsResponse.CountMetric metric : metrics) {
            writer.printf("%s,%d%n", escapeCsv(metric.label()), metric.count());
        }
    }

    private byte[] exportPdf(ScanReportResponse report) {
        return PdfReportGenerator.generate(report);
    }

    private String escapeCsv(String value) {
        if (value == null) {
            return "";
        }
        String sanitized = value.replace("\r", " ").replace("\n", " ");
        int firstVisible = 0;
        while (firstVisible < sanitized.length()
                && (Character.isWhitespace(sanitized.charAt(firstVisible))
                || Character.isISOControl(sanitized.charAt(firstVisible)))) {
            firstVisible++;
        }
        if (firstVisible < sanitized.length()
                && "=+-@".indexOf(sanitized.charAt(firstVisible)) >= 0) {
            sanitized = "'" + sanitized;
        }
        if (sanitized.contains(",") || sanitized.contains("\"") || sanitized.contains("\n")) {
            return "\"" + sanitized.replace("\"", "\"\"") + "\"";
        }
        return sanitized;
    }

    private String reportCount(Integer count) {
        return count == null ? "Not reported" : count.toString();
    }

    private ScanFindingResponse toSanitizedFindingResponse(ScanFinding finding) {
        FindingPriorityAssessment priority = FindingPriorityAssessment.assess(
                finding.getSeverity(), finding.getVerificationStatus(), finding.getSourceConfidence());
        return new ScanFindingResponse(
                finding.getId(),
                finding.getCheckType(),
                finding.getSeverity(),
                FindingSanitizer.sanitize(finding.getAffectedComponent()),
                FindingSanitizer.sanitize(finding.getEvidence()),
                FindingSanitizer.sanitize(finding.getRationale()),
                FindingSanitizer.sanitize(finding.getRemediation()),
                finding.getDetectionSource(),
                finding.getVerificationStatus(),
                finding.getDetectedAt(),
                finding.getSourceRuleId(),
                finding.getSourceConfidence(),
                finding.getSourceReference(),
                finding.getSourceCweId(),
                finding.getSourceWascId(),
                priority.score(),
                priority.level(),
                priority.explanation(),
                FindingSanitizer.safeEndpoint(finding.getEndpointUrl()),
                finding.getHttpMethod(),
                FindingSanitizer.sanitize(finding.getParameterName())
        );
    }

    private String sanitize(String input) {
        if (input == null) {
            return null;
        }
        // Redact Bearer tokens, passwords, cookies, secrets
        return input.replaceAll("(?i)(bearer\\s+)[a-zA-Z0-9._~+/-]+", "$1[REDACTED]")
                .replaceAll("(?i)(password|secret|token|apikey|jwt)=[^;&\\s]+", "$1=[REDACTED]");
    }

    private ScanJob findAccessible(Long scanId, User actor) {
        boolean isAdmin = actor.getRoles().stream().anyMatch(role -> role.getName() == RoleName.ADMIN);
        ScanJob job = scanJobRepository.findByIdAndOrganization_Id(scanId, actor.getOrganization().getId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found"));
        if (!job.getTarget().getOrganization().getId().equals(actor.getOrganization().getId())
                || (!isAdmin && (job.getTarget().getStatus() != TargetStatus.APPROVED
                || !assignmentRepository.existsByTarget_IdAndAnalyst_Id(
                        job.getTarget().getId(), actor.getId())))) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found");
        }
        return job;
    }

    private String correlationEngine(String detectionSource) {
        if ("OWASP_ZAP".equals(detectionSource)) {
            return "OWASP_ZAP";
        }
        if ("PASSIVE_HEADERS".equals(detectionSource)
                || "ACTIVE_QUERY_PARAMETER".equals(detectionSource)
                || "ACTIVE_POST_FORM".equals(detectionSource)) {
            return "NATIVE";
        }
        return null;
    }

    private record ExactCorrelationKey(String category, String endpoint,
                                       String parameter, String component, String evidence) {
    }

    private User requireOperationalUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AccessDeniedException("Authentication required");
        }
        User actor = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new AccessDeniedException("Authentication required"));
        if (actor.getStatus() != UserStatus.ACTIVE) {
            throw new AccessDeniedException("Active account required");
        }
        Organization organization = actor.getOrganization();
        if (organization == null || organization.getStatus() != OrganizationStatus.APPROVED) {
            throw new AccessDeniedException("An approved organization membership is required");
        }
        boolean allowedRole = actor.getRoles().stream().anyMatch(role ->
                role.getName() == RoleName.ADMIN || role.getName() == RoleName.SECURITY_ANALYST);
        if (!allowedRole) {
            throw new AccessDeniedException("Insufficient role");
        }
        return actor;
    }
}
