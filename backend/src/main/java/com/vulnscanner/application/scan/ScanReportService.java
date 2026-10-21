package com.vulnscanner.application.scan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
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
import java.util.Locale;

@Service
public class ScanReportService {

    private final ScanJobRepository scanJobRepository;
    private final ScanFindingRepository scanFindingRepository;
    private final ScanCrawlPageRepository scanCrawlPageRepository;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    public ScanReportService(ScanJobRepository scanJobRepository,
                             ScanFindingRepository scanFindingRepository,
                             ScanCrawlPageRepository scanCrawlPageRepository,
                             UserRepository userRepository,
                             ObjectMapper objectMapper) {
        this.scanJobRepository = scanJobRepository;
        this.scanFindingRepository = scanFindingRepository;
        this.scanCrawlPageRepository = scanCrawlPageRepository;
        this.userRepository = userRepository;
        this.objectMapper = objectMapper;
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
                job.getTarget().getUrl(),
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
                sanitizedFindings
        );
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
            writer.println("# Created At," + report.createdAt());
            writer.println("# Completed At," + (report.completedAt() != null ? report.completedAt().toString() : ""));
            writer.println("# High," + report.severitySummary().high() + ",Medium," + report.severitySummary().medium()
                    + ",Low," + report.severitySummary().low() + ",Total," + report.totalFindings());
            writer.println();

            writer.println("Finding ID,Check Type,Severity,Affected Component,Evidence,Rationale,Remediation,Detection Source,Verification Status,Detected At");

            for (ScanFindingResponse finding : report.findings()) {
                writer.printf("%d,%s,%s,%s,%s,%s,%s,%s,%s,%s%n",
                        finding.id(),
                        escapeCsv(finding.checkType()),
                        escapeCsv(finding.severity()),
                        escapeCsv(finding.affectedComponent()),
                        escapeCsv(finding.evidence()),
                        escapeCsv(finding.rationale()),
                        escapeCsv(finding.remediation()),
                        escapeCsv(finding.detectionSource()),
                        escapeCsv(finding.verificationStatus()),
                        escapeCsv(finding.detectedAt() != null ? finding.detectedAt().toString() : "")
                );
            }
            writer.flush();
            return out.toByteArray();
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
        if (sanitized.contains(",") || sanitized.contains("\"") || sanitized.contains("\n")) {
            return "\"" + sanitized.replace("\"", "\"\"") + "\"";
        }
        return sanitized;
    }

    private ScanFindingResponse toSanitizedFindingResponse(ScanFinding finding) {
        return new ScanFindingResponse(
                finding.getId(),
                finding.getCheckType(),
                finding.getSeverity(),
                sanitize(finding.getAffectedComponent()),
                sanitize(finding.getEvidence()),
                sanitize(finding.getRationale()),
                sanitize(finding.getRemediation()),
                finding.getDetectionSource(),
                finding.getVerificationStatus(),
                finding.getDetectedAt()
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
        return (isAdmin
                ? scanJobRepository.findByIdAndOrganization_Id(scanId, actor.getOrganization().getId())
                : scanJobRepository.findByIdAndRequestedBy_Id(scanId, actor.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found"));
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
