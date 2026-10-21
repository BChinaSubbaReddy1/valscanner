package com.vulnscanner.application.scan;

import com.vulnscanner.application.common.ApiResponse;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/scans")
@PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
public class ScanController {
    private final ScanService scanService;
    private final ScanReportService scanReportService;

    public ScanController(ScanService scanService, ScanReportService scanReportService) {
        this.scanService = scanService;
        this.scanReportService = scanReportService;
    }

    @PostMapping
    public ResponseEntity<ApiResponse<ScanJobResponse>> create(@Valid @RequestBody ScanCreateRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Scan job created", scanService.create(request)));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<Page<ScanJobResponse>>> list(
            @PageableDefault(size = 20, sort = "createdAt") Pageable pageable) {
        return ResponseEntity.ok(ApiResponse.success("Scan jobs retrieved", scanService.list(pageable)));
    }

    @GetMapping("/me/dashboard")
    @PreAuthorize("hasRole('SECURITY_ANALYST')")
    public ResponseEntity<ApiResponse<AnalystDashboardResponse>> analystDashboard() {
        return ResponseEntity.ok(ApiResponse.success("Analyst dashboard retrieved",
                scanService.analystDashboard()));
    }

    @GetMapping("/pending-approval")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Page<ScanJobResponse>>> pendingApprovals(
            @PageableDefault(size = 20, sort = "createdAt") Pageable pageable) {
        return ResponseEntity.ok(ApiResponse.success("Pending scan approvals retrieved",
                scanService.pendingApprovals(pageable)));
    }

    @PostMapping("/{scanId}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<ScanJobResponse>> approve(@PathVariable Long scanId) {
        return ResponseEntity.ok(ApiResponse.success("Scan request approved", scanService.approve(scanId)));
    }

    @PostMapping("/{scanId}/reject")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<ScanJobResponse>> reject(@PathVariable Long scanId,
                                                                @Valid @RequestBody ScanRejectRequest request) {
        return ResponseEntity.ok(ApiResponse.success("Scan request rejected",
                scanService.reject(scanId, request)));
    }

    @GetMapping("/{scanId}")
    public ResponseEntity<ApiResponse<ScanJobResponse>> get(@PathVariable Long scanId) {
        return ResponseEntity.ok(ApiResponse.success("Scan job retrieved", scanService.get(scanId)));
    }

    @PostMapping("/{scanId}/cancel")
    public ResponseEntity<ApiResponse<ScanJobResponse>> cancel(@PathVariable Long scanId) {
        return ResponseEntity.ok(ApiResponse.success("Scan cancellation recorded", scanService.cancel(scanId)));
    }

    @GetMapping("/{scanId}/findings")
    public ResponseEntity<ApiResponse<List<ScanFindingResponse>>> findings(@PathVariable Long scanId) {
        return ResponseEntity.ok(ApiResponse.success("Scan findings retrieved", scanService.findings(scanId)));
    }

    @GetMapping("/{scanId}/crawl-pages")
    public ResponseEntity<ApiResponse<List<ScanCrawlPageResponse>>> crawlPages(@PathVariable Long scanId) {
        return ResponseEntity.ok(ApiResponse.success("Scan crawl pages retrieved",
                scanService.crawlPages(scanId)));
    }

    @GetMapping("/{scanId}/report")
    public ResponseEntity<ApiResponse<ScanReportResponse>> report(@PathVariable Long scanId) {
        return ResponseEntity.ok(ApiResponse.success("Scan report retrieved",
                scanReportService.generateReport(scanId)));
    }

    @GetMapping("/{scanId}/report/export")
    public ResponseEntity<byte[]> exportReport(
            @PathVariable Long scanId,
            @RequestParam(defaultValue = "json") String format) {
        byte[] content = scanReportService.exportReport(scanId, format);
        String normalizedFormat = format.trim().toLowerCase(java.util.Locale.ROOT);
        String contentType = switch (normalizedFormat) {
            case "csv" -> "text/csv; charset=UTF-8";
            case "pdf" -> "application/pdf";
            default -> "application/json; charset=UTF-8";
        };
        String extension = switch (normalizedFormat) {
            case "csv" -> "csv";
            case "pdf" -> "pdf";
            default -> "json";
        };
        return ResponseEntity.ok()
                .header(org.springframework.http.HttpHeaders.CONTENT_TYPE, contentType)
                .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"scan-report-" + scanId + "." + extension + "\"")
                .body(content);
    }
}
