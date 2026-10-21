package com.vulnscanner.application.scan;

import java.time.Instant;
import java.util.List;

public record ScanReportResponse(
        Long scanId,
        Long targetId,
        String targetName,
        String targetUrl,
        ScanType scanType,
        ScanStatus status,
        int progress,
        String statusMessage,
        String failureReason,
        boolean cancellationRequested,
        Instant createdAt,
        Instant startedAt,
        Instant completedAt,
        Long organizationId,
        String organizationName,
        SeveritySummary severitySummary,
        int totalFindings,
        int totalCrawlPages,
        List<ScanFindingResponse> findings
) {
    public record SeveritySummary(long high, long medium, long low, long total) {}
}
