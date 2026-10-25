package com.vulnscanner.application.scan;

import java.time.Instant;

public record ScanJobResponse(
        Long id,
        Long targetId,
        String targetName,
        ScanType scanType,
        ScanStatus status,
        int progress,
        String statusMessage,
        String failureReason,
        boolean cancellationRequested,
        Instant createdAt,
        Instant startedAt,
        Instant completedAt,
        Long reviewedByUserId,
        Instant reviewedAt,
        String rejectionReason,
        ScanExecutionSummary executionSummary
) {
}
