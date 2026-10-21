package com.vulnscanner.application.scan;

public record AnalystDashboardResponse(
        long approvedTargets,
        long pendingScanApprovals,
        long queuedScans,
        long crawlingScans,
        long scanningScans,
        long runningScans,
        long completedScans,
        long failedScans,
        long cancelledScans,
        long rejectedScans,
        long highSeverityFindings,
        long mediumSeverityFindings,
        long lowSeverityFindings
) {
}
