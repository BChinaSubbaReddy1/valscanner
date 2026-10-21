package com.vulnscanner.application.organization;

public record OrganizationDashboardResponse(
        long totalUsers,
        long approvedUsers,
        long pendingApprovalRequests,
        long suspendedUsers,
        long activeSecurityAnalysts,
        long totalTargets,
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
