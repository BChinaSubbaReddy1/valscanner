package com.vulnscanner.application.organization;

public record PlatformDashboardResponse(
        long totalOrganizations,
        long pendingOrganizations,
        long approvedOrganizations,
        long rejectedOrganizations,
        long suspendedOrganizations
) {
}
