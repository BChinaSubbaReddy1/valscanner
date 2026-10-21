package com.vulnscanner.application.organization;

import java.time.Instant;

public record OrganizationRegistryItem(
        Long id,
        String name,
        OrganizationStatus status,
        boolean ownOrganization,
        Instant registeredAt,
        Instant approvedAt,
        String adminDisplayName
) {
}
