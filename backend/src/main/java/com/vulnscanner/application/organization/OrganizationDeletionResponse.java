package com.vulnscanner.application.organization;

import java.time.Instant;

public record OrganizationDeletionResponse(
        Long id,
        String name,
        OrganizationStatus status,
        Instant deletedAt
) {
}
