package com.vulnscanner.application.organization;

import java.time.Instant;

public record OrganizationResponse(
        Long id,
        String name,
        OrganizationStatus status,
        String contactEmail,
        String primaryContactName,
        Instant createdAt,
        Instant updatedAt,
        String registrationAdminEmail,
        String registrationAdminFirstName,
        String registrationAdminLastName
) {
}
