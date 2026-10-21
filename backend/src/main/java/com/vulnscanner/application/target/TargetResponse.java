package com.vulnscanner.application.target;

import java.time.Instant;

public record TargetResponse(
        Long id,
        String name,
        String url,
        TargetType type,
        Long organizationId,
        TargetStatus status,
        Instant createdAt,
        Instant updatedAt
) {
}
