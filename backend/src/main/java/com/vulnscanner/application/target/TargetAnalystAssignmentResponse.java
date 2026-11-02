package com.vulnscanner.application.target;

import java.time.Instant;

public record TargetAnalystAssignmentResponse(
        Long analystId,
        String displayName,
        Instant assignedAt
) {
}
