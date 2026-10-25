package com.vulnscanner.application.scan;

import java.time.Instant;

public record ScanFindingResponse(
        Long id,
        String checkType,
        String severity,
        String affectedComponent,
        String evidence,
        String rationale,
        String remediation,
        String detectionSource,
        String verificationStatus,
        Instant detectedAt,
        String sourceRuleId,
        String sourceConfidence,
        String sourceReference,
        String sourceCweId,
        String sourceWascId
) {
}
