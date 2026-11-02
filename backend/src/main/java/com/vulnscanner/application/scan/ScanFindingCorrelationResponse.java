package com.vulnscanner.application.scan;

import java.util.List;

public record ScanFindingCorrelationResponse(
        String checkType,
        String affectedComponent,
        List<Long> findingIds,
        List<String> detectionEngines,
        String interpretation,
        String relationshipType,
        String matchingEvidence,
        String confidence
) {
}
