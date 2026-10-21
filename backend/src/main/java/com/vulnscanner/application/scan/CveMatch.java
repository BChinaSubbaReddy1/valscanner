package com.vulnscanner.application.scan;

public record CveMatch(
        String cveId,
        String software,
        String version,
        double cvssScore,
        String cvssSeverity,
        String cvssVector,
        String description
) {
}
