package com.vulnscanner.application.scan;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record ScanAnalyticsResponse(
        Long scanId,
        Long targetId,
        ScanStatus scanStatus,
        String resultCompleteness,
        ScanType scanType,
        String nativeEngineStatus,
        String zapEngineStatus,
        int totalFindings,
        long rawFindingObservations,
        long duplicateEngineObservationsSuppressed,
        int totalCrawlPages,
        List<EndpointMetric> endpoints,
        boolean endpointsTruncated,
        List<CountMetric> severities,
        List<CountMetric> findingTypes,
        List<CountMetric> owaspCategories,
        int unmappedOwaspFindings,
        List<CountMetric> detectionSources,
        List<CountMetric> findingRules,
        RuleCoverage ruleCoverage,
        HistoryComparison history
) {
    public record EndpointMetric(
            String url,
            int findingCount,
            boolean crawled,
            Integer httpStatusCode,
            Map<String, Long> severities,
            Map<String, Long> findingTypes,
            Map<String, Long> detectionSources
    ) {
    }

    public record CountMetric(String key, String label, long count) {
    }

    public record RuleCoverage(
            String inventoryStatus,
            List<String> nativeRulesWithFindings,
            List<String> zapRulesWithFindings,
            boolean activeScanRequested,
            List<String> passiveEnabledRules,
            List<String> activeEnabledRules,
            List<String> unsupportedOrSkippedChecks,
            String executionEvidence
    ) {
    }

    public record HistoryComparison(
            boolean comparable,
            Long previousScanId,
            Instant previousCompletedAt,
            int newFindings,
            int resolvedFindings,
            int persistentFindings,
            int severityChangedFindings,
            String explanation
    ) {
    }
}
