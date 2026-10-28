package com.vulnscanner.application.scan;

import java.util.List;

public record ScanExecutionSummary(
        String nativeEngineStatus,
        String zapEngineStatus,
        boolean zapRequested,
        String zapFailureReason,
        String zapSpiderStatus,
        Integer zapSpiderDiscoveredCount,
        String zapPassiveStatus,
        Integer zapAlertCount,
        String zapActiveStatus,
        NvdLookupStatus nvdLookupStatus,
        Integer discoveredPageCount,
        Integer visitedPageCount,
        Integer testedPassivePageCount,
        List<String> checksInScope,
        List<String> checksOutOfScope
) {
    public static ScanExecutionSummary from(ScanJob job) {
        List<String> included;
        List<String> excluded;
        switch (job.getScanType()) {
            case PASSIVE_HEADERS -> {
                included = List.of(
                        "Native response security-header checks",
                        "Set-Cookie attribute observations (Secure assessed only for HTTPS responses)",
                        "Server and X-Powered-By disclosure checks",
                        "NVD keyword-candidate enrichment when configured and version metadata is detected",
                        "OWASP ZAP spider and passive analysis"
                );
                excluded = List.of(
                        "SQL injection and reflected XSS active probes",
                        "OWASP ZAP active scanning",
                        "Authorization and access-control testing"
                );
            }
            case ZAP_PASSIVE -> {
                included = List.of(
                        "Native passive response checks",
                        "OWASP ZAP spider and passive analysis"
                );
                excluded = List.of(
                        "Native SQL injection and reflected XSS active probes",
                        "OWASP ZAP active scanning",
                        "Authorization and access-control testing"
                );
            }
            case ZAP_ACTIVE -> {
                included = List.of(
                        "Native passive response checks",
                        "Bounded native query-parameter SQL injection and reflected XSS probes; explicitly allowlisted POST-form probes when configured",
                        "OWASP ZAP spider, passive analysis, and scoped active scanning"
                );
                excluded = List.of("Authorization and access-control testing");
            }
            default -> {
                included = List.of("No scan checks are defined for this scan type");
                excluded = List.of();
            }
        }
        return new ScanExecutionSummary(
                job.getNativeEngineStatus(),
                job.getZapEngineStatus(),
                job.isZapRequested(),
                job.getZapFailureReason(),
                job.getZapSpiderStatus(),
                job.getZapSpiderDiscoveredCount(),
                job.getZapPassiveStatus(),
                job.getZapAlertCount(),
                job.getZapActiveStatus(),
                job.getNvdLookupStatus(),
                job.getDiscoveredPageCount(),
                job.getVisitedPageCount(),
                job.getTestedPassivePageCount(),
                included,
                excluded
        );
    }
}
