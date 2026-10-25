package com.vulnscanner.application.scan;

import org.springframework.stereotype.Component;

import java.util.Locale;

@Component
public class ZapScanAdapter {

    public ScanFinding toFinding(ScanJob job, ZapAlert alert) {
        String checkType = mapCheckType(alert.alert());
        String severity = mapSeverity(alert.risk());
        String verificationStatus = mapVerificationStatus(alert.confidence());

        String component = alert.url() != null ? alert.url() : "";
        if (alert.param() != null && !alert.param().isBlank()) {
            component = component + " [" + alert.param().trim() + "]";
        }

        String evidence = (alert.evidence() != null && !alert.evidence().isBlank())
                ? alert.evidence()
                : ((alert.attack() != null && !alert.attack().isBlank()) ? alert.attack() : alert.alert());

        String rationale = (alert.description() != null && !alert.description().isBlank())
                ? alert.description()
                : "Identified by OWASP ZAP automated scanner.";

        String remediation = (alert.solution() != null && !alert.solution().isBlank())
                ? alert.solution()
                : "Review OWASP security guidance for " + alert.alert() + ".";

        ScanFinding finding = new ScanFinding(
                job,
                bounded(checkType, 64),
                severity,
                bounded(FindingSanitizer.sanitize(component), 2048),
                bounded(FindingSanitizer.sanitize(evidence), 1000),
                bounded(FindingSanitizer.sanitize(rationale), 1000),
                bounded(FindingSanitizer.sanitize(remediation), 1000),
                "OWASP_ZAP",
                verificationStatus
        );
        finding.setSourceMetadata(
                bounded(FindingSanitizer.sanitize(alert.pluginId()), 64),
                bounded(FindingSanitizer.sanitize(alert.confidence()), 16),
                bounded(FindingSanitizer.sanitize(alert.reference()), 2048),
                bounded(FindingSanitizer.sanitize(alert.cweid()), 16),
                bounded(FindingSanitizer.sanitize(alert.wascid()), 16)
        );
        return finding;
    }

    public String mapSeverity(String risk) {
        if (risk == null) {
            return "LOW";
        }
        return switch (risk.trim().toLowerCase(Locale.ROOT)) {
            case "high" -> "HIGH";
            case "medium" -> "MEDIUM";
            case "low", "informational" -> "LOW";
            default -> "LOW";
        };
    }

    public String mapVerificationStatus(String confidence) {
        if (confidence == null) {
            return "POTENTIAL";
        }
        return switch (confidence.trim().toLowerCase(Locale.ROOT)) {
            case "high" -> "OBSERVED";
            case "medium" -> "OBSERVED";
            default -> "POTENTIAL";
        };
    }

    public String mapCheckType(String alertName) {
        if (alertName == null || alertName.isBlank()) {
            return "ZAP_ALERT";
        }
        String normalized = alertName.trim().toLowerCase(Locale.ROOT);

        if (normalized.contains("x-frame-options") || normalized.contains("clickjacking")) {
            return "MISSING_FRAME_PROTECTION";
        }
        if (normalized.contains("content security policy") || normalized.contains("csp")) {
            return "MISSING_CONTENT_SECURITY_POLICY";
        }
        if (normalized.contains("x-content-type-options")) {
            return "MISSING_CONTENT_TYPE_OPTIONS";
        }
        if (normalized.contains("strict-transport-security") || normalized.contains("hsts")) {
            return "MISSING_STRICT_TRANSPORT_SECURITY";
        }
        if (normalized.contains("sql injection")) {
            return "SQL_INJECTION_SUSPECTED";
        }
        if (normalized.contains("cross site scripting") || normalized.contains("xss")) {
            return "REFLECTED_XSS_POTENTIAL";
        }
        if (normalized.contains("httponly")) {
            return "COOKIE_MISSING_HTTP_ONLY";
        }
        if (normalized.contains("cookie") && normalized.contains("secure")) {
            return "COOKIE_MISSING_SECURE";
        }
        if (normalized.contains("samesite")) {
            return "COOKIE_MISSING_SAMESITE";
        }
        if (normalized.contains("server leaks") || normalized.contains("server header")) {
            return "INFORMATION_DISCLOSURE_SERVER";
        }
        if (normalized.contains("x-powered-by")) {
            return "INFORMATION_DISCLOSURE_X-POWERED-BY";
        }

        // Generic ZAP identifier
        String slug = normalized.replaceAll("[^a-z0-9]+", "_").replaceAll("^_+|_+$", "").toUpperCase(Locale.ROOT);
        String result = "ZAP_" + slug;
        return result.length() <= 64 ? result : result.substring(0, 64);
    }

    private String bounded(String value, int maxLength) {
        if (value == null) {
            return "";
        }
        return value.length() <= maxLength ? value : value.substring(0, maxLength - 3) + "...";
    }
}
