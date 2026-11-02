package com.vulnscanner.application.scan;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

final class AdaptiveCheckSelector {
    private static final Set<String> DATABASE_INDICATORS = Set.of(
            "mysql", "mariadb", "postgres", "postgresql", "sqlite", "oracle", "sql server", "mssql");
    private static final Set<String> DATA_PARAMETER_INDICATORS = Set.of(
            "id", "q", "query", "search", "filter", "sort", "page", "item", "product",
            "user", "record", "order", "limit", "offset", "category");
    private static final Set<String> DATA_ENDPOINT_INDICATORS = Set.of(
            "search", "query", "filter", "item", "product", "user", "record", "catalog", "api");

    private AdaptiveCheckSelector() {
    }

    static Plan select(ScanType scanType, String endpoint, String contentType, Map<String, List<String>> headers,
                       List<String> parameterNames, boolean postForm, boolean explicitlyAllowedPost) {
        if (scanType != ScanType.ZAP_ACTIVE || parameterNames == null || parameterNames.isEmpty()) {
            return new Plan(false, false, List.of(), "Active checks are disabled or no input parameter was observed.");
        }
        if (postForm && !explicitlyAllowedPost) {
            return new Plan(false, false, List.of(), "POST form is not explicitly allowlisted.");
        }

        List<String> observedTechnology = observedDatabaseTechnology(headers);
        boolean htmlResponse = isHtml(contentType);
        boolean hasUsableParameter = parameterNames.stream()
                .anyMatch(name -> !ParameterSensitivity.isSensitive(name));
        boolean dataParameters = parameterNames.stream().filter(java.util.Objects::nonNull)
                .map(name -> name.toLowerCase(Locale.ROOT))
                .anyMatch(DATA_PARAMETER_INDICATORS::contains);
        boolean dataEndpoint = hasDataEndpoint(endpoint);
        boolean sqlRelevant = hasUsableParameter;
        List<String> selected = new ArrayList<>();
        if (sqlRelevant) {
            selected.add("SQL_INJECTION");
        }
        if (htmlResponse && hasUsableParameter) {
            selected.add("REFLECTED_XSS");
        }
        String method = postForm ? "allowlisted POST form" : "GET query";
        String sqlBasis = !observedTechnology.isEmpty()
                ? "response headers exposed database technology signature(s): "
                        + String.join(", ", observedTechnology)
                : dataParameters || dataEndpoint
                        ? "a data-oriented input name or endpoint was observed"
                        : "an eligible non-sensitive input was observed";
        String rationale = method + " parameters were observed; "
                + (sqlRelevant ? sqlBasis + " supports a bounded SQL check"
                : "no eligible non-sensitive input supports SQL probing")
                + (htmlResponse
                ? (hasUsableParameter
                        ? "; HTML response and usable input support a bounded reflection check"
                        : "; HTML response had no usable input for a reflection check")
                : "; response media type does not support an HTML reflection check");
        return new Plan(sqlRelevant, htmlResponse && hasUsableParameter,
                List.copyOf(observedTechnology), rationale);
    }

    private static List<String> observedDatabaseTechnology(Map<String, List<String>> headers) {
        if (headers == null || headers.isEmpty()) {
            return List.of();
        }
        String observedHeaders = headers.entrySet().stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase("server")
                        || entry.getKey().equalsIgnoreCase("x-powered-by")
                        || entry.getKey().equalsIgnoreCase("x-backend"))
                .flatMap(entry -> entry.getValue().stream())
                .map(value -> value.toLowerCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.joining(" "));
        return DATABASE_INDICATORS.stream().filter(observedHeaders::contains).sorted().toList();
    }

    private static boolean isHtml(String contentType) {
        if (contentType == null) {
            return false;
        }
        String mediaType = contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        return "text/html".equals(mediaType) || "application/xhtml+xml".equals(mediaType);
    }

    private static boolean hasDataEndpoint(String endpoint) {
        if (endpoint == null) {
            return false;
        }
        try {
            String path = java.net.URI.create(endpoint).getRawPath();
            return path != null && DATA_ENDPOINT_INDICATORS.stream()
                    .anyMatch(indicator -> path.toLowerCase(Locale.ROOT).contains(indicator));
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    record Plan(boolean sqlInjection, boolean reflectedXss,
                 List<String> observedDatabaseTechnology, String rationale) {
        int requestsPerParameter() {
            return (sqlInjection ? 2 : 0) + (reflectedXss ? 1 : 0);
        }

        List<String> selectedChecks() {
            List<String> checks = new ArrayList<>();
            if (sqlInjection) {
                checks.add("SQL_INJECTION");
            }
            if (reflectedXss) {
                checks.add("REFLECTED_XSS");
            }
            return List.copyOf(checks);
        }
    }
}
