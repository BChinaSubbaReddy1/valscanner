package com.vulnscanner.application.scan;

import java.util.regex.Pattern;

public final class FindingSanitizer {
    private static final Pattern BEARER = Pattern.compile("(?i)(bearer\\s+)[a-z0-9._~+/-]+=*");
    private static final Pattern SENSITIVE_ASSIGNMENT =
            Pattern.compile("(?i)(password|passwd|token|secret|authorization|api[_-]?key|jwt|session)\\s*[:=]\\s*[^&\\s,;<>\\\"]+");
    private static final Pattern SENSITIVE_URL_PARAMETER =
            Pattern.compile("(?i)([?&](?:password|token|secret|api[_-]?key|authorization|jwt|cookie|session)=)[^&#\\s]+");
    private static final Pattern COOKIE_VALUE =
            Pattern.compile("(?i)(set-cookie\\s*:\\s*[^=;\\s]+)=([^;\\r\\n]*)");
    private static final Pattern COOKIE_ASSIGNMENT =
            Pattern.compile("(?i)(?<![a-z0-9-])(cookie\\s*[:=]\\s*)[^&\\s,;<>\\\"]+");

    private FindingSanitizer() {
    }

    public static String sanitize(String input) {
        if (input == null) {
            return null;
        }
        return SENSITIVE_URL_PARAMETER.matcher(
                SENSITIVE_ASSIGNMENT.matcher(
                        COOKIE_ASSIGNMENT.matcher(
                                COOKIE_VALUE.matcher(BEARER.matcher(input)
                                        .replaceAll("$1[REDACTED]"))
                                        .replaceAll("$1=[REDACTED]"))
                                .replaceAll("$1[REDACTED]"))
                        .replaceAll("$1=[REDACTED]"))
                .replaceAll("$1[REDACTED]");
    }
}
