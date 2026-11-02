package com.vulnscanner.application.scan;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingSanitizerTest {

    @Test
    void redactsSensitiveValuesAcrossFindingSources() {
        String sanitized = FindingSanitizer.sanitize(
                "Bearer abc.def_ghi password=hunter2 https://example.invalid/?token=reset-value "
                        + "Set-Cookie: session=cookie-value; HttpOnly");

        assertTrue(sanitized.contains("Bearer [REDACTED]"));
        assertTrue(sanitized.contains("password=[REDACTED]"));
        assertTrue(sanitized.contains("token=[REDACTED]"));
        assertTrue(sanitized.contains("Set-Cookie: session=[REDACTED]"));
        assertFalse(sanitized.contains("hunter2"));
        assertFalse(sanitized.contains("reset-value"));
        assertFalse(sanitized.contains("cookie-value"));
    }

    @Test
    void endpointMetadataDropsQueryValuesAndCookieSessionIdentifiersAreRedacted() {
        String endpoint = FindingSanitizer.safeEndpoint(
                "https://example.test/search?token=hidden&q=term#fragment");
        String sanitized = FindingSanitizer.sanitize(
                "Cookie: JSESSIONID=hidden-session; sid=hidden-sid");

        assertEquals("https://example.test/search?token&q", endpoint);
        assertFalse(endpoint.contains("hidden"));
        assertFalse(endpoint.contains("term"));
        assertFalse(endpoint.contains("fragment"));
        assertFalse(sanitized.contains("hidden-session"));
        assertFalse(sanitized.contains("hidden-sid"));
        assertTrue(FindingSanitizer.safeEndpoint("file:///etc/passwd") == null);
    }
}
