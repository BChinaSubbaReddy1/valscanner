package com.vulnscanner.application.scan;

import org.junit.jupiter.api.Test;

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
}
