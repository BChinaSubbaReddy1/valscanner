package com.vulnscanner.application.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class PasswordResetRateLimiterTest {
    private MutableClock clock;
    private PasswordResetRateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        rateLimiter = new PasswordResetRateLimiter(clock);
    }

    @Test
    void loginGenerationAllowsTwentyRequestsPerIpWithoutSharingPasswordResetAllowance() {
        for (int request = 0; request < 20; request++) {
            assertTrue(rateLimiter.tryAcquireLoginOtp("192.0.2.50"));
        }
        assertFalse(rateLimiter.tryAcquireLoginOtp("192.0.2.50"));

        for (int request = 0; request < 5; request++) {
            assertTrue(rateLimiter.tryAcquirePasswordReset("192.0.2.50"));
        }
        assertFalse(rateLimiter.tryAcquirePasswordReset("192.0.2.50"));
        assertTrue(rateLimiter.tryAcquireLoginOtp("192.0.2.51"));
    }

    @Test
    void verificationAndResendLimitsAreIndependentAndScopedToChallenge() {
        for (int request = 0; request < 10; request++) {
            assertTrue(rateLimiter.tryAcquireLoginOtpVerification("challenge-a"));
        }
        assertFalse(rateLimiter.tryAcquireLoginOtpVerification("challenge-a"));
        assertTrue(rateLimiter.tryAcquireLoginOtpVerification("challenge-b"));

        for (int request = 0; request < 5; request++) {
            assertTrue(rateLimiter.tryAcquireLoginOtpResend("challenge-a"));
        }
        assertFalse(rateLimiter.tryAcquireLoginOtpResend("challenge-a"));
        assertTrue(rateLimiter.tryAcquireLoginOtpResend("challenge-b"));
    }

    @Test
    void rateLimitWindowsResetAfterFifteenMinutes() {
        for (int request = 0; request < 20; request++) {
            assertTrue(rateLimiter.tryAcquireLoginOtp("192.0.2.50"));
        }
        assertFalse(rateLimiter.tryAcquireLoginOtp("192.0.2.50"));

        clock.advance(Duration.ofMinutes(15));

        assertTrue(rateLimiter.tryAcquireLoginOtp("192.0.2.50"));
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> instant;

        private MutableClock(Instant initialInstant) {
            instant = new AtomicReference<>(initialInstant);
        }

        private void advance(Duration duration) {
            instant.updateAndGet(current -> current.plus(duration));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant.get();
        }
    }
}
