package com.vulnscanner.application.auth;

import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

@Component
public class PasswordResetRateLimiter {
    private static final int MAX_TRACKED_KEYS_PER_OPERATION = 10_000;
    private static final Duration WINDOW = Duration.ofMinutes(15);

    private final Clock clock;
    private final Map<BucketKey, Window> windows = new HashMap<>();

    public PasswordResetRateLimiter() {
        this(Clock.systemUTC());
    }

    PasswordResetRateLimiter(Clock clock) {
        this.clock = clock;
    }

    public synchronized boolean tryAcquireLoginOtp(String remoteAddress) {
        return tryAcquire(Operation.LOGIN_OTP, normalize(remoteAddress), 20);
    }

    public synchronized boolean tryAcquireLoginOtpVerification(String challengeTokenHash) {
        return tryAcquire(Operation.LOGIN_OTP_VERIFICATION, challengeTokenHash, 10);
    }

    public synchronized boolean tryAcquireLoginOtpResend(String challengeTokenHash) {
        return tryAcquire(Operation.LOGIN_OTP_RESEND, challengeTokenHash, 5);
    }

    public synchronized boolean tryAcquirePasswordReset(String remoteAddress) {
        return tryAcquire(Operation.PASSWORD_RESET, normalize(remoteAddress), 5);
    }

    private boolean tryAcquire(Operation operation, String key, int maxRequests) {
        Instant now = clock.instant();
        Iterator<Map.Entry<BucketKey, Window>> iterator = windows.entrySet().iterator();
        while (iterator.hasNext()) {
            if (!now.isBefore(iterator.next().getValue().startedAt().plus(WINDOW))) {
                iterator.remove();
            }
        }

        BucketKey bucketKey = new BucketKey(operation, key);
        Window current = windows.get(bucketKey);
        if (current == null) {
            long trackedForOperation = windows.keySet().stream()
                    .filter(existing -> existing.operation() == operation)
                    .count();
            if (trackedForOperation >= MAX_TRACKED_KEYS_PER_OPERATION) {
                return false;
            }
            windows.put(bucketKey, new Window(now, 1));
            return true;
        }
        if (current.count() >= maxRequests) {
            return false;
        }
        windows.put(bucketKey, new Window(current.startedAt(), current.count() + 1));
        return true;
    }

    private String normalize(String value) {
        return value == null || value.isBlank() ? "unknown" : value;
    }

    private enum Operation {
        LOGIN_OTP,
        LOGIN_OTP_VERIFICATION,
        LOGIN_OTP_RESEND,
        PASSWORD_RESET
    }

    private record BucketKey(Operation operation, String key) {
    }

    private record Window(Instant startedAt, int count) {
    }
}
