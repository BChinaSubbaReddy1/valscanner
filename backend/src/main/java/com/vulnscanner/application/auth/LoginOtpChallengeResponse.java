package com.vulnscanner.application.auth;

import java.time.Instant;

public record LoginOtpChallengeResponse(
        String challengeToken,
        String maskedEmail,
        Instant expiresAt,
        Instant resendAvailableAt
) {
}
