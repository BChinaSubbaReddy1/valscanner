package com.vulnscanner.application.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record LoginOtpVerificationRequest(
        @NotBlank(message = "Login verification is invalid or expired")
        @Pattern(regexp = "[A-Za-z0-9_-]{43}", message = "Login verification is invalid or expired")
        String challengeToken,

        @NotBlank(message = "Login verification is invalid or expired")
        @Pattern(regexp = "[0-9]{6}", message = "Login verification is invalid or expired")
        String otp
) {
}
