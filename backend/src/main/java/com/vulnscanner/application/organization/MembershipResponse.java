package com.vulnscanner.application.organization;

import com.vulnscanner.application.user.UserStatus;

import java.time.Instant;
import java.util.List;

public record MembershipResponse(
        Long userId,
        String displayName,
        List<String> roles,
        UserStatus status,
        Instant requestedAt
) {
}
