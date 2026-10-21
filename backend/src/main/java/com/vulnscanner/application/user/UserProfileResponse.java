package com.vulnscanner.application.user;

import com.vulnscanner.application.organization.OrganizationStatus;

import java.util.List;

public record UserProfileResponse(
        Long id,
        String email,
        String firstName,
        String lastName,
        Long organizationId,
        String organizationName,
        OrganizationStatus organizationStatus,
        List<String> roles,
        UserStatus accountStatus,
        String membershipApprovalStatus
) {
}
