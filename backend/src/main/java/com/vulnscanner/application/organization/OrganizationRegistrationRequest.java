package com.vulnscanner.application.organization;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record OrganizationRegistrationRequest(
        @NotBlank(message = "Organization name is required")
        @Size(max = 150, message = "Organization name cannot exceed 150 characters")
        String name,

        @NotBlank(message = "Contact email is required")
        @Email(message = "Contact email must be valid")
        @Size(max = 255, message = "Contact email cannot exceed 255 characters")
        String contactEmail,

        @NotBlank(message = "Primary contact name is required")
        @Size(max = 255, message = "Primary contact name cannot exceed 255 characters")
        String primaryContactName
) {
}
