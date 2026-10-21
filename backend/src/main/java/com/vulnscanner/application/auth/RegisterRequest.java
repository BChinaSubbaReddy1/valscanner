package com.vulnscanner.application.auth;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "First name is required")
        @Size(max = 150, message = "First name cannot exceed 150 characters")
        String firstName,

        @NotBlank(message = "Last name is required")
        @Size(max = 150, message = "Last name cannot exceed 150 characters")
        String lastName,

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        @Size(max = 255, message = "Email cannot exceed 255 characters")
        String email,

        @NotBlank(message = "Password is required")
        @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
        String password,

        @Size(max = 32, message = "Role cannot exceed 32 characters")
        String role,

        @Size(max = 150, message = "Organization name cannot exceed 150 characters")
        String organizationName,

        @Email(message = "Organization contact email must be valid")
        @Size(max = 255, message = "Organization contact email cannot exceed 255 characters")
        String organizationContactEmail
) {
    @JsonAnySetter
    public void rejectUnknownProperty(String property, Object value) {
        throw new IllegalArgumentException("Unsupported registration field: " + property);
    }
}
