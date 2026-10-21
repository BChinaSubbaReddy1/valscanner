package com.vulnscanner.application.target;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record TargetCreateRequest(
        @NotBlank @Size(max = 150) String name,
        @NotBlank @Size(max = 2048) String url,
        @NotNull TargetType type
) {
}
