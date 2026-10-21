package com.vulnscanner.application.scan;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ScanRejectRequest(
        @NotBlank @Size(max = 1000) String reason
) {
}
