package com.vulnscanner.application.scan;

import jakarta.validation.constraints.NotNull;

public record ScanCreateRequest(
        @NotNull Long targetId,
        @NotNull ScanType scanType
) {
}
