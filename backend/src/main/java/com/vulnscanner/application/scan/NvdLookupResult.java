package com.vulnscanner.application.scan;

import java.util.List;
import java.util.Objects;

public record NvdLookupResult(NvdLookupStatus status, List<CveMatch> candidates) {
    public NvdLookupResult {
        Objects.requireNonNull(status, "status is required");
        candidates = List.copyOf(candidates);
    }
}
