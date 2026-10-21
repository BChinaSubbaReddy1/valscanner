package com.vulnscanner.application.target;

import jakarta.validation.constraints.NotNull;

public record TargetDecisionRequest(
        @NotNull TargetDecision decision
) {
}
