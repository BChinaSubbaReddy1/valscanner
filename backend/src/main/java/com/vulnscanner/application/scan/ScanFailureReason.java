package com.vulnscanner.application.scan;

public enum ScanFailureReason {
    EXECUTOR_UNAVAILABLE,
    TARGET_URL_INVALID,
    OUTBOUND_REQUEST_FAILED,
    RESPONSE_LIMIT_EXCEEDED,
    TIME_BUDGET_EXCEEDED
}
