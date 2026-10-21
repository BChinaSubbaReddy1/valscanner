package com.vulnscanner.application.scan;

public enum ScanStatus {
    PENDING_APPROVAL,
    CREATED,
    QUEUED,
    CRAWLING,
    SCANNING,
    RUNNING,
    COMPLETED,
    FAILED,
    CANCELLED,
    REJECTED
}
