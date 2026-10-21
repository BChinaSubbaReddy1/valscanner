package com.vulnscanner.application.scan;

import java.time.Instant;

public record ScanCrawlPageResponse(
        Long id,
        String url,
        int depth,
        int statusCode,
        int responseBytes,
        int discoveredLinks,
        Instant discoveredAt) {
}
