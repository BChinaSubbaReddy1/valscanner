package com.vulnscanner.application.scan;

import java.time.Instant;
import java.util.List;

public record ScanCrawlPageResponse(
        Long id,
        String url,
        int depth,
        int statusCode,
        int responseBytes,
        int discoveredLinks,
        List<DiscoveredForm> discoveredForms,
        Instant discoveredAt) {
}
