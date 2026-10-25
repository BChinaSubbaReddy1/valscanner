package com.vulnscanner.application.scan;

import jakarta.persistence.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.List;

@Entity
@Table(name = "scan_crawl_pages", indexes = {
        @Index(name = "idx_scan_crawl_pages_scan", columnList = "scan_job_id"),
        @Index(name = "uk_scan_crawl_pages_url_hash", columnList = "scan_job_id,url_hash", unique = true)
})
public class ScanCrawlPage {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "scan_job_id", nullable = false)
    private ScanJob scanJob;

    @Column(nullable = false, length = 2048)
    private String url;

    @Column(name = "url_hash", nullable = false, length = 64)
    private String urlHash;

    @Column(nullable = false)
    private int depth;

    @Column(nullable = false)
    private int statusCode;

    @Column(nullable = false)
    private int responseBytes;

    @Column(nullable = false)
    private int discoveredLinks;

    @Convert(converter = DiscoveredFormsConverter.class)
    @Column(name = "discovered_forms_json", columnDefinition = "TEXT")
    private List<DiscoveredForm> discoveredForms = List.of();

    @Column(nullable = false, updatable = false)
    private Instant discoveredAt = Instant.now();

    protected ScanCrawlPage() {
    }

    public ScanCrawlPage(ScanJob scanJob, String url, int depth, int statusCode,
                         int responseBytes, int discoveredLinks) {
        this(scanJob, url, depth, statusCode, responseBytes, discoveredLinks, List.of());
    }

    public ScanCrawlPage(ScanJob scanJob, String url, int depth, int statusCode,
                         int responseBytes, int discoveredLinks, List<DiscoveredForm> discoveredForms) {
        this.scanJob = scanJob;
        this.url = url;
        this.urlHash = hashUrl(url);
        this.depth = depth;
        this.statusCode = statusCode;
        this.responseBytes = responseBytes;
        this.discoveredLinks = discoveredLinks;
        this.discoveredForms = discoveredForms == null ? List.of() : List.copyOf(discoveredForms);
    }

    public Long getId() { return id; }
    public String getUrl() { return url; }
    public int getDepth() { return depth; }
    public int getStatusCode() { return statusCode; }
    public int getResponseBytes() { return responseBytes; }
    public int getDiscoveredLinks() { return discoveredLinks; }
    public List<DiscoveredForm> getDiscoveredForms() { return List.copyOf(discoveredForms); }
    public Instant getDiscoveredAt() { return discoveredAt; }

    @PrePersist
    @PreUpdate
    private void ensureUrlHash() {
        if (urlHash == null && url != null) {
            urlHash = hashUrl(url);
        }
    }

    private static String hashUrl(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte item : digest) {
                hex.append(String.format("%02x", item));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
