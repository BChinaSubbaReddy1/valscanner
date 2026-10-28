package com.vulnscanner.application.scan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpTimeoutException;
import java.util.regex.Pattern;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Service
public class ZapClientService {
    private static final Logger log = LoggerFactory.getLogger(ZapClientService.class);
    private static final int MAX_ALERTS = 1000;
    private static final int MAX_API_RESPONSE_BYTES = 2_097_152;

    private final String baseUrl;
    private final String apiKey;
    private final boolean enabled;
    private final Duration connectTimeout;
    private final Duration readTimeout;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    @Autowired
    public ZapClientService(
            @Value("${scanner.zap.base-url:http://localhost:8090}") String baseUrl,
            @Value("${scanner.zap.api-key:}") String apiKey,
            @Value("${scanner.zap.enabled:false}") boolean enabled,
            @Value("${scanner.zap.connect-timeout-seconds:5}") int connectTimeoutSeconds,
            @Value("${scanner.zap.read-timeout-seconds:15}") int readTimeoutSeconds,
            ObjectMapper objectMapper) {
        this(baseUrl, apiKey, enabled, connectTimeoutSeconds, readTimeoutSeconds, objectMapper, null);
    }

    ZapClientService(
            String baseUrl,
            String apiKey,
            boolean enabled,
            int connectTimeoutSeconds,
            int readTimeoutSeconds,
            ObjectMapper objectMapper,
            HttpClient httpClient) {
        this.baseUrl = (baseUrl == null || baseUrl.isBlank()) ? "http://localhost:8090" : baseUrl.replaceAll("/+$", "");
        this.apiKey = apiKey != null ? apiKey.trim() : "";
        this.enabled = enabled;
        this.connectTimeout = Duration.ofSeconds(Math.max(1, connectTimeoutSeconds));
        this.readTimeout = Duration.ofSeconds(Math.max(1, readTimeoutSeconds));
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
        this.httpClient = httpClient != null ? httpClient : HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(this.connectTimeout)
                .build();
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isAvailable() {
        return checkAvailability() == AvailabilityStatus.AVAILABLE;
    }

    public AvailabilityStatus checkAvailability() {
        if (!enabled) {
            return AvailabilityStatus.UNAVAILABLE;
        }
        try {
            HttpRequest request = newRequestBuilder("/JSON/core/view/version/")
                    .timeout(readTimeout)
                    .GET()
                    .build();
            HttpResponse<byte[]> response = BoundedHttpResponse.send(
                    httpClient, request, MAX_API_RESPONSE_BYTES, readTimeout);
            if (response.statusCode() == 401 || response.statusCode() == 403) {
                log.warn("OWASP ZAP health check authentication failed (HTTP {})", response.statusCode());
                return AvailabilityStatus.UNAVAILABLE;
            }
            if (response.statusCode() != 200) {
                log.warn("OWASP ZAP health check returned HTTP {}", response.statusCode());
                return AvailabilityStatus.UNAVAILABLE;
            }
            JsonNode json = objectMapper.readTree(new String(response.body(), StandardCharsets.UTF_8));
            if (json.path("version").asText("").isBlank()) {
                log.warn("OWASP ZAP health check returned an invalid version response");
                return AvailabilityStatus.UNAVAILABLE;
            }
            return AvailabilityStatus.AVAILABLE;
        } catch (HttpTimeoutException exception) {
            log.warn("OWASP ZAP health check timed out");
            return AvailabilityStatus.TIMED_OUT;
        } catch (IOException exception) {
            log.warn("OWASP ZAP health check communication or response failed ({})",
                    exception.getClass().getSimpleName());
            return AvailabilityStatus.UNAVAILABLE;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            log.warn("OWASP ZAP health check was interrupted");
            return AvailabilityStatus.UNAVAILABLE;
        }
    }

    public String startSpider(String targetUrl) throws IOException, InterruptedException {
        return startSpider(targetUrl, null);
    }

    public ScopeContext createTargetContext(URI target, String contextName)
            throws IOException, InterruptedException {
        JsonNode context = executeRequest("/JSON/context/action/newContext/?contextName="
                + URLEncoder.encode(contextName, StandardCharsets.UTF_8));
        String contextId = context.path("contextId").asText("");
        if (contextId.isBlank()) {
            throw new IOException("ZAP did not create a target context");
        }
        ScopeContext created = new ScopeContext(contextName, contextId);
        try {
            String originPattern = "^" + Pattern.quote(target.getScheme() + "://" + target.getRawAuthority())
                    + "(?:/.*)?$";
            String includePath = "/JSON/context/action/includeInContext/?contextName="
                    + URLEncoder.encode(contextName, StandardCharsets.UTF_8)
                    + "&regex=" + URLEncoder.encode(originPattern, StandardCharsets.UTF_8);
            JsonNode includeResult = executeRequest(includePath);
            if (!"OK".equalsIgnoreCase(includeResult.path("Result").asText())) {
                throw new IOException("ZAP did not apply the target-origin scope");
            }
            return created;
        } catch (IOException | InterruptedException exception) {
            removeContext(created);
            throw exception;
        }
    }

    public void removeContext(ScopeContext context) {
        if (context == null) {
            return;
        }
        try {
            executeRequest("/JSON/context/action/removeContext/?contextName="
                    + URLEncoder.encode(context.name(), StandardCharsets.UTF_8));
        } catch (Exception exception) {
            log.warn("Failed to remove temporary ZAP scan context ({})", exception.getClass().getSimpleName());
        }
    }

    public String startSpider(String targetUrl, String contextName) throws IOException, InterruptedException {
        String encodedUrl = URLEncoder.encode(targetUrl, StandardCharsets.UTF_8);
        String path = "/JSON/spider/action/scan/?url=" + encodedUrl
                + (contextName == null ? "" : "&contextName=" + URLEncoder.encode(contextName, StandardCharsets.UTF_8))
                + "&maxChildren=10&maxDepth=2";
        JsonNode json = executeRequest(path);
        return requiredScanId(json, "spider");
    }

    public int getSpiderProgress(String scanId) throws IOException, InterruptedException {
        requireScanId(scanId, "spider");
        String path = "/JSON/spider/view/status/?scanId=" + URLEncoder.encode(scanId, StandardCharsets.UTF_8);
        JsonNode json = executeRequest(path);
        return requiredProgress(json, "spider");
    }

    public int getSpiderDiscoveredCount(String scanId) throws IOException, InterruptedException {
        requireScanId(scanId, "spider");
        String path = "/JSON/spider/view/results/?scanId=" + URLEncoder.encode(scanId, StandardCharsets.UTF_8);
        JsonNode json = executeRequest(path);
        JsonNode results = json.get("results");
        if (results == null || !results.isArray() || results.size() > 10000) {
            throw new IOException("ZAP spider results response is invalid");
        }
        return results.size();
    }

    public void stopSpider(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return;
        }
        try {
            String path = "/JSON/spider/action/stop/?scanId=" + URLEncoder.encode(scanId, StandardCharsets.UTF_8);
            executeRequest(path);
        } catch (Exception ignored) {
            log.warn("Failed to stop ZAP spider scanId {}", scanId);
        }
    }

    public String startActiveScan(String targetUrl) throws IOException, InterruptedException {
        return startActiveScan(targetUrl, null);
    }

    public String startActiveScan(String targetUrl, ScopeContext context) throws IOException, InterruptedException {
        if (context == null || context.id().isBlank()) {
            throw new IOException("A scoped ZAP context is required for active scanning");
        }
        String encodedUrl = URLEncoder.encode(targetUrl, StandardCharsets.UTF_8);
        String path = "/JSON/ascan/action/scan/?url=" + encodedUrl
                + "&recurse=true&inScopeOnly=true&contextId="
                + URLEncoder.encode(context.id(), StandardCharsets.UTF_8)
                + "&maxScanDurationInMins=1&maxRuleDurationInMins=1&maxAlertsPerRule=10";
        JsonNode json = executeRequest(path);
        return requiredScanId(json, "active");
    }

    public int getActiveScanProgress(String scanId) throws IOException, InterruptedException {
        requireScanId(scanId, "active");
        String path = "/JSON/ascan/view/status/?scanId=" + URLEncoder.encode(scanId, StandardCharsets.UTF_8);
        JsonNode json = executeRequest(path);
        return requiredProgress(json, "active");
    }

    public int getPassiveScanRecordsToScan() throws IOException, InterruptedException {
        JsonNode json = executeRequest("/JSON/pscan/view/recordsToScan/");
        JsonNode records = json.get("recordsToScan");
        if (records == null || !records.asText().matches("\\d{1,8}")) {
            throw new IOException("ZAP passive scan queue response is invalid");
        }
        try {
            return Integer.parseInt(records.asText());
        } catch (NumberFormatException exception) {
            throw new IOException("ZAP passive scan queue response is invalid", exception);
        }
    }

    public void stopActiveScan(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return;
        }
        try {
            String path = "/JSON/ascan/action/stop/?scanId=" + URLEncoder.encode(scanId, StandardCharsets.UTF_8);
            executeRequest(path);
        } catch (Exception ignored) {
            log.warn("Failed to stop ZAP active scanId {}", scanId);
        }
    }

    public List<ZapAlert> getAlerts(String targetBaseUrl) throws IOException, InterruptedException {
        String encodedUrl = URLEncoder.encode(targetBaseUrl, StandardCharsets.UTF_8);
        String path = "/JSON/core/view/alerts/?baseurl=" + encodedUrl;
        JsonNode json = executeRequest(path);
        JsonNode alertsNode = json.path("alerts");
        if (!alertsNode.isArray()) {
            throw new IOException("ZAP returned an invalid alerts response");
        }
        if (alertsNode.size() > MAX_ALERTS) {
            throw new IOException("ZAP alert response exceeded the configured limit");
        }

        List<ZapAlert> alerts = new ArrayList<>();
        for (JsonNode node : alertsNode) {
            alerts.add(new ZapAlert(
                    node.path("pluginId").asText(""),
                    node.path("alert").asText(""),
                    node.path("risk").asText("Informational"),
                    node.path("confidence").asText("Low"),
                    node.path("url").asText(targetBaseUrl),
                    node.path("param").asText(""),
                    node.path("attack").asText(""),
                    node.path("evidence").asText(""),
                    node.path("description").asText(""),
                    node.path("solution").asText(""),
                    node.path("reference").asText(""),
                    node.path("cweid").asText(""),
                    node.path("wascid").asText("")
            ));
        }
        return alerts;
    }

    private String requiredScanId(JsonNode response, String scanType) throws IOException {
        String scanId = response.path("scan").asText("");
        if (scanId.isBlank()) {
            throw new IOException("ZAP did not return a " + scanType + " scan ID");
        }
        return scanId;
    }

    private void requireScanId(String scanId, String scanType) throws IOException {
        if (scanId == null || scanId.isBlank()) {
            throw new IOException("ZAP " + scanType + " scan ID is missing");
        }
    }

    private int requiredProgress(JsonNode response, String scanType) throws IOException {
        JsonNode progress = response.get("status");
        if (progress == null || !progress.asText().matches("\\d{1,3}")) {
            throw new IOException("ZAP " + scanType + " progress response is invalid");
        }
        int value;
        try {
            value = Integer.parseInt(progress.asText());
        } catch (NumberFormatException exception) {
            throw new IOException("ZAP " + scanType + " progress response is invalid", exception);
        }
        if (value < 0 || value > 100) {
            throw new IOException("ZAP " + scanType + " progress is outside the valid range");
        }
        return value;
    }

    private JsonNode executeRequest(String relativePath) throws IOException, InterruptedException {
        HttpRequest request = newRequestBuilder(relativePath)
                .timeout(readTimeout)
                .GET()
                .build();
        HttpResponse<byte[]> response = BoundedHttpResponse.send(
                httpClient, request, MAX_API_RESPONSE_BYTES, readTimeout);
        if (response.statusCode() != 200) {
            throw new IOException("ZAP API request to " + sanitizePath(relativePath)
                    + " returned HTTP " + response.statusCode());
        }
        return objectMapper.readTree(new String(response.body(), StandardCharsets.UTF_8));
    }

    private HttpRequest.Builder newRequestBuilder(String relativePath) {
        String url = baseUrl + relativePath;
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .header("Accept", "application/json");
        if (!apiKey.isBlank()) {
            builder.header("X-ZAP-API-Key", apiKey);
        }
        return builder;
    }

    private String sanitizePath(String path) {
        // Redact any query param api keys from error paths
        return path.replaceAll("(?i)(apikey=)[^&]+", "$1[REDACTED]");
    }

    public record ScopeContext(String name, String id) {
    }

    public enum AvailabilityStatus {
        AVAILABLE,
        UNAVAILABLE,
        TIMED_OUT
    }
}
