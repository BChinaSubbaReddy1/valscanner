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
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Service
public class ZapClientService {
    private static final Logger log = LoggerFactory.getLogger(ZapClientService.class);

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
        if (!enabled) {
            return false;
        }
        try {
            HttpRequest request = newRequestBuilder("/JSON/core/view/version/")
                    .timeout(connectTimeout)
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return response.statusCode() == 200;
        } catch (Exception exception) {
            log.debug("OWASP ZAP health check failed: {}", exception.getMessage());
            return false;
        }
    }

    public String startSpider(String targetUrl) throws IOException, InterruptedException {
        String encodedUrl = URLEncoder.encode(targetUrl, StandardCharsets.UTF_8);
        String path = "/JSON/spider/action/scan/?url=" + encodedUrl;
        JsonNode json = executeRequest(path);
        return json.path("scan").asText(null);
    }

    public int getSpiderProgress(String scanId) throws IOException, InterruptedException {
        if (scanId == null || scanId.isBlank()) {
            return 100;
        }
        String path = "/JSON/spider/view/status/?scanId=" + URLEncoder.encode(scanId, StandardCharsets.UTF_8);
        JsonNode json = executeRequest(path);
        return json.path("status").asInt(100);
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
        String encodedUrl = URLEncoder.encode(targetUrl, StandardCharsets.UTF_8);
        String path = "/JSON/ascan/action/scan/?url=" + encodedUrl + "&recurse=true";
        JsonNode json = executeRequest(path);
        return json.path("scan").asText(null);
    }

    public int getActiveScanProgress(String scanId) throws IOException, InterruptedException {
        if (scanId == null || scanId.isBlank()) {
            return 100;
        }
        String path = "/JSON/ascan/view/status/?scanId=" + URLEncoder.encode(scanId, StandardCharsets.UTF_8);
        JsonNode json = executeRequest(path);
        return json.path("status").asInt(100);
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
            return List.of();
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

    private JsonNode executeRequest(String relativePath) throws IOException, InterruptedException {
        HttpRequest request = newRequestBuilder(relativePath)
                .timeout(readTimeout)
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() != 200) {
            throw new IOException("ZAP API request to " + sanitizePath(relativePath)
                    + " returned HTTP " + response.statusCode());
        }
        return objectMapper.readTree(response.body());
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
}
