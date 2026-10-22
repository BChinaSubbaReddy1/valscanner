package com.vulnscanner.application.scan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class NvdCveService {
    private static final Logger log = LoggerFactory.getLogger(NvdCveService.class);
    private static final int MAX_NVD_RESPONSE_BYTES = 2_097_152;
    private static final Pattern SOFTWARE_VERSION_PATTERN =
            Pattern.compile("(?i)^([a-zA-Z0-9_-]+)/(\\d+(?:\\.\\d+)*(?:[a-zA-Z0-9_.-]+)?)$");

    private final String apiUrl;
    private final String apiKey;
    private final boolean enabled;
    private final Duration timeout;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private static final int MAX_CACHE_ENTRIES = 256;
    private final Map<String, List<CveMatch>> cache = Collections.synchronizedMap(
            new LinkedHashMap<>(32, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, List<CveMatch>> eldest) {
                    return size() > MAX_CACHE_ENTRIES;
                }
            });

    @org.springframework.beans.factory.annotation.Autowired
    public NvdCveService(
            @Value("${scanner.nvd.api-url:https://services.nvd.nist.gov/rest/json/cves/2.0}") String apiUrl,
            @Value("${scanner.nvd.api-key:}") String apiKey,
            @Value("${scanner.nvd.enabled:true}") boolean enabled,
            @Value("${scanner.nvd.timeout-seconds:5}") int timeoutSeconds,
            ObjectMapper objectMapper) {
        this(apiUrl, apiKey, enabled, timeoutSeconds, objectMapper, null);
    }

    NvdCveService(
            String apiUrl,
            String apiKey,
            boolean enabled,
            int timeoutSeconds,
            ObjectMapper objectMapper,
            HttpClient httpClient) {
        this.apiUrl = (apiUrl == null || apiUrl.isBlank())
                ? "https://services.nvd.nist.gov/rest/json/cves/2.0" : apiUrl.trim();
        this.apiKey = apiKey != null ? apiKey.trim() : "";
        this.enabled = enabled;
        this.timeout = Duration.ofSeconds(Math.max(1, timeoutSeconds));
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
        this.httpClient = httpClient != null ? httpClient : HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(this.timeout)
                .build();
    }

    public SoftwareVersion parseSoftwareVersion(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            return null;
        }
        for (String token : rawValue.split("\\s+")) {
            Matcher matcher = SOFTWARE_VERSION_PATTERN.matcher(token.trim());
            if (matcher.matches()) {
                String software = matcher.group(1).trim();
                String version = matcher.group(2).trim();
                if (!software.isBlank() && !version.isBlank() && version.matches(".*\\d.*")) {
                    return new SoftwareVersion(software, version);
                }
            }
        }
        return null;
    }

    public List<CveMatch> findCves(String software, String version) {
        if (!enabled || software == null || software.isBlank() || version == null || version.isBlank()) {
            return List.of();
        }

        String cacheKey = (software + ":" + version).toLowerCase(Locale.ROOT);
        List<CveMatch> cached = cache.get(cacheKey);
        if (cached != null) {
            return cached;
        }
        List<CveMatch> result = queryNvd(software, version);
        if (result != null) {
            cache.put(cacheKey, result);
            return result;
        }
        return List.of();
    }

    private List<CveMatch> queryNvd(String software, String version) {
        try {
            String keyword = software + " " + version;
            String encodedKeyword = URLEncoder.encode(keyword, StandardCharsets.UTF_8);
            String url = apiUrl + (apiUrl.contains("?") ? "&" : "?") + "keywordSearch=" + encodedKeyword
                    + "&resultsPerPage=5";

            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(URI.create(url))
                    .timeout(timeout)
                    .header("User-Agent", "Automated-Web-Scanner-Passive/1.0")
                    .header("Accept", "application/json")
                    .GET();

            if (!apiKey.isBlank()) {
                requestBuilder.header("apiKey", apiKey);
            }

            HttpResponse<byte[]> response = BoundedHttpResponse.send(
                    httpClient, requestBuilder.build(), MAX_NVD_RESPONSE_BYTES, timeout);

            if (response.statusCode() == 429) {
                log.warn("NVD API rate limit exceeded (HTTP 429) querying {}:{}", software, version);
                return null;
            }
            if (response.statusCode() >= 500) {
                log.warn("NVD API service unavailable (HTTP {}) querying {}:{}", response.statusCode(), software, version);
                return null;
            }
            if (response.statusCode() != 200) {
                log.warn("NVD API query for {}:{} returned unexpected HTTP {}", software, version, response.statusCode());
                return null;
            }
            String responseBody = new String(response.body(), StandardCharsets.UTF_8);
            JsonNode responseRoot = objectMapper.readTree(responseBody);
            if (!responseRoot.path("vulnerabilities").isArray()) {
                log.warn("NVD API returned an invalid response querying {}:{}", software, version);
                return null;
            }
            return parseNvdResponse(responseBody, software, version);

        } catch (HttpTimeoutException exception) {
            log.warn("NVD API request timed out querying {}:{}", software, version);
            return null;
        } catch (IOException | InterruptedException exception) {
            if (exception instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            log.warn("NVD API query failed for {}:{} ({})", software, version, exception.getClass().getSimpleName());
            return null;
        } catch (Exception exception) {
            log.warn("Unexpected NVD query failure for {}:{} ({})", software, version,
                    exception.getClass().getSimpleName());
            return null;
        }
    }

    List<CveMatch> parseNvdResponse(String json, String software, String version) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            JsonNode root = objectMapper.readTree(json);
            JsonNode vulnerabilities = root.path("vulnerabilities");
            if (!vulnerabilities.isArray()) {
                return List.of();
            }

            List<CveMatch> results = new ArrayList<>();
            for (JsonNode item : vulnerabilities) {
                JsonNode cve = item.path("cve");
                String cveId = cve.path("id").asText();
                if (cveId == null || !cveId.startsWith("CVE-")) {
                    continue;
                }

                String description = "";
                JsonNode descriptions = cve.path("descriptions");
                if (descriptions.isArray()) {
                    for (JsonNode desc : descriptions) {
                        if ("en".equalsIgnoreCase(desc.path("lang").asText(""))) {
                            description = desc.path("value").asText("");
                            break;
                        }
                    }
                }

                CvssInfo cvss = extractCvss(cve.path("metrics"));

                results.add(new CveMatch(
                        cveId,
                        software,
                        version,
                        cvss.score(),
                        cvss.severity(),
                        cvss.vector(),
                        description
                ));
            }
            return results;
        } catch (Exception exception) {
            log.warn("Failed to parse NVD response for {}:{}: {}", software, version, exception.getMessage());
            return List.of();
        }
    }

    private CvssInfo extractCvss(JsonNode metrics) {
        // Try CVSS v3.1
        JsonNode v31 = metrics.path("cvssMetricV31");
        if (v31.isArray() && !v31.isEmpty()) {
            JsonNode cvssData = v31.get(0).path("cvssData");
            return parseCvssData(cvssData);
        }
        // Try CVSS v3.0
        JsonNode v30 = metrics.path("cvssMetricV30");
        if (v30.isArray() && !v30.isEmpty()) {
            JsonNode cvssData = v30.get(0).path("cvssData");
            return parseCvssData(cvssData);
        }
        return new CvssInfo(0.0, "UNKNOWN", "N/A");
    }

    private CvssInfo parseCvssData(JsonNode cvssData) {
        double score = cvssData.path("baseScore").asDouble(0.0);
        String severity = cvssData.path("baseSeverity").asText("UNKNOWN").toUpperCase(Locale.ROOT);
        String vector = cvssData.path("vectorString").asText("N/A");
        return new CvssInfo(score, severity, vector);
    }

    public record SoftwareVersion(String software, String version) {}
    private record CvssInfo(double score, String severity, String vector) {}
}
