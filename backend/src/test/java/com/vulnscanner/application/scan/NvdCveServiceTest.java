package com.vulnscanner.application.scan;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class NvdCveServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void parsesSoftwareAndVersionAccurately() {
        NvdCveService service = new NvdCveService(null, null, true, 5, objectMapper, null);

        NvdCveService.SoftwareVersion v1 = service.parseSoftwareVersion("Apache/2.4.49");
        assertNotNull(v1);
        assertEquals("Apache", v1.software());
        assertEquals("2.4.49", v1.version());

        NvdCveService.SoftwareVersion v2 = service.parseSoftwareVersion("nginx/1.18.0 (Ubuntu)");
        assertNotNull(v2);
        assertEquals("nginx", v2.software());
        assertEquals("1.18.0", v2.version());

        NvdCveService.SoftwareVersion v3 = service.parseSoftwareVersion("PHP/8.1.2-1ubuntu2.14");
        assertNotNull(v3);
        assertEquals("PHP", v3.software());
        assertEquals("8.1.2-1ubuntu2.14", v3.version());

        // Negative cases - no version, invalid format, or bare software name
        assertNull(service.parseSoftwareVersion("Cloudflare"));
        assertNull(service.parseSoftwareVersion("Apache"));
        assertNull(service.parseSoftwareVersion("custom-server"));
        assertNull(service.parseSoftwareVersion(""));
        assertNull(service.parseSoftwareVersion(null));
    }

    @Test
    void parsesValidNvdJsonResponseWithCvssV3() {
        NvdCveService service = new NvdCveService(null, null, true, 5, objectMapper, null);
        String nvdJson = """
                {
                  "resultsPerPage": 1,
                  "startIndex": 0,
                  "totalResults": 1,
                  "vulnerabilities": [
                    {
                      "cve": {
                        "id": "CVE-2021-41773",
                        "descriptions": [
                          {
                            "lang": "en",
                            "value": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49."
                          }
                        ],
                        "metrics": {
                          "cvssMetricV31": [
                            {
                              "cvssData": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                              }
                            }
                          ]
                        }
                      }
                    }
                  ]
                }
                """;

        List<CveMatch> matches = service.parseNvdResponse(nvdJson, "Apache", "2.4.49");
        assertEquals(1, matches.size());
        CveMatch match = matches.get(0);
        assertEquals("CVE-2021-41773", match.cveId());
        assertEquals("Apache", match.software());
        assertEquals("2.4.49", match.version());
        assertEquals(7.5, match.cvssScore());
        assertEquals("HIGH", match.cvssSeverity());
        assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", match.cvssVector());
        assertTrue(match.description().contains("path normalization"));
    }

    @Test
    void handlesRateLimitGracefullyWithoutThrowing() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<byte[]> response = response(429, "");
        whenSend(client, CompletableFuture.completedFuture(response));

        NvdCveService service = new NvdCveService(
                "https://services.nvd.nist.gov/rest/json/cves/2.0", "", true, 5, objectMapper, client);

        List<CveMatch> matches = service.findCves("Apache", "2.4.49");
        assertTrue(matches.isEmpty());
    }

    @Test
    void handlesServiceUnavailableAndTimeoutGracefully() throws Exception {
        HttpClient client = mock(HttpClient.class);
        whenSend(client, CompletableFuture.failedFuture(new HttpTimeoutException("Connection timed out")));

        NvdCveService service = new NvdCveService(
                "https://services.nvd.nist.gov/rest/json/cves/2.0", "", true, 5, objectMapper, client);

        List<CveMatch> matches = service.findCves("Apache", "2.4.49");
        assertTrue(matches.isEmpty());
    }

    @Test
    void cachesSuccessfulLookupsToPreventRedundantOutboundRequests() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<byte[]> response = response(200, "{\"vulnerabilities\": []}");
        whenSend(client, CompletableFuture.completedFuture(response));

        NvdCveService service = new NvdCveService(
                "https://services.nvd.nist.gov/rest/json/cves/2.0", "", true, 5, objectMapper, client);

        List<CveMatch> first = service.findCves("nginx", "1.18.0");
        List<CveMatch> second = service.findCves("nginx", "1.18.0");

        assertSame(first, second);
        verify(client, times(1)).sendAsync(any(), any());
    }

    @Test
    void doesNotCacheRateLimitedResponses() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<byte[]> rateLimited = response(429, "");
        HttpResponse<byte[]> recovered = response(200, "{\"vulnerabilities\": []}");
        whenSend(client, CompletableFuture.completedFuture(rateLimited),
                CompletableFuture.completedFuture(recovered));

        NvdCveService service = new NvdCveService(
                "https://services.nvd.nist.gov/rest/json/cves/2.0", "", true, 5, objectMapper, client);

        assertTrue(service.findCves("Apache", "2.4.49").isEmpty());
        assertTrue(service.findCves("Apache", "2.4.49").isEmpty());

        verify(client, times(2)).sendAsync(any(), any());
    }

    @Test
    void boundsSuccessfulResponseCache() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<byte[]> response = response(200, "{\"vulnerabilities\": []}");
        whenSend(client, CompletableFuture.completedFuture(response));

        NvdCveService service = new NvdCveService(
                "https://services.nvd.nist.gov/rest/json/cves/2.0", "", true, 5, objectMapper, client);
        for (int index = 0; index < 257; index++) {
            service.findCves("software" + index, "1.0");
        }
        service.findCves("software0", "1.0");

        verify(client, times(258)).sendAsync(any(), any());
    }

    private HttpResponse<byte[]> response(int status, String body) {
        @SuppressWarnings("unchecked")
        HttpResponse<byte[]> response = (HttpResponse<byte[]>) mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.body()).thenReturn(body.getBytes(StandardCharsets.UTF_8));
        return response;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void whenSend(HttpClient client, CompletableFuture<HttpResponse<byte[]>>... responses) {
        AtomicInteger responseIndex = new AtomicInteger();
        doAnswer(invocation -> responses[Math.min(responseIndex.getAndIncrement(), responses.length - 1)])
                .when(client).sendAsync(any(), any());
    }
}
