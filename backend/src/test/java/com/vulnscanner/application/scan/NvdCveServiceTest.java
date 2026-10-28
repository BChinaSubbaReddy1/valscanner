package com.vulnscanner.application.scan;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

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

        NvdLookupResult result = service.parseNvdResponse(nvdJson, "Apache", "2.4.49");
        List<CveMatch> matches = result.candidates();
        assertEquals(NvdLookupStatus.CANDIDATES_FOUND, result.status());
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
    void doesNotReuseCacheEntriesAcrossDifferentSoftwareAndVersionPairs() throws Exception {
        HttpClient client = mock(HttpClient.class);
        whenSend(client,
                CompletableFuture.completedFuture(response(200, """
                        {"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}]}
                        """)),
                CompletableFuture.completedFuture(response(200, """
                        {"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2025-5678"}}]}
                        """)));
        NvdCveService service = new NvdCveService(
                "https://services.nvd.nist.gov/rest/json/cves/2.0", "", true, 5, objectMapper, client);

        assertEquals("CVE-2024-1234", service.lookupCves("product:edition", "1").candidates().getFirst().cveId());
        assertEquals("CVE-2025-5678", service.lookupCves("product", "edition:1").candidates().getFirst().cveId());
        verify(client, times(2)).sendAsync(any(), any());
    }

    @Test
    void doesNotCacheMalformedVulnerabilityRecordsAsAnEmptySuccessfulSearch() throws Exception {
        HttpClient client = mock(HttpClient.class);
        whenSend(client,
                CompletableFuture.completedFuture(response(200, """
                        {"vulnerabilities":[{}]}
                        """)),
                CompletableFuture.completedFuture(response(200, """
                        {"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}]}
                        """)));
        NvdCveService service = new NvdCveService(
                "https://services.nvd.nist.gov/rest/json/cves/2.0", "", true, 5, objectMapper, client);

        assertEquals(NvdLookupStatus.INVALID_RESPONSE, service.lookupCves("Apache", "2.4.49").status());
        NvdLookupResult recovered = service.lookupCves("Apache", "2.4.49");
        assertEquals(NvdLookupStatus.CANDIDATES_FOUND, recovered.status());
        assertEquals("CVE-2024-1234", recovered.candidates().getFirst().cveId());
        verify(client, times(2)).sendAsync(any(), any());
    }

    @Test
    void rejectsMalformedCveIdentifiersAndUntrustedCvssValues() {
        NvdCveService service = new NvdCveService(null, null, true, 5, objectMapper, null);
        String json = """
                {"totalResults":2,"vulnerabilities":[
                  {"cve":{"id":"CVE-not-valid","metrics":{"cvssMetricV31":[{"cvssData":{
                    "baseScore":15.5,"baseSeverity":"CRITICAL","vectorString":"not-a-vector"}}]}}},
                  {"cve":{"id":"CVE-2024-1234","metrics":{"cvssMetricV31":[{"cvssData":{
                    "baseScore":12.5,"baseSeverity":"UNKNOWN","vectorString":"not-a-vector"}}]}}}
                ]}
                """;

        NvdLookupResult result = service.parseNvdResponse(json, "Apache", "2.4.49");

        assertEquals(NvdLookupStatus.INVALID_RESPONSE, result.status());
        assertTrue(result.candidates().isEmpty());
    }

    @Test
    void reportsInvalidCvssFieldsAsUnavailableForValidCveIdentifiers() {
        NvdCveService service = new NvdCveService(null, null, true, 5, objectMapper, null);
        List<String> invalidMetrics = List.of(
                """
                {"baseScore":12.5,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
                """,
                """
                {"baseScore":7.5,"baseSeverity":"LOW","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
                """,
                """
                {"baseScore":7.5,"baseSeverity":"HIGH","vectorString":"not-a-vector"}
                """
        );

        for (String cvssData : invalidMetrics) {
            NvdLookupResult result = service.parseNvdResponse("""
                    {"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-1234",
                      "metrics":{"cvssMetricV31":[{"cvssData":%s}]}}}]}
                    """.formatted(cvssData), "Apache", "2.4.49");

            CveMatch match = result.candidates().getFirst();
            assertEquals(NvdLookupStatus.CANDIDATES_FOUND, result.status());
            assertEquals(0.0, match.cvssScore());
            assertEquals("UNKNOWN", match.cvssSeverity());
            assertEquals("N/A", match.cvssVector());
        }
    }

    @Test
    void distinguishesMalformedResponsesFromValidEmptyResults() {
        NvdCveService service = new NvdCveService(null, null, true, 5, objectMapper, null);

        assertEquals(NvdLookupStatus.INVALID_RESPONSE,
                service.parseNvdResponse("{\"vulnerabilities\":[{}]}", "Apache", "2.4.49").status());
        assertEquals(NvdLookupStatus.INVALID_RESPONSE,
                service.parseNvdResponse("{\"vulnerabilities\":[{\"cve\":{\"id\":\"CVE-bad\"}}]}",
                        "Apache", "2.4.49").status());
        assertEquals(NvdLookupStatus.INVALID_RESPONSE,
                service.parseNvdResponse("{\"notVulnerabilities\":[]}", "Apache", "2.4.49").status());
        assertEquals(NvdLookupStatus.INVALID_RESPONSE,
                service.parseNvdResponse("{broken json", "Apache", "2.4.49").status());
        assertEquals(NvdLookupStatus.INVALID_RESPONSE,
                service.parseNvdResponse("{\"vulnerabilities\":[]}", "Apache", "2.4.49").status());
        assertEquals(NvdLookupStatus.INVALID_RESPONSE,
                service.parseNvdResponse("""
                        {"totalResults":0,"vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}]}
                        """, "Apache", "2.4.49").status());
        assertEquals(NvdLookupStatus.NO_CANDIDATES,
                service.parseNvdResponse("{\"totalResults\":0,\"vulnerabilities\":[]}",
                        "Apache", "2.4.49").status());
    }

    @Test
    void reportsMissingCvssMetricsAsUnavailableRatherThanAZeroScore() {
        NvdCveService service = new NvdCveService(null, null, true, 5, objectMapper, null);

        CveMatch match = service.parseNvdResponse("""
                {"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}]}
                """, "Apache", "2.4.49").candidates().getFirst();

        assertEquals(0.0, match.cvssScore());
        assertEquals("UNKNOWN", match.cvssSeverity());
        assertEquals("N/A", match.cvssVector());
    }

    @Test
    void encodesSearchParametersAndSendsConfiguredApiKeyAsHeader() throws Exception {
        HttpClient client = mock(HttpClient.class);
        whenSend(client, CompletableFuture.completedFuture(response(200,
                "{\"totalResults\":0,\"vulnerabilities\": []}")));
        NvdCveService service = new NvdCveService(
                "https://nvd.example.test/cves?source=test", "secret-api-key", true, 5, objectMapper, client);

        assertEquals(NvdLookupStatus.NO_CANDIDATES,
                service.lookupCves("Apache&keywordSearch=other", "2.4.49").status());

        ArgumentCaptor<HttpRequest> requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(client).sendAsync(requestCaptor.capture(), any());
        HttpRequest request = requestCaptor.getValue();
        assertEquals("secret-api-key", request.headers().firstValue("apiKey").orElseThrow());
        assertTrue(request.uri().getRawQuery().contains("source=test&keywordSearch=Apache%26keywordSearch%3Dother+2.4.49"));
        assertFalse(request.uri().getRawQuery().contains("&keywordSearch=other"));
    }

    @Test
    void handlesRateLimitGracefullyWithoutThrowing() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<byte[]> response = response(429, "");
        whenSend(client, CompletableFuture.completedFuture(response));

        NvdCveService service = new NvdCveService(
                "https://services.nvd.nist.gov/rest/json/cves/2.0", "", true, 5, objectMapper, client);

        NvdLookupResult result = service.lookupCves("Apache", "2.4.49");
        assertEquals(NvdLookupStatus.RATE_LIMITED, result.status());
        assertTrue(result.candidates().isEmpty());
    }

    @Test
    void distinguishesNetworkTimeoutFromServiceUnavailability() throws Exception {
        HttpClient client = mock(HttpClient.class);
        whenSend(client,
                CompletableFuture.failedFuture(new HttpTimeoutException("Connection timed out")),
                CompletableFuture.completedFuture(response(503, "")));

        NvdCveService service = new NvdCveService(
                "https://services.nvd.nist.gov/rest/json/cves/2.0", "", true, 5, objectMapper, client);

        assertEquals(NvdLookupStatus.TIMEOUT, service.lookupCves("Apache", "2.4.49").status());
        assertEquals(NvdLookupStatus.UNAVAILABLE, service.lookupCves("Apache", "2.4.49").status());
    }

    @Test
    void cachesSuccessfulLookupsToPreventRedundantOutboundRequests() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<byte[]> response = response(200, "{\"totalResults\":0,\"vulnerabilities\": []}");
        whenSend(client, CompletableFuture.completedFuture(response));

        NvdCveService service = new NvdCveService(
                "https://services.nvd.nist.gov/rest/json/cves/2.0", "", true, 5, objectMapper, client);

        NvdLookupResult first = service.lookupCves("nginx", "1.18.0");
        NvdLookupResult second = service.lookupCves("nginx", "1.18.0");

        assertSame(first, second);
        assertEquals(NvdLookupStatus.NO_CANDIDATES, first.status());
        verify(client, times(1)).sendAsync(any(), any());
    }

    @Test
    void doesNotCacheRateLimitedResponses() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<byte[]> rateLimited = response(429, "");
        HttpResponse<byte[]> recovered = response(200, "{\"totalResults\":0,\"vulnerabilities\": []}");
        whenSend(client, CompletableFuture.completedFuture(rateLimited),
                CompletableFuture.completedFuture(recovered));

        NvdCveService service = new NvdCveService(
                "https://services.nvd.nist.gov/rest/json/cves/2.0", "", true, 5, objectMapper, client);

        assertEquals(NvdLookupStatus.RATE_LIMITED, service.lookupCves("Apache", "2.4.49").status());
        assertEquals(NvdLookupStatus.NO_CANDIDATES, service.lookupCves("Apache", "2.4.49").status());

        verify(client, times(2)).sendAsync(any(), any());
    }

    @Test
    void boundsSuccessfulResponseCache() throws Exception {
        HttpClient client = mock(HttpClient.class);
        HttpResponse<byte[]> response = response(200, "{\"totalResults\":0,\"vulnerabilities\": []}");
        whenSend(client, CompletableFuture.completedFuture(response));

        NvdCveService service = new NvdCveService(
                "https://services.nvd.nist.gov/rest/json/cves/2.0", "", true, 5, objectMapper, client);
        for (int index = 0; index < 257; index++) {
            service.lookupCves("software" + index, "1.0");
        }
        service.lookupCves("software0", "1.0");

        verify(client, times(258)).sendAsync(any(), any());
    }

    @Test
    void preservesCandidatesWhenNvdIndicatesMoreResultsThanReturned() {
        NvdCveService service = new NvdCveService(null, null, true, 5, objectMapper, null);

        NvdLookupResult result = service.parseNvdResponse("""
                {"totalResults":6,"vulnerabilities":[
                  {"cve":{"id":"CVE-2024-1234"}},
                  {"cve":{"id":"CVE-2024-5678"}}
                ]}
                """, "Apache", "2.4.49");

        assertEquals(NvdLookupStatus.PARTIAL_RESULTS, result.status());
        assertEquals(2, result.candidates().size());
    }

    @Test
    void distinguishesDisabledAndNotRequestedLookups() {
        NvdCveService disabled = new NvdCveService(null, null, false, 5, objectMapper, null);
        NvdCveService enabled = new NvdCveService(null, null, true, 5, objectMapper, null);

        assertEquals(NvdLookupStatus.DISABLED, disabled.lookupCves("Apache", "2.4.49").status());
        assertEquals(NvdLookupStatus.NOT_REQUESTED, enabled.lookupCves(" ", "2.4.49").status());
    }

    @Test
    void aggregatesMultipleLookupOutcomesWithoutClaimingNoCandidates() {
        assertEquals(NvdLookupStatus.PARTIAL_RESULTS,
                NvdLookupStatus.NO_CANDIDATES.merge(NvdLookupStatus.TIMEOUT));
        assertEquals(NvdLookupStatus.PARTIAL_RESULTS,
                NvdLookupStatus.RATE_LIMITED.merge(NvdLookupStatus.CANDIDATES_FOUND));
        assertEquals(NvdLookupStatus.CANDIDATES_FOUND,
                NvdLookupStatus.NO_CANDIDATES.merge(NvdLookupStatus.CANDIDATES_FOUND));
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
