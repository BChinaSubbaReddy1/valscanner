package com.vulnscanner.application.scan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.role.Role;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.target.Target;
import com.vulnscanner.application.target.TargetStatus;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ZapIntegrationTest {
    private HttpServer targetServer;
    private HttpServer zapMockServer;

    @BeforeEach
    void setUp() throws Exception {
        targetServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        targetServer.createContext("/", exchange -> {
            byte[] body = "<html><head><title>App</title></head><body>Welcome</body></html>".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        targetServer.start();
    }

    @AfterEach
    void tearDown() {
        if (targetServer != null) {
            targetServer.stop(0);
        }
        if (zapMockServer != null) {
            zapMockServer.stop(0);
        }
    }

    private ScanJob createApprovedJob(Long id, ScanType scanType, String targetUrl) {
        Organization org = new Organization();
        ReflectionTestUtils.setField(org, "id", 100L);
        org.setStatus(OrganizationStatus.APPROVED);

        User analyst = new User();
        analyst.setStatus(UserStatus.ACTIVE);
        analyst.setOrganization(org);
        Role role = new Role();
        role.setName(RoleName.SECURITY_ANALYST);
        analyst.setRoles(Set.of(role));

        Target target = new Target();
        target.setUrl(targetUrl);
        target.setStatus(TargetStatus.APPROVED);
        target.setOrganization(org);

        ScanJob job = new ScanJob(target, org, analyst, scanType);
        ReflectionTestUtils.setField(job, "id", id);
        job.transitionTo(ScanStatus.PENDING_APPROVAL, 0, "Awaiting approval", null);
        job.approve(analyst);
        return job;
    }

    @Test
    void testZapUnavailableFallbackToNativeScan() {
        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(1L, ScanType.ZAP_PASSIVE, targetUrl);

        ScanJobRepository jobRepo = mock(ScanJobRepository.class);
        when(jobRepo.findByIdForExecutionUpdate(1L)).thenReturn(Optional.of(job));
        ScanFindingRepository findingRepo = mock(ScanFindingRepository.class);
        TransactionTemplate tx = mock(TransactionTemplate.class);
        doAnswer(inv -> {
            ((java.util.function.Consumer<org.springframework.transaction.TransactionStatus>) inv.getArgument(0)).accept(null);
            return null;
        }).when(tx).executeWithoutResult(any());

        ZapClientService zapClient = mock(ZapClientService.class);
        when(zapClient.isAvailable()).thenReturn(false);

        ScanExecutionService executionService = new ScanExecutionService(
                jobRepo, findingRepo, true, tx, null, null,
                10, 6, 15, null, null,
                zapClient, new ZapScanAdapter(), true
        );

        executionService.execute(1L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals(100, job.getProgress());
        assertEquals("Passive header scan completed", job.getStatusMessage());
    }

    @Test
    void testZapUnavailableWithFallbackDisabledFailsJob() {
        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(2L, ScanType.ZAP_PASSIVE, targetUrl);

        ScanJobRepository jobRepo = mock(ScanJobRepository.class);
        when(jobRepo.findByIdForExecutionUpdate(2L)).thenReturn(Optional.of(job));
        ScanFindingRepository findingRepo = mock(ScanFindingRepository.class);
        TransactionTemplate tx = mock(TransactionTemplate.class);
        doAnswer(inv -> {
            ((java.util.function.Consumer<org.springframework.transaction.TransactionStatus>) inv.getArgument(0)).accept(null);
            return null;
        }).when(tx).executeWithoutResult(any());

        ZapClientService zapClient = mock(ZapClientService.class);
        when(zapClient.isAvailable()).thenReturn(false);

        ScanExecutionService executionService = new ScanExecutionService(
                jobRepo, findingRepo, true, tx, null, null,
                10, 6, 15, null, null,
                zapClient, new ZapScanAdapter(), false // fallback disabled
        );

        executionService.execute(2L);

        assertEquals(ScanStatus.FAILED, job.getStatus());
        assertEquals(ScanFailureReason.EXECUTOR_UNAVAILABLE.name(), job.getFailureReason());
        assertTrue(job.getStatusMessage().contains("OWASP ZAP service is unavailable"));
    }

    @Test
    void testZapScanSuccessWithAlertMappingAndDeduplication() throws Exception {
        // Setup mock ZAP HTTP server
        zapMockServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        zapMockServer.createContext("/JSON/core/view/version/", exchange -> {
            byte[] body = "{\"version\":\"2.14.0\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        zapMockServer.createContext("/JSON/spider/action/scan/", exchange -> {
            byte[] body = "{\"scan\":\"1\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        zapMockServer.createContext("/JSON/spider/view/status/", exchange -> {
            byte[] body = "{\"status\":\"100\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        zapMockServer.createContext("/JSON/ascan/action/scan/", exchange -> {
            byte[] body = "{\"scan\":\"2\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        zapMockServer.createContext("/JSON/ascan/view/status/", exchange -> {
            byte[] body = "{\"status\":\"100\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        zapMockServer.createContext("/JSON/core/view/alerts/", exchange -> {
            String alertsJson = "{\"alerts\":[" +
                    "{\"alert\":\"Cross Site Scripting (Reflected)\",\"risk\":\"High\",\"confidence\":\"High\",\"url\":\"http://127.0.0.1/test\",\"param\":\"q\",\"evidence\":\"<script>alert(1)</script>\",\"description\":\"XSS description\",\"solution\":\"Sanitize input\"}," +
                    "{\"alert\":\"Cross Site Scripting (Reflected)\",\"risk\":\"High\",\"confidence\":\"High\",\"url\":\"http://127.0.0.1/test\",\"param\":\"q\",\"evidence\":\"<script>alert(1)</script>\",\"description\":\"Duplicate duplicate\",\"solution\":\"Sanitize input\"}," +
                    "{\"alert\":\"Missing Anti-clickjacking Header\",\"risk\":\"Medium\",\"confidence\":\"Medium\",\"url\":\"http://127.0.0.1/test\",\"evidence\":\"\",\"description\":\"Missing X-Frame-Options\",\"solution\":\"Add X-Frame-Options\"}" +
                    "]}";
            byte[] body = alertsJson.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        zapMockServer.start();

        String zapBaseUrl = "http://127.0.0.1:" + zapMockServer.getAddress().getPort();
        ZapClientService zapClient = new ZapClientService(zapBaseUrl, "test-api-key", true, 2, 5, new ObjectMapper());

        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(3L, ScanType.ZAP_ACTIVE, targetUrl);

        ScanJobRepository jobRepo = mock(ScanJobRepository.class);
        when(jobRepo.findByIdForExecutionUpdate(3L)).thenReturn(Optional.of(job));
        ScanFindingRepository findingRepo = mock(ScanFindingRepository.class);
        TransactionTemplate tx = mock(TransactionTemplate.class);
        doAnswer(inv -> {
            ((java.util.function.Consumer<org.springframework.transaction.TransactionStatus>) inv.getArgument(0)).accept(null);
            return null;
        }).when(tx).executeWithoutResult(any());

        ScanExecutionService executionService = new ScanExecutionService(
                jobRepo, findingRepo, true, tx, null, null,
                10, 6, 15, null, null,
                zapClient, new ZapScanAdapter(), false
        );

        executionService.execute(3L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals(100, job.getProgress());
        assertEquals("OWASP ZAP scan completed successfully", job.getStatusMessage());

        ArgumentCaptor<ScanFinding> findingCaptor = ArgumentCaptor.forClass(ScanFinding.class);
        verify(findingRepo, times(2)).save(findingCaptor.capture());

        List<ScanFinding> savedFindings = findingCaptor.getAllValues();
        assertEquals(2, savedFindings.size());

        ScanFinding xssFinding = savedFindings.stream()
                .filter(f -> f.getCheckType().equals("REFLECTED_XSS_POTENTIAL"))
                .findFirst().orElseThrow();
        assertEquals("HIGH", xssFinding.getSeverity());
        assertEquals("VERIFIED", xssFinding.getVerificationStatus());
        assertEquals("OWASP_ZAP", xssFinding.getDetectionSource());
        assertTrue(xssFinding.getAffectedComponent().contains("[q]"));

        ScanFinding clickjackingFinding = savedFindings.stream()
                .filter(f -> f.getCheckType().equals("MISSING_FRAME_PROTECTION"))
                .findFirst().orElseThrow();
        assertEquals("MEDIUM", clickjackingFinding.getSeverity());
        assertEquals("OBSERVED", clickjackingFinding.getVerificationStatus());
    }

    @Test
    void testZapScanRejectsPrivateTargetWhenNotAllowed() {
        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(4L, ScanType.ZAP_PASSIVE, targetUrl);

        ScanJobRepository jobRepo = mock(ScanJobRepository.class);
        when(jobRepo.findByIdForExecutionUpdate(4L)).thenReturn(Optional.of(job));
        ScanFindingRepository findingRepo = mock(ScanFindingRepository.class);
        TransactionTemplate tx = mock(TransactionTemplate.class);
        doAnswer(inv -> {
            ((java.util.function.Consumer<org.springframework.transaction.TransactionStatus>) inv.getArgument(0)).accept(null);
            return null;
        }).when(tx).executeWithoutResult(any());

        ZapClientService zapClient = mock(ZapClientService.class);
        when(zapClient.isAvailable()).thenReturn(true);

        ScanExecutionService executionService = new ScanExecutionService(
                jobRepo, findingRepo, false, tx, null, null, // allowPrivateTargets = false
                10, 6, 15, null, null,
                zapClient, new ZapScanAdapter(), false
        );

        executionService.execute(4L);

        assertEquals(ScanStatus.FAILED, job.getStatus());
        assertEquals(ScanFailureReason.TARGET_URL_INVALID.name(), job.getFailureReason());
        assertTrue(job.getStatusMessage().contains("Target resolves to a disallowed network address"));
    }

    @Test
    void testZapScanHandlesCancellationGracefully() throws Exception {
        zapMockServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        zapMockServer.createContext("/JSON/core/view/version/", exchange -> {
            byte[] body = "{\"version\":\"2.14.0\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        zapMockServer.createContext("/JSON/spider/action/scan/", exchange -> {
            byte[] body = "{\"scan\":\"10\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        zapMockServer.createContext("/JSON/spider/action/stop/", exchange -> {
            byte[] body = "{\"result\":\"OK\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        zapMockServer.start();

        String zapBaseUrl = "http://127.0.0.1:" + zapMockServer.getAddress().getPort();
        ZapClientService zapClient = new ZapClientService(zapBaseUrl, "test-api-key", true, 2, 5, new ObjectMapper());

        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(5L, ScanType.ZAP_PASSIVE, targetUrl);

        // Pre-request cancellation
        job.requestCancellation();

        ScanJobRepository jobRepo = mock(ScanJobRepository.class);
        when(jobRepo.findByIdForExecutionUpdate(5L)).thenReturn(Optional.of(job));
        ScanFindingRepository findingRepo = mock(ScanFindingRepository.class);
        TransactionTemplate tx = mock(TransactionTemplate.class);
        doAnswer(inv -> {
            ((java.util.function.Consumer<org.springframework.transaction.TransactionStatus>) inv.getArgument(0)).accept(null);
            return null;
        }).when(tx).executeWithoutResult(any());

        ScanExecutionService executionService = new ScanExecutionService(
                jobRepo, findingRepo, true, tx, null, null,
                10, 6, 15, null, null,
                zapClient, new ZapScanAdapter(), false
        );

        executionService.execute(5L);

        // Cancellation checked during spider loop or runClaimed guard
        // Because cancellation was requested before runClaimed, runClaimed returns early
        assertNotEquals(ScanStatus.COMPLETED, job.getStatus());
    }
}
