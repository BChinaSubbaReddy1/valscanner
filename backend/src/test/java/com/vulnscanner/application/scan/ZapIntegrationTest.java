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
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

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

    private void permitTestTargetOrigin(ScanExecutionService service, ScanJob job) {
        java.net.URI target = java.net.URI.create(job.getTarget().getUrl());
        ReflectionTestUtils.setField(service, "allowedPrivateTargetOrigins",
                target.getScheme() + "://" + target.getRawAuthority());
    }

    @Test
    void everySupportedScanModeRunsZapSpiderAndPassiveAnalysis() throws Exception {
        long scanId = 100L;
        for (ScanType scanType : ScanType.values()) {
            long id = scanId++;
            String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
            ScanJob job = createApprovedJob(id, scanType, targetUrl);
            ScanJobRepository jobs = mock(ScanJobRepository.class);
            when(jobs.findByIdForExecutionUpdate(id)).thenReturn(Optional.of(job));
            ScanFindingRepository findings = mock(ScanFindingRepository.class);
            ZapClientService zap = mock(ZapClientService.class);
            when(zap.isEnabled()).thenReturn(true);
            when(zap.checkAvailability()).thenReturn(ZapClientService.AvailabilityStatus.AVAILABLE);
            when(zap.createTargetContext(any(), anyString()))
                    .thenReturn(new ZapClientService.ScopeContext("scan-" + id, "context-" + id));
            when(zap.startSpider(eq(targetUrl), anyString())).thenReturn("spider-" + id);
            when(zap.getSpiderProgress(anyString())).thenReturn(100);
            when(zap.getSpiderDiscoveredCount(anyString())).thenReturn(2);
            when(zap.getPassiveScanRecordsToScan()).thenReturn(0);
            when(zap.getAlerts(targetUrl)).thenReturn(List.of());
            if (scanType == ScanType.ZAP_ACTIVE) {
                when(zap.startActiveScan(eq(targetUrl), any())).thenReturn("active-" + id);
                when(zap.getActiveScanProgress(anyString())).thenReturn(100);
            }

            ScanExecutionService service = new ScanExecutionService(
                    jobs, findings, true, null, null, null,
                    10, 6, 15, null, null, zap, new ZapScanAdapter());
            permitTestTargetOrigin(service, job);
            service.runClaimed(id);

            assertEquals(ScanStatus.COMPLETED, job.getStatus(), scanType.name());
            assertTrue(job.isZapRequested(), scanType.name());
            assertEquals("COMPLETED", job.getZapEngineStatus(), scanType.name());
            assertEquals("COMPLETED", job.getZapSpiderStatus(), scanType.name());
            assertEquals(2, job.getZapSpiderDiscoveredCount(), scanType.name());
            assertEquals("COMPLETED", job.getZapPassiveStatus(), scanType.name());
            assertEquals(0, job.getZapAlertCount(), scanType.name());
            if (scanType == ScanType.ZAP_ACTIVE) {
                assertEquals("COMPLETED", job.getZapActiveStatus());
                verify(zap).startActiveScan(eq(targetUrl), any());
            } else {
                assertNull(job.getZapActiveStatus());
                verify(zap, never()).startActiveScan(anyString(), any());
            }
            verify(zap).startSpider(eq(targetUrl), anyString());
            verify(zap).getAlerts(targetUrl);
        }
    }

    @Test
    void unavailableZapCompletesWithNativeFindings() {
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
        when(zapClient.isEnabled()).thenReturn(true);
        when(zapClient.checkAvailability()).thenReturn(ZapClientService.AvailabilityStatus.UNAVAILABLE);

        ScanExecutionService executionService = new ScanExecutionService(
                jobRepo, findingRepo, true, tx, null, null,
                10, 6, 15, null, null,
                zapClient, new ZapScanAdapter()
        );
        permitTestTargetOrigin(executionService, job);

        executionService.execute(1L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals(100, job.getProgress());
        assertEquals("UNAVAILABLE", job.getZapEngineStatus());
        assertEquals("ZAP_HEALTH_CHECK_FAILED", job.getZapFailureReason());
        assertTrue(job.getStatusMessage().contains("OWASP ZAP is unavailable"));
        verify(findingRepo, atLeastOnce()).save(any(ScanFinding.class));
    }

    @Test
    void testZapUnavailablePreservesNativeResultsWhenFallbackIsDisabled() {
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
        when(zapClient.isEnabled()).thenReturn(true);
        when(zapClient.checkAvailability()).thenReturn(ZapClientService.AvailabilityStatus.UNAVAILABLE);

        ScanExecutionService executionService = new ScanExecutionService(
                jobRepo, findingRepo, true, tx, null, null,
                10, 6, 15, null, null,
                zapClient, new ZapScanAdapter()
        );
        permitTestTargetOrigin(executionService, job);

        executionService.execute(2L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertNull(job.getFailureReason());
        assertEquals("UNAVAILABLE", job.getZapEngineStatus());
        assertTrue(job.getStatusMessage().contains("OWASP ZAP is unavailable"));
        verify(findingRepo, atLeastOnce()).save(any(ScanFinding.class));
    }

    @Test
    void unavailableZapRetainsNativeResultsForAnActiveRequest() {
        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(9L, ScanType.ZAP_ACTIVE, targetUrl);
        ScanJobRepository jobRepo = mock(ScanJobRepository.class);
        when(jobRepo.findByIdForExecutionUpdate(9L)).thenReturn(Optional.of(job));
        ScanFindingRepository findingRepo = mock(ScanFindingRepository.class);
        TransactionTemplate tx = mock(TransactionTemplate.class);
        doAnswer(invocation -> {
            ((java.util.function.Consumer<org.springframework.transaction.TransactionStatus>)
                    invocation.getArgument(0)).accept(null);
            return null;
        }).when(tx).executeWithoutResult(any());
        ZapClientService zapClient = mock(ZapClientService.class);
        when(zapClient.isEnabled()).thenReturn(true);
        when(zapClient.checkAvailability()).thenReturn(ZapClientService.AvailabilityStatus.UNAVAILABLE);

        ScanExecutionService service = new ScanExecutionService(
                jobRepo, findingRepo, true, tx, null, null,
                10, 6, 15, null, null, zapClient, new ZapScanAdapter());
        permitTestTargetOrigin(service, job);
        service.execute(9L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertNull(job.getFailureReason());
        assertEquals("UNAVAILABLE", job.getZapEngineStatus());
        assertTrue(job.getStatusMessage().contains("OWASP ZAP is unavailable"));
        verify(findingRepo, atLeastOnce()).save(any(ScanFinding.class));
    }

    @Test
    void disabledZapIsReportedAsDisabledWithoutClaimingZapExecution() throws Exception {
        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(12L, ScanType.ZAP_PASSIVE, targetUrl);
        ScanJobRepository jobRepo = mock(ScanJobRepository.class);
        when(jobRepo.findByIdForExecutionUpdate(12L)).thenReturn(Optional.of(job));
        ScanFindingRepository findingRepo = mock(ScanFindingRepository.class);
        TransactionTemplate tx = mock(TransactionTemplate.class);
        doAnswer(invocation -> {
            ((java.util.function.Consumer<org.springframework.transaction.TransactionStatus>)
                    invocation.getArgument(0)).accept(null);
            return null;
        }).when(tx).executeWithoutResult(any());

        ZapClientService zapClient = mock(ZapClientService.class);
        when(zapClient.isEnabled()).thenReturn(false);

        ScanExecutionService service = new ScanExecutionService(
                jobRepo, findingRepo, true, tx, null, null,
                10, 6, 15, null, null, zapClient, new ZapScanAdapter());
        permitTestTargetOrigin(service, job);
        service.execute(12L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals("COMPLETED", job.getNativeEngineStatus());
        assertEquals("DISABLED", job.getZapEngineStatus());
        assertEquals("ZAP_DISABLED_BY_CONFIGURATION", job.getZapFailureReason());
        verify(zapClient, never()).checkAvailability();
        verify(zapClient, never()).startSpider(anyString(), anyString());
    }

    @Test
    void zapStartupFailureIsReportedWithoutDiscardingNativeFindings() throws Exception {
        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(14L, ScanType.PASSIVE_HEADERS, targetUrl);
        ScanJobRepository jobs = mock(ScanJobRepository.class);
        when(jobs.findByIdForExecutionUpdate(14L)).thenReturn(Optional.of(job));
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        ZapClientService zap = mock(ZapClientService.class);
        when(zap.isEnabled()).thenReturn(true);
        when(zap.checkAvailability()).thenReturn(ZapClientService.AvailabilityStatus.AVAILABLE);
        when(zap.createTargetContext(any(), anyString()))
                .thenReturn(new ZapClientService.ScopeContext("scan-14", "14"));
        when(zap.startSpider(eq(targetUrl), anyString())).thenThrow(new java.io.IOException("start failed"));

        ScanExecutionService service = new ScanExecutionService(
                jobs, findings, true, null, null, null,
                10, 6, 15, null, null, zap, new ZapScanAdapter());
        permitTestTargetOrigin(service, job);
        service.runClaimed(14L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals("FAILED", job.getZapEngineStatus());
        assertEquals("ZAP_COMMUNICATION_FAILED", job.getZapFailureReason());
        assertEquals("FAILED", job.getZapSpiderStatus());
        assertEquals("NOT_STARTED", job.getZapPassiveStatus());
        assertEquals("COMPLETED", job.getNativeEngineStatus());
        verify(findings, atLeastOnce()).save(any(ScanFinding.class));
    }

    @Test
    void zapHealthCheckTimeoutIsDistinctFromUnavailable() throws Exception {
        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(17L, ScanType.PASSIVE_HEADERS, targetUrl);
        ScanJobRepository jobs = mock(ScanJobRepository.class);
        when(jobs.findByIdForExecutionUpdate(17L)).thenReturn(Optional.of(job));
        ZapClientService zap = mock(ZapClientService.class);
        when(zap.isEnabled()).thenReturn(true);
        when(zap.checkAvailability()).thenReturn(ZapClientService.AvailabilityStatus.TIMED_OUT);

        ScanExecutionService service = new ScanExecutionService(
                jobs, mock(ScanFindingRepository.class), true, null, null, null,
                10, 6, 15, null, null, zap, new ZapScanAdapter());
        permitTestTargetOrigin(service, job);
        service.runClaimed(17L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals("TIMED_OUT", job.getZapEngineStatus());
        assertEquals("ZAP_HEALTH_CHECK_TIMEOUT", job.getZapFailureReason());
        verify(zap, never()).startSpider(anyString(), anyString());
    }

    @Test
    void zapTimeoutIsReportedAsTimedOutAndDoesNotClaimSuccess() throws Exception {
        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(15L, ScanType.PASSIVE_HEADERS, targetUrl);
        ScanJobRepository jobs = mock(ScanJobRepository.class);
        when(jobs.findByIdForExecutionUpdate(15L)).thenReturn(Optional.of(job));
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        ZapClientService zap = mock(ZapClientService.class);
        when(zap.isEnabled()).thenReturn(true);
        when(zap.checkAvailability()).thenReturn(ZapClientService.AvailabilityStatus.AVAILABLE);
        when(zap.createTargetContext(any(), anyString()))
                .thenReturn(new ZapClientService.ScopeContext("scan-15", "15"));
        when(zap.startSpider(eq(targetUrl), anyString())).thenReturn("spider-15");
        when(zap.getSpiderProgress("spider-15")).thenReturn(0);

        ScanExecutionService service = new ScanExecutionService(
                jobs, findings, true, null, null, null,
                10, 6, 15, null, null, zap, new ZapScanAdapter(), 1);
        permitTestTargetOrigin(service, job);
        service.runClaimed(15L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals("TIMED_OUT", job.getZapEngineStatus());
        assertEquals("TIME_BUDGET_EXCEEDED", job.getZapFailureReason());
        assertEquals("TIMED_OUT", job.getZapSpiderStatus());
        assertEquals("NOT_STARTED", job.getZapPassiveStatus());
    }

    @Test
    void concurrentExecutionRequestsDoNotStartZapTwiceForOneScan() throws Exception {
        long id = 16L;
        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(id, ScanType.PASSIVE_HEADERS, targetUrl);
        ScanJobRepository jobs = mock(ScanJobRepository.class);
        when(jobs.findByIdForExecutionUpdate(id)).thenReturn(Optional.of(job));
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        ZapClientService zap = mock(ZapClientService.class);
        CountDownLatch healthCheckEntered = new CountDownLatch(1);
        CountDownLatch allowHealthCheck = new CountDownLatch(1);
        when(zap.isEnabled()).thenReturn(true);
        when(zap.checkAvailability()).thenAnswer(invocation -> {
            healthCheckEntered.countDown();
            if (!allowHealthCheck.await(5, TimeUnit.SECONDS)) {
                throw new IllegalStateException("test did not release health check");
            }
            return ZapClientService.AvailabilityStatus.AVAILABLE;
        });
        when(zap.createTargetContext(any(), anyString()))
                .thenReturn(new ZapClientService.ScopeContext("scan-16", "16"));
        when(zap.startSpider(eq(targetUrl), anyString())).thenReturn("spider-16");
        when(zap.getSpiderProgress(anyString())).thenReturn(100);
        when(zap.getPassiveScanRecordsToScan()).thenReturn(0);
        when(zap.getAlerts(targetUrl)).thenReturn(List.of());

        ScanExecutionService service = new ScanExecutionService(
                jobs, findings, true, null, null, null,
                10, 6, 15, null, null, zap, new ZapScanAdapter());
        permitTestTargetOrigin(service, job);
        Thread firstWorker = new Thread(() -> service.execute(id));
        firstWorker.start();
        try {
            assertTrue(healthCheckEntered.await(5, TimeUnit.SECONDS));
            service.execute(id);
        } finally {
            allowHealthCheck.countDown();
        }
        firstWorker.join(5000);
        service.execute(id);

        assertFalse(firstWorker.isAlive());
        assertEquals("COMPLETED", job.getZapEngineStatus());
        verify(zap, times(1)).startSpider(eq(targetUrl), anyString());
    }

    @Test
    void unexpectedZapWorkerFailureIsPersistedAsFailed() throws Exception {
        ScanJob job = createApprovedJob(13L, ScanType.ZAP_PASSIVE,
                "http://127.0.0.1:" + targetServer.getAddress().getPort());
        ScanJobRepository jobRepo = mock(ScanJobRepository.class);
        when(jobRepo.findByIdForExecutionUpdate(13L)).thenReturn(Optional.of(job));
        ScanFindingRepository findingRepo = mock(ScanFindingRepository.class);
        TransactionTemplate tx = mock(TransactionTemplate.class);
        doAnswer(invocation -> {
            ((java.util.function.Consumer<org.springframework.transaction.TransactionStatus>)
                    invocation.getArgument(0)).accept(null);
            return null;
        }).when(tx).executeWithoutResult(any());
        ZapClientService zapClient = mock(ZapClientService.class);
        when(zapClient.isEnabled()).thenReturn(true);
        when(zapClient.checkAvailability()).thenReturn(ZapClientService.AvailabilityStatus.AVAILABLE);
        when(zapClient.createTargetContext(any(), anyString()))
                .thenThrow(new IllegalStateException("controlled ZAP worker failure"));

        ScanExecutionService service = new ScanExecutionService(
                jobRepo, findingRepo, true, tx, null, null,
                10, 6, 15, null, null, zapClient, new ZapScanAdapter());
        permitTestTargetOrigin(service, job);

        service.execute(13L);

        assertEquals(ScanStatus.FAILED, job.getStatus());
        assertEquals("FAILED", job.getZapEngineStatus());
        assertEquals("ZAP_EXECUTION_FAILED", job.getZapFailureReason());
        assertEquals("COMPLETED", job.getNativeEngineStatus());
        assertNotNull(job.getFailureReason());
        verify(zapClient).createTargetContext(any(), anyString());
    }

    @Test
    void zapAlertRetainsConfidenceAsMetadataWithoutTreatingItAsVerification() {
        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(10L, ScanType.ZAP_PASSIVE, targetUrl);
        ZapAlert alert = new ZapAlert("40012", "Cross Site Scripting (Reflected)", "High", "High",
                targetUrl + "/search", "q", "<script>", "<script>", "Description", "Remediation",
                "https://example.test/rule", "79", "8");

        ScanFinding finding = new ZapScanAdapter().toFinding(job, alert);

        assertEquals("POTENTIAL", finding.getVerificationStatus());
        assertEquals("40012", finding.getSourceRuleId());
        assertEquals("High", finding.getSourceConfidence());
        assertEquals("https://example.test/rule", finding.getSourceReference());
        assertEquals("79", finding.getSourceCweId());
        assertEquals("8", finding.getSourceWascId());

        ZapAlert sqlAlert = new ZapAlert("40018", "SQL Injection", "High", "High",
                targetUrl + "/search", "q", "test", "database error", "Description", "Remediation",
                "", "", "");
        ScanFinding sqlFinding = new ZapScanAdapter().toFinding(job, sqlAlert);

        assertEquals("SUSPECTED", sqlFinding.getVerificationStatus());
        assertEquals("High", sqlFinding.getSourceConfidence());

        for (String confidence : List.of("Medium", "Low")) {
            ZapAlert xssAlert = new ZapAlert("40012", "Cross Site Scripting (Reflected)", "High", confidence,
                    targetUrl + "/search", "q", "", "", "Description", "Remediation",
                    "", "", "");
            assertEquals("POTENTIAL",
                    new ZapScanAdapter().toFinding(job, xssAlert).getVerificationStatus());
        }
        ZapAlert xssWithoutConfidence = new ZapAlert("40012", "Cross Site Scripting (Reflected)", "High", null,
                targetUrl + "/search", "q", "", "", "Description", "Remediation",
                "", "", "");
        assertEquals("POTENTIAL",
                new ZapScanAdapter().toFinding(job, xssWithoutConfidence).getVerificationStatus());

        ZapAlert xssProtectionHeaderAlert = new ZapAlert("10020", "X-XSS-Protection Header Not Set",
                "Low", "High", targetUrl, "", "", "", "Description", "Remediation",
                "", "", "");
        ScanFinding xssProtectionHeaderFinding = new ZapScanAdapter().toFinding(job, xssProtectionHeaderAlert);
        assertEquals("ZAP_X_XSS_PROTECTION_HEADER_NOT_SET", xssProtectionHeaderFinding.getCheckType());
        assertEquals("POTENTIAL", xssProtectionHeaderFinding.getVerificationStatus());
    }

    @Test
    void deduplicatesIdenticalZapEvidenceButPersistsDistinctEvidence() {
        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(11L, ScanType.ZAP_PASSIVE, targetUrl);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        when(findings.findByScanJob_Id(11L)).thenReturn(List.of());
        ScanExecutionService service = new ScanExecutionService(
                mock(ScanJobRepository.class), findings, false, null);
        ZapAlert original = new ZapAlert("40012", "Cross Site Scripting (Reflected)", "High", "High",
                targetUrl + "/search", "q", "<script>one</script>", "<script>one</script>",
                "Description", "Remediation", "https://example.test/rule", "79", "8");
        ZapAlert duplicate = new ZapAlert("40012", "Cross Site Scripting (Reflected)", "High", "High",
                targetUrl + "/search", "q", "<script>one</script>", "<script>one</script>",
                "Duplicate description", "Remediation", "https://example.test/rule", "79", "8");
        ZapAlert distinctEvidence = new ZapAlert("40012", "Cross Site Scripting (Reflected)", "High", "High",
                targetUrl + "/search", "q", "<script>two</script>", "<script>two</script>",
                "Description", "Remediation", "https://example.test/rule", "79", "8");

        ReflectionTestUtils.invokeMethod(service, "persistZapFindings",
                job, List.of(original, duplicate, distinctEvidence));

        ArgumentCaptor<ScanFinding> captor = ArgumentCaptor.forClass(ScanFinding.class);
        verify(findings, times(2)).save(captor.capture());
        assertTrue(captor.getAllValues().stream()
                .anyMatch(finding -> "<script>one</script>".equals(finding.getEvidence())));
        assertTrue(captor.getAllValues().stream()
                .anyMatch(finding -> "<script>two</script>".equals(finding.getEvidence())));
    }

    @Test
    void passiveZapWaitsForAnalysisAfterNativeChecks() throws Exception {
        zapMockServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        respond("/JSON/core/view/version/", "{\"version\":\"2.16.1\"}");
        respond("/JSON/context/action/newContext/", "{\"contextId\":\"11\"}");
        respond("/JSON/context/action/includeInContext/", "{\"Result\":\"OK\"}");
        respond("/JSON/context/action/removeContext/", "{\"Result\":\"OK\"}");
        respond("/JSON/spider/action/scan/", "{\"scan\":\"1\"}");
        respond("/JSON/spider/view/status/", "{\"status\":\"100\"}");
        respond("/JSON/spider/view/results/", "{\"results\":[\"http://example.test/\",\"http://example.test/a\"]}");
        AtomicInteger passiveQueueChecks = new AtomicInteger();
        zapMockServer.createContext("/JSON/pscan/view/recordsToScan/", exchange -> {
            String remaining = passiveQueueChecks.getAndIncrement() == 0 ? "1" : "0";
            byte[] body = ("{\"recordsToScan\":\"" + remaining + "\"}").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        respond("/JSON/core/view/alerts/", "{\"alerts\":[]}");
        zapMockServer.start();

        ZapClientService zapClient = new ZapClientService(
                "http://127.0.0.1:" + zapMockServer.getAddress().getPort(), "", true, 1, 1, new ObjectMapper());
        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(11L, ScanType.ZAP_PASSIVE, targetUrl);
        ScanJobRepository jobRepo = mock(ScanJobRepository.class);
        when(jobRepo.findByIdForExecutionUpdate(11L)).thenReturn(Optional.of(job));
        ScanFindingRepository findingRepo = mock(ScanFindingRepository.class);
        TransactionTemplate tx = mock(TransactionTemplate.class);
        doAnswer(invocation -> {
            ((java.util.function.Consumer<org.springframework.transaction.TransactionStatus>)
                    invocation.getArgument(0)).accept(null);
            return null;
        }).when(tx).executeWithoutResult(any());

        ScanExecutionService service = new ScanExecutionService(
                jobRepo, findingRepo, true, tx, null, null,
                10, 6, 15, null, null, zapClient, new ZapScanAdapter());
        permitTestTargetOrigin(service, job);
        service.execute(11L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals("Native and OWASP ZAP scans completed successfully", job.getStatusMessage());
        assertEquals("COMPLETED", job.getZapEngineStatus());
        assertEquals("COMPLETED", job.getZapSpiderStatus());
        assertEquals(2, job.getZapSpiderDiscoveredCount());
        assertEquals("COMPLETED", job.getZapPassiveStatus());
        assertEquals(0, job.getZapAlertCount());
        assertEquals(2, passiveQueueChecks.get());
        verify(findingRepo, atLeastOnce()).save(any(ScanFinding.class));
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
        AtomicBoolean activeScanWasScoped = new AtomicBoolean();
        AtomicBoolean targetOriginWasConfigured = new AtomicBoolean();
        zapMockServer.createContext("/JSON/context/action/newContext/", exchange -> {
            byte[] body = "{\"contextId\":\"7\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        zapMockServer.createContext("/JSON/context/action/includeInContext/", exchange -> {
            String query = URLDecoder.decode(exchange.getRequestURI().getRawQuery(), StandardCharsets.UTF_8);
            targetOriginWasConfigured.set(query.contains("http://127.0.0.1")
                    && query.contains("\\Q") && query.contains("\\E"));
            byte[] body = "{\"Result\":\"OK\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        zapMockServer.createContext("/JSON/context/action/removeContext/", exchange -> {
            byte[] body = "{\"Result\":\"OK\"}".getBytes(StandardCharsets.UTF_8);
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
        zapMockServer.createContext("/JSON/spider/view/results/", exchange -> {
            byte[] body = "{\"results\":[\"http://127.0.0.1/\",\"http://127.0.0.1/test\"]}"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream output = exchange.getResponseBody()) { output.write(body); }
        });
        zapMockServer.createContext("/JSON/ascan/action/scan/", exchange -> {
            String query = exchange.getRequestURI().getRawQuery();
            activeScanWasScoped.set(query != null && query.contains("inScopeOnly=true")
                    && query.contains("contextId=7"));
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
        zapMockServer.createContext("/JSON/pscan/view/recordsToScan/", exchange -> {
            byte[] body = "{\"recordsToScan\":\"0\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        zapMockServer.createContext("/JSON/core/view/alerts/", exchange -> {
            String alertsJson = "{\"alerts\":[" +
                    "{\"alert\":\"Cross Site Scripting (Reflected)\",\"risk\":\"High\",\"confidence\":\"High\",\"url\":\"http://127.0.0.1/test\",\"param\":\"q\",\"evidence\":\"<script>alert(1)</script> Bearer zap.synthetic-token\",\"description\":\"XSS description\",\"solution\":\"Sanitize input\"}," +
                    "{\"alert\":\"Cross Site Scripting (Reflected)\",\"risk\":\"High\",\"confidence\":\"High\",\"url\":\"http://127.0.0.1/test\",\"param\":\"q\",\"evidence\":\"<script>alert(1)</script> Bearer zap.synthetic-token\",\"description\":\"Duplicate duplicate\",\"solution\":\"Sanitize input\"}," +
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
                zapClient, new ZapScanAdapter()
        );
        permitTestTargetOrigin(executionService, job);

        executionService.execute(3L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals(100, job.getProgress());
        assertEquals("COMPLETED", job.getZapEngineStatus());
        assertEquals("COMPLETED", job.getZapSpiderStatus());
        assertEquals(2, job.getZapSpiderDiscoveredCount());
        assertEquals("COMPLETED", job.getZapPassiveStatus());
        assertEquals("COMPLETED", job.getZapActiveStatus());
        assertEquals(3, job.getZapAlertCount());
        assertEquals("Native and OWASP ZAP scans completed successfully", job.getStatusMessage());
        assertTrue(activeScanWasScoped.get());
        assertTrue(targetOriginWasConfigured.get());

        ArgumentCaptor<ScanFinding> findingCaptor = ArgumentCaptor.forClass(ScanFinding.class);
        verify(findingRepo, atLeast(2)).save(findingCaptor.capture());

        List<ScanFinding> savedFindings = findingCaptor.getAllValues().stream()
                .filter(finding -> "OWASP_ZAP".equals(finding.getDetectionSource()))
                .toList();
        assertEquals(2, savedFindings.size());

        ScanFinding xssFinding = savedFindings.stream()
                .filter(f -> f.getCheckType().equals("REFLECTED_XSS_POTENTIAL"))
                .findFirst().orElseThrow();
        assertEquals("HIGH", xssFinding.getSeverity());
        assertEquals("POTENTIAL", xssFinding.getVerificationStatus());
        assertEquals("High", xssFinding.getSourceConfidence());
        assertEquals("", xssFinding.getSourceRuleId());
        assertEquals("OWASP_ZAP", xssFinding.getDetectionSource());
        assertTrue(xssFinding.getAffectedComponent().contains("[q]"));
        assertFalse(xssFinding.getEvidence().contains("zap.synthetic-token"));

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
        when(zapClient.checkAvailability()).thenReturn(ZapClientService.AvailabilityStatus.AVAILABLE);

        ScanExecutionService executionService = new ScanExecutionService(
                jobRepo, findingRepo, false, tx, null, null, // allowPrivateTargets = false
                10, 6, 15, null, null,
                zapClient, new ZapScanAdapter()
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
                zapClient, new ZapScanAdapter()
        );
        permitTestTargetOrigin(executionService, job);

        executionService.execute(5L);

        // Cancellation checked during spider loop or runClaimed guard
        // Because cancellation was requested before runClaimed, runClaimed returns early
        assertNotEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals("NOT_STARTED", job.getZapEngineStatus());
        assertEquals("CANCELLED_BEFORE_ZAP", job.getZapFailureReason());
    }

    @Test
    void incompleteZapActiveScanRetainsNativeResultsAsPartialCompletion() throws Exception {
        zapMockServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        respond("/JSON/core/view/version/", "{\"version\":\"2.14.0\"}");
        respond("/JSON/context/action/newContext/", "{\"contextId\":\"9\"}");
        respond("/JSON/context/action/includeInContext/", "{\"Result\":\"OK\"}");
        respond("/JSON/context/action/removeContext/", "{\"Result\":\"OK\"}");
        respond("/JSON/spider/action/scan/", "{\"scan\":\"1\"}");
        respond("/JSON/spider/view/status/", "{\"status\":\"100\"}");
        respond("/JSON/spider/view/results/", "{\"results\":[]}");
        respond("/JSON/ascan/action/scan/", "{\"scan\":\"2\"}");
        respond("/JSON/ascan/view/status/", "{\"status\":\"0\"}");
        zapMockServer.start();

        ZapClientService zapClient = new ZapClientService(
                "http://127.0.0.1:" + zapMockServer.getAddress().getPort(), "", true, 1, 1, new ObjectMapper());
        String targetUrl = "http://127.0.0.1:" + targetServer.getAddress().getPort();
        ScanJob job = createApprovedJob(8L, ScanType.ZAP_ACTIVE, targetUrl);
        ScanJobRepository jobRepo = mock(ScanJobRepository.class);
        when(jobRepo.findByIdForExecutionUpdate(8L)).thenReturn(Optional.of(job));
        ScanFindingRepository findingRepo = mock(ScanFindingRepository.class);
        TransactionTemplate tx = mock(TransactionTemplate.class);
        doAnswer(invocation -> {
            ((java.util.function.Consumer<org.springframework.transaction.TransactionStatus>)
                    invocation.getArgument(0)).accept(null);
            return null;
        }).when(tx).executeWithoutResult(any());

        ScanExecutionService executionService = new ScanExecutionService(
                jobRepo, findingRepo, true, tx, null, null,
                10, 6, 15, null, null, zapClient, new ZapScanAdapter(), 2);
        permitTestTargetOrigin(executionService, job);
        executionService.execute(8L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertNull(job.getFailureReason());
        assertEquals("TIMED_OUT", job.getZapEngineStatus());
        assertEquals("TIME_BUDGET_EXCEEDED", job.getZapFailureReason());
        assertEquals("TIMED_OUT", job.getZapActiveStatus());
        assertEquals("COMPLETED", job.getZapSpiderStatus());
        assertEquals("NOT_STARTED", job.getZapPassiveStatus());
        assertTrue(job.getStatusMessage().contains("TIME_BUDGET_EXCEEDED"));
        verify(findingRepo, atLeastOnce()).save(any(ScanFinding.class));
    }

    private void respond(String path, String content) {
        zapMockServer.createContext(path, exchange -> {
            byte[] body = content.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
    }
}
