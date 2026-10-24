package com.vulnscanner.application.scan;

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
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class ScanExecutionServiceTest {
    private HttpServer server;
    private HttpServer secondaryServer;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
        if (secondaryServer != null) {
            secondaryServer.stop(0);
        }
    }

    @Test
    void scansControlledResponseAndPersistsOnlyObservedPassiveFindings() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "text/plain");
            exchange.getResponseHeaders().add("X-Content-Type-Options", "nosniff");
            exchange.getResponseHeaders().add("Referrer-Policy", "no-referrer");
            exchange.getResponseHeaders().add("Server", "Apache/2.4 token=synthetic-value");
            exchange.getResponseHeaders().add("Set-Cookie", "session=abc; HttpOnly; SameSite=Lax");
            exchange.getResponseHeaders().add("Set-Cookie", "preference=dark mode; SameSite=Lax");
            byte[] body = "controlled".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = new Organization();
        setId(organization, 17L);
        organization.setStatus(OrganizationStatus.APPROVED);
        Target target = new Target();
        target.setUrl("http://127.0.0.1:" + server.getAddress().getPort() + "/");
        target.setStatus(TargetStatus.APPROVED);
        target.setOrganization(organization);
        User analyst = new User();
        analyst.setOrganization(organization);
        analyst.setStatus(UserStatus.ACTIVE);
        analyst.setRoles(Set.of(new Role(RoleName.SECURITY_ANALYST)));
        ScanJob job = new ScanJob(target, organization, analyst, ScanType.PASSIVE_HEADERS);
        job.transitionTo(ScanStatus.PENDING_APPROVAL, 0, "Awaiting approval", null);
        job.approve(analyst);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        ScanExecutionService service = new ScanExecutionService(jobs, findings, false, null);
        ReflectionTestUtils.setField(service, "allowedPrivateTargetOrigins",
                "HTTP://127.0.0.1:" + server.getAddress().getPort());
        service.runClaimed(1L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus(), job.getStatusMessage());
        ArgumentCaptor<ScanFinding> captor = ArgumentCaptor.forClass(ScanFinding.class);
        verify(findings, atLeastOnce()).save(captor.capture());
        assertEquals("MISSING_CONTENT_SECURITY_POLICY", captor.getAllValues().stream()
                .map(ScanFinding::getCheckType).filter("MISSING_CONTENT_SECURITY_POLICY"::equals)
                .findFirst().orElseThrow());
        ScanFinding cookieFinding = captor.getAllValues().stream()
                .filter(finding -> "COOKIE_MISSING_HTTP_ONLY".equals(finding.getCheckType()))
                .findFirst().orElseThrow();
        assertEquals("OBSERVED", cookieFinding.getVerificationStatus());
        assertTrue(cookieFinding.getEvidence().contains("preference"));
        assertTrue(!cookieFinding.getEvidence().contains("dark mode"));
        assertTrue(!cookieFinding.getEvidence().contains("abc"));
        ScanFinding serverFinding = captor.getAllValues().stream()
                .filter(finding -> "INFORMATION_DISCLOSURE_SERVER".equals(finding.getCheckType()))
                .findFirst().orElseThrow();
        assertFalse(serverFinding.getEvidence().contains("synthetic-value"));
        verify(findings, never()).save(argThat(finding ->
                "MISSING_CONTENT_TYPE_OPTIONS".equals(finding.getCheckType())));
        verify(findings, never()).save(argThat(finding ->
                "MISSING_REFERRER_POLICY".equals(finding.getCheckType())));
    }

    @Test
    void crawlsSameOriginLinksWithFragmentNormalizationAndDeduplication() throws Exception {
        AtomicInteger crossOriginRequests = new AtomicInteger();
        secondaryServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        secondaryServer.createContext("/", exchange -> {
            crossOriginRequests.incrementAndGet();
            byte[] body = "<p>outside</p>".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        secondaryServer.start();

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicInteger staticRequests = new AtomicInteger();
        server.createContext("/", exchange -> {
            byte[] body = ("<a href=\"/child#section\">child</a>"
                    + "<a href=\"/child\">duplicate</a>"
                    + "<a href=\"/style.css\">static</a>"
                    + "<a href=\"http://127.0.0.1:" + secondaryServer.getAddress().getPort()
                    + "/outside\">outside</a>").getBytes();
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/child", exchange -> {
            byte[] body = "<p>child</p>".getBytes();
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/style.css", exchange -> {
            staticRequests.incrementAndGet();
            byte[] body = "body{}".getBytes();
            exchange.getResponseHeaders().add("Content-Type", "text/css");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        ScanCrawlPageRepository crawlPages = mock(ScanCrawlPageRepository.class);
        Organization organization = new Organization();
        setId(organization, 18L);
        organization.setStatus(OrganizationStatus.APPROVED);
        Target target = new Target();
        target.setUrl("http://127.0.0.1:" + server.getAddress().getPort() + "/");
        target.setStatus(TargetStatus.APPROVED);
        target.setOrganization(organization);
        User analyst = new User();
        analyst.setOrganization(organization);
        analyst.setStatus(UserStatus.ACTIVE);
        analyst.setRoles(Set.of(new Role(RoleName.SECURITY_ANALYST)));
        ScanJob job = new ScanJob(target, organization, analyst, ScanType.PASSIVE_HEADERS);
        job.transitionTo(ScanStatus.PENDING_APPROVAL, 0, "Awaiting approval", null);
        job.approve(analyst);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        ScanExecutionService service = new ScanExecutionService(
                jobs, findings, true, null, null, crawlPages);
        service.runClaimed(2L);

        verify(crawlPages, times(2)).save(any(ScanCrawlPage.class));
        assertEquals(1, staticRequests.get());
        assertEquals(0, crossOriginRequests.get());
        assertEquals(ScanStatus.COMPLETED, job.getStatus());
    }

    @Test
    void rejectsPrivateTargetWhenDevelopmentOverrideIsDisabled() {
        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(19L);
        Target target = approvedTarget(organization, "http://127.0.0.1:1/");
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        new ScanExecutionService(jobs, findings, false, null).runClaimed(3L);

        assertEquals(ScanStatus.FAILED, job.getStatus());
        verify(findings, never()).save(any());
    }

    @Test
    void privateTargetAllowlistRequiresExactOriginPort() {
        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(20L);
        Target target = approvedTarget(organization, "http://127.0.0.1:1/");
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        ScanExecutionService service = new ScanExecutionService(jobs, findings, false, null);
        ReflectionTestUtils.setField(service, "allowedPrivateTargetOrigins", "http://127.0.0.1:2");
        service.runClaimed(4L);

        assertEquals(ScanStatus.FAILED, job.getStatus());
        verify(findings, never()).save(any());
    }

    @Test
    void rejectsInvalidPrivateTargetOriginConfiguration() {
        ScanExecutionService service = new ScanExecutionService(
                mock(ScanJobRepository.class), mock(ScanFindingRepository.class), false, null);
        ReflectionTestUtils.setField(service, "allowedPrivateTargetOrigins", "http://127.0.0.1:99999");

        assertThrows(IllegalStateException.class, () -> service.validateResolvedAddresses(
                URI.create("http://127.0.0.1:8080/"), new java.util.HashMap<>()));
    }

    @Test
    void rejectsChangedDnsResolutionDuringScan() {
        ScanExecutionService service = new ScanExecutionService(
                mock(ScanJobRepository.class), mock(ScanFindingRepository.class), false, null);
        ReflectionTestUtils.setField(service, "allowedPrivateTargetOrigins", "http://127.0.0.1:8080");
        java.util.Map<String, java.util.Set<String>> priorResolution = new java.util.HashMap<>();
        priorResolution.put("127.0.0.1", java.util.Set.of("192.0.2.1"));

        assertThrows(ScanExecutionService.ScanExecutionException.class,
                () -> service.validateResolvedAddresses(
                        URI.create("http://127.0.0.1:8080/"), priorResolution));
    }

    @Test
    void rejectsCloudMetadataAddressesEvenWhenPrivateTargetsAreAllowed() throws Exception {
        ScanExecutionService service = new ScanExecutionService(
                mock(ScanJobRepository.class), mock(ScanFindingRepository.class), true, null);

        assertTrue(service.isCloudMetadata(java.net.InetAddress.getByName("169.254.169.254")));
        assertTrue(service.isCloudMetadata(java.net.InetAddress.getByName("169.254.170.2")));
        assertTrue(service.isCloudMetadata(java.net.InetAddress.getByName("fd00:ec2:0:0:0:0:0:254")));
    }

    @Test
    void rejectsHttpClientsConfiguredToFollowRedirects() {
        HttpClient redirectingClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.ALWAYS)
                .build();

        assertThrows(IllegalArgumentException.class, () -> new ScanExecutionService(
                mock(ScanJobRepository.class), mock(ScanFindingRepository.class), false,
                null, null, null, 10, 6, 15, redirectingClient, null));
    }

    @Test
    void doesNotFollowRedirectsToUnapprovedPrivateOrigin() throws Exception {
        AtomicInteger redirectedRequests = new AtomicInteger();
        secondaryServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        secondaryServer.createContext("/", exchange -> {
            redirectedRequests.incrementAndGet();
            byte[] body = "outside".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        secondaryServer.start();

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Location",
                    "http://127.0.0.1:" + secondaryServer.getAddress().getPort() + "/");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(24L);
        Target target = approvedTarget(organization,
                "http://127.0.0.1:" + server.getAddress().getPort() + "/");
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        ScanExecutionService service = new ScanExecutionService(jobs, findings, false, null);
        ReflectionTestUtils.setField(service, "allowedPrivateTargetOrigins",
                "http://127.0.0.1:" + server.getAddress().getPort());
        service.runClaimed(8L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals(0, redirectedRequests.get());
    }

    @Test
    void failsOversizedResponsesWithoutPersistingFindings() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = new byte[1_048_577];
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(20L);
        Target target = approvedTarget(organization,
                "http://127.0.0.1:" + server.getAddress().getPort() + "/");
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        new ScanExecutionService(jobs, findings, true, null).runClaimed(4L);

        assertEquals(ScanStatus.FAILED, job.getStatus());
        assertTrue("RESPONSE_LIMIT_EXCEEDED".equals(job.getFailureReason()));
        verify(findings, never()).save(any());
    }

    @Test
    void appliesRequestDeadlineToResponseBodyAfterHeaders() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            try {
                Thread.sleep(2_000);
                exchange.getResponseBody().write("late".getBytes(StandardCharsets.UTF_8));
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(24L);
        ScanJob job = approvedJob(organization, approvedTarget(organization,
                "http://127.0.0.1:" + server.getAddress().getPort() + "/"));
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        ScanExecutionService service = new ScanExecutionService(
                jobs, findings, true, null, null, null, 10, 6, 1,
                null, null, null, null, false);
        long startedAt = System.nanoTime();
        service.runClaimed(8L);

        assertEquals(ScanStatus.FAILED, job.getStatus());
        assertEquals(ScanFailureReason.TIME_BUDGET_EXCEEDED.name(), job.getFailureReason());
        assertTrue(TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - startedAt) < 4);
    }

    @Test
    void honorsCancellationRequestedWhileTheTargetBodyIsBeingRead() throws Exception {
        CountDownLatch requestReceived = new CountDownLatch(1);
        CountDownLatch finishResponse = new CountDownLatch(1);
        AtomicBoolean cancellationRequested = new AtomicBoolean(false);
        AtomicBoolean transactionOpen = new AtomicBoolean(false);
        AtomicBoolean targetRequestedInsideTransaction = new AtomicBoolean(false);
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            targetRequestedInsideTransaction.set(transactionOpen.get());
            requestReceived.countDown();
            try {
                finishResponse.await(5, TimeUnit.SECONDS);
                byte[] body = "safe".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(25L);
        ScanJob job = approvedJob(organization, approvedTarget(organization,
                "http://127.0.0.1:" + server.getAddress().getPort() + "/"));
        setId(job, 25L);
        when(jobs.findByIdForExecutionUpdate(25L)).thenReturn(Optional.of(job));
        when(jobs.findCancellationRequestedById(25L))
                .thenAnswer(invocation -> Optional.of(cancellationRequested.get()));
        org.springframework.transaction.support.TransactionTemplate tx =
                mock(org.springframework.transaction.support.TransactionTemplate.class);
        doAnswer(invocation -> {
            transactionOpen.set(true);
            try {
                ((java.util.function.Consumer<org.springframework.transaction.TransactionStatus>)
                        invocation.getArgument(0)).accept(null);
            } finally {
                transactionOpen.set(false);
            }
            return null;
        }).when(tx).executeWithoutResult(any());

        ScanExecutionService service = new ScanExecutionService(
                jobs, findings, true, tx, null, null, 10, 6, 10,
                null, null, null, null, false);
        var worker = java.util.concurrent.CompletableFuture.runAsync(() -> service.execute(25L));
        assertTrue(requestReceived.await(3, TimeUnit.SECONDS));
        cancellationRequested.set(true);
        finishResponse.countDown();
        worker.get(5, TimeUnit.SECONDS);

        assertEquals(ScanStatus.CANCELLED, job.getStatus());
        assertFalse(targetRequestedInsideTransaction.get());
    }

    @Test
    void passiveHeadersModeNeverSendsSqlInjectionOrXssProbes() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        List<String> queries = new CopyOnWriteArrayList<>();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.incrementAndGet();
            String query = exchange.getRequestURI().getRawQuery();
            queries.add(query == null ? "" : query);
            String decoded = URLDecoder.decode(query == null ? "" : query, StandardCharsets.UTF_8);
            String body;
            if (decoded.contains("' OR '1'='1") || decoded.contains("' OR '1'='2")) {
                body = "Database error: SQL syntax near query";
            } else if (decoded.contains("vscanxss")) {
                body = "<html>" + decoded.substring(decoded.indexOf('=') + 1) + "</html>";
            } else {
                body = "safe";
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(21L);
        Target target = approvedTarget(organization,
                "http://127.0.0.1:" + server.getAddress().getPort() + "/?id=1");
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        ScanExecutionService service = new ScanExecutionService(jobs, findings, true, null);
        service.runClaimed(5L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals(1, requests.get());
        assertEquals(List.of("id=1"), queries);
        verify(findings, never()).save(argThat(finding ->
                "SQL_INJECTION_SUSPECTED".equals(finding.getCheckType())
                        || "REFLECTED_XSS_POTENTIAL".equals(finding.getCheckType())));
    }

    @Test
    void explicitActiveModeRunsBoundedSqlAndXssChecks() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.incrementAndGet();
            String decoded = URLDecoder.decode(
                    exchange.getRequestURI().getRawQuery() == null ? ""
                            : exchange.getRequestURI().getRawQuery(),
                    StandardCharsets.UTF_8);
            String body;
            int status = 200;
            if (decoded.contains("' OR '1'='1")) {
                body = "Database error: SQL syntax near query";
                status = 500;
            } else if (decoded.contains("vscanxss")) {
                body = "<html>" + decoded.substring(decoded.indexOf('=') + 1) + "</html>";
            } else {
                body = "<html>safe</html>";
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(26L);
        Target target = approvedTarget(organization,
                "http://127.0.0.1:" + server.getAddress().getPort() + "/?id=1");
        ScanJob job = approvedJob(organization, target);
        ReflectionTestUtils.setField(job, "scanType", ScanType.ZAP_ACTIVE);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));
        ZapClientService zap = mock(ZapClientService.class);
        when(zap.isAvailable()).thenReturn(true);
        when(zap.createTargetContext(any(), anyString()))
                .thenReturn(new ZapClientService.ScopeContext("test-context", "1"));
        when(zap.startSpider(anyString(), anyString())).thenReturn("spider-1");
        when(zap.getSpiderProgress("spider-1")).thenReturn(100);
        when(zap.startActiveScan(anyString(), any())).thenReturn("active-1");
        when(zap.getActiveScanProgress("active-1")).thenReturn(100);
        when(zap.getAlerts(anyString())).thenReturn(List.of());

        ScanExecutionService service = new ScanExecutionService(
                jobs, findings, true, null, null, null, 10, 6, 5,
                null, null, zap, new ZapScanAdapter(), false);
        service.runClaimed(26L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus(), job.getStatusMessage());
        ArgumentCaptor<ScanFinding> captor = ArgumentCaptor.forClass(ScanFinding.class);
        verify(findings, atLeastOnce()).save(captor.capture());
        assertTrue(captor.getAllValues().stream()
                .anyMatch(finding -> "SQL_INJECTION_SUSPECTED".equals(finding.getCheckType())));
        assertTrue(captor.getAllValues().stream()
                .anyMatch(finding -> "REFLECTED_XSS_POTENTIAL".equals(finding.getCheckType())));
        assertEquals(4, requests.get());
    }

    @Test
    void doesNotReportSqlOrXssWhenInputIsEncodedOrNoDatabaseSignalExists() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = "safe response".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(22L);
        Target target = approvedTarget(organization,
                "http://127.0.0.1:" + server.getAddress().getPort() + "/?id=1");
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        new ScanExecutionService(jobs, findings, true, null).runClaimed(6L);

        verify(findings, never()).save(argThat(finding ->
                "SQL_INJECTION_SUSPECTED".equals(finding.getCheckType())
                        || "REFLECTED_XSS_POTENTIAL".equals(finding.getCheckType())));
        assertEquals(ScanStatus.COMPLETED, job.getStatus());
    }

    @Test
    void passiveHeadersScanUsesOnlyTheCrawlRequestBudget() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.incrementAndGet();
            byte[] body = "safe".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(23L);
        Target target = approvedTarget(organization,
                "http://127.0.0.1:" + server.getAddress().getPort() + "/?one=1&two=2&three=3");
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        new ScanExecutionService(jobs, findings, true, null).runClaimed(7L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals(1, requests.get());
    }

    @Test
    void rejectsMalformedCredentialAndMulticastUrls() {
        for (String url : Set.of("http://user:pass@127.0.0.1:1/", "http://[malformed",
                "http://224.0.0.1:80/")) {
            ScanJobRepository jobs = mock(ScanJobRepository.class);
            ScanFindingRepository findings = mock(ScanFindingRepository.class);
            Organization organization = approvedOrganization(21L);
            ScanJob job = approvedJob(organization, approvedTarget(organization, url));
            when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

            new ScanExecutionService(jobs, findings, false, null).runClaimed(5L);

            assertEquals(ScanStatus.FAILED, job.getStatus());
            verify(findings, never()).save(any());
        }
    }

    @Test
    void scansLocalHostTargetSuccessfullyWithHttp11() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            byte[] body = "<html><body><h1>LocalHost App</h1></body></html>".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        ScanCrawlPageRepository crawlPages = mock(ScanCrawlPageRepository.class);
        Organization organization = approvedOrganization(99L);
        Target target = approvedTarget(organization, "http://127.0.0.1:" + server.getAddress().getPort() + "/");
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        ScanExecutionService service = new ScanExecutionService(jobs, findings, true, null, null, crawlPages);
        service.runClaimed(99L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals(100, job.getProgress());
        verify(crawlPages, times(1)).save(any(ScanCrawlPage.class));
    }

    @Test
    void scanRecoveryRunnerMarksInterruptedScansAsFailed() {
        ScanJobRepository jobs = mock(ScanJobRepository.class);
        Organization organization = approvedOrganization(100L);
        Target target = approvedTarget(organization, "http://127.0.0.1:8080/");
        ScanJob crawlingJob = approvedJob(organization, target);
        crawlingJob.transitionTo(ScanStatus.CRAWLING, 10, "Discovering", null);

        when(jobs.findByStatusIn(anyCollection())).thenReturn(java.util.List.of(crawlingJob));

        ScanRecoveryRunner runner = new ScanRecoveryRunner(jobs);
        runner.run(null);

        assertEquals(ScanStatus.FAILED, crawlingJob.getStatus());
        assertEquals("EXECUTOR_UNAVAILABLE", crawlingJob.getFailureReason());
        assertTrue(crawlingJob.getStatusMessage().contains("restart"));
        verify(jobs).save(crawlingJob);
    }

    @Test
    void doesNotReportXssWhenReflectedInJsonContentType() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String query = exchange.getRequestURI().getRawQuery();
            String decoded = URLDecoder.decode(query == null ? "" : query, StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            byte[] body = ("{\"input\": \"" + (decoded.contains("=") ? decoded.substring(decoded.indexOf('=') + 1) : "") + "\"}").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(30L);
        Target target = approvedTarget(organization, "http://127.0.0.1:" + server.getAddress().getPort() + "/?name=test");
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        new ScanExecutionService(jobs, findings, true, null).runClaimed(30L);

        verify(findings, never()).save(argThat(finding -> "REFLECTED_XSS_POTENTIAL".equals(finding.getCheckType())));
        assertEquals(ScanStatus.COMPLETED, job.getStatus());
    }

    @Test
    void matchesNvdCveWhenSoftwareVersionIsDisclosed() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "text/plain");
            exchange.getResponseHeaders().add("Server", "Apache/2.4.49");
            byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(31L);
        Target target = approvedTarget(organization, "http://127.0.0.1:" + server.getAddress().getPort() + "/");
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        NvdCveService nvdService = mock(NvdCveService.class);
        when(nvdService.parseSoftwareVersion("Apache/2.4.49"))
                .thenReturn(new NvdCveService.SoftwareVersion("Apache", "2.4.49"));
        when(nvdService.findCves("Apache", "2.4.49")).thenReturn(java.util.List.of(
                new CveMatch("CVE-2021-41773", "Apache", "2.4.49", 7.5, "HIGH",
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Path traversal flaw in Apache HTTP Server 2.4.49")
        ));

        ScanExecutionService service = new ScanExecutionService(jobs, findings, true, null,
                null, null, 10, 6, 15, null, nvdService);
        service.runClaimed(31L);

        ArgumentCaptor<ScanFinding> captor = ArgumentCaptor.forClass(ScanFinding.class);
        verify(findings, atLeastOnce()).save(captor.capture());
        ScanFinding cveFinding = captor.getAllValues().stream()
                .filter(f -> "CVE_KEYWORD_CANDIDATE".equals(f.getCheckType()))
                .findFirst().orElseThrow();
        assertEquals("LOW", cveFinding.getSeverity());
        assertEquals("NVD_CVE_LOOKUP", cveFinding.getDetectionSource());
        assertEquals("POTENTIAL", cveFinding.getVerificationStatus());
        assertTrue(cveFinding.getEvidence().contains("CVE-2021-41773"));
        assertTrue(cveFinding.getEvidence().contains("Product and version applicability are not verified"));
        assertTrue(cveFinding.getEvidence().contains("NVD CVSS: 7.5"));
        assertTrue(cveFinding.getEvidence().contains("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"));
    }

    private void setId(Object entity, long id) {
        ReflectionTestUtils.setField(entity, "id", id);
    }

    private Organization approvedOrganization(long id) {
        Organization organization = new Organization();
        setId(organization, id);
        organization.setStatus(OrganizationStatus.APPROVED);
        return organization;
    }

    private Target approvedTarget(Organization organization, String url) {
        Target target = new Target();
        target.setUrl(url);
        target.setStatus(TargetStatus.APPROVED);
        target.setOrganization(organization);
        return target;
    }

    private ScanJob approvedJob(Organization organization, Target target) {
        User analyst = new User();
        analyst.setOrganization(organization);
        analyst.setStatus(UserStatus.ACTIVE);
        analyst.setRoles(Set.of(new Role(RoleName.SECURITY_ANALYST)));
        ScanJob job = new ScanJob(target, organization, analyst, ScanType.PASSIVE_HEADERS);
        job.transitionTo(ScanStatus.PENDING_APPROVAL, 0, "Awaiting approval", null);
        job.approve(analyst);
        return job;
    }
}
