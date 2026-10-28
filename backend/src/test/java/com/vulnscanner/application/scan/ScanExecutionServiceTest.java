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
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
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
    void normalizeCanonicalizesSchemeAndHostAndPreservesRawComponents() {
        ScanExecutionService service = new ScanExecutionService(
                mock(ScanJobRepository.class), mock(ScanFindingRepository.class), false, null);

        assertEquals("http://example.com/a?x=1",
                ReflectionTestUtils.invokeMethod(service, "normalize", URI.create("HTTP://Example.COM/a?x=1"))
                        .toString());
        assertEquals("http://127.0.0.1:8080/a?x=1",
                ReflectionTestUtils.invokeMethod(service, "normalize", URI.create("http://127.0.0.1:8080/a?x=1"))
                        .toString());
        assertEquals("http://[::1]:8080/a?x=1",
                ReflectionTestUtils.invokeMethod(service, "normalize", URI.create("http://[::1]:8080/a?x=1"))
                        .toString());
        assertEquals("http://example.com/a%20b?keep=a%20b&tail=x%2By",
                ReflectionTestUtils.invokeMethod(service, "normalize",
                        URI.create("http://example.com/a%20b?keep=a%20b&tail=x%2By"))
                        .toString());
        assertEquals("http://example.com/?literal=a+b&encoded=a%2Bb&space=a%20b",
                ReflectionTestUtils.invokeMethod(service, "normalize",
                        URI.create("http://example.com/?literal=a+b&encoded=a%2Bb&space=a%20b"))
                        .toString());
        assertEquals("http://user:pass@example.com:8080/a",
                ReflectionTestUtils.invokeMethod(service, "normalize",
                        URI.create("http://user:pass@Example.COM:8080/a"))
                        .toString());
    }

    @Test
    void normalizeCanonicalizesSchemeHostAndPreservesExactEncoding() {
        ScanExecutionService service = new ScanExecutionService(
                mock(ScanJobRepository.class), mock(ScanFindingRepository.class), false, null);

        assertEquals("http://example.com/a?x=1",
                ReflectionTestUtils.invokeMethod(service, "normalize", URI.create("HTTP://Example.COM/a?x=1"))
                        .toString());
        assertEquals("http://127.0.0.1:8080/a?x=1",
                ReflectionTestUtils.invokeMethod(service, "normalize", URI.create("http://127.0.0.1:8080/a?x=1"))
                        .toString());
        assertEquals("http://[::1]:8080/a?x=1",
                ReflectionTestUtils.invokeMethod(service, "normalize", URI.create("http://[::1]:8080/a?x=1"))
                        .toString());
        assertEquals("http://example.com/a%20b?keep=a%20b&tail=x%2By",
                ReflectionTestUtils.invokeMethod(service, "normalize",
                        URI.create("http://example.com/a%20b?keep=a%20b&tail=x%2By"))
                        .toString());
    }

    @Test
    void normalizeCanonicalizesEquivalentRootPathAndDefaultPort() {
        ScanExecutionService service = new ScanExecutionService(
                mock(ScanJobRepository.class), mock(ScanFindingRepository.class), false, null);

        assertEquals("http://example.com/",
                ReflectionTestUtils.invokeMethod(service, "normalize", URI.create("http://example.com"))
                        .toString());
        assertEquals("http://example.com/",
                ReflectionTestUtils.invokeMethod(service, "normalize", URI.create("http://example.com:80/"))
                        .toString());
        assertEquals("https://example.com/",
                ReflectionTestUtils.invokeMethod(service, "normalize", URI.create("https://example.com:443"))
                        .toString());
    }

    @Test
    void postActionAllowlistCanonicalizesOriginButKeepsPathAndQueryExact() {
        ScanExecutionService service = new ScanExecutionService(
                mock(ScanJobRepository.class), mock(ScanFindingRepository.class), false, null);
        ReflectionTestUtils.setField(service, "activePostFormAllowlist",
                "HTTP://Example.COM:80/search/../search?mode=basic");

        assertEquals(Boolean.TRUE, ReflectionTestUtils.invokeMethod(service, "isConfiguredPostAction",
                URI.create("http://example.com/search?mode=basic")));
        assertEquals(Boolean.FALSE, ReflectionTestUtils.invokeMethod(service, "isConfiguredPostAction",
                URI.create("http://example.com/search/?mode=basic")));
        assertEquals(Boolean.FALSE, ReflectionTestUtils.invokeMethod(service, "isConfiguredPostAction",
                URI.create("http://example.com/search?mode=advanced")));
        assertEquals(Boolean.FALSE, ReflectionTestUtils.invokeMethod(service, "isConfiguredPostAction",
                URI.create("http://example.com/search?mode=basic#fragment")));

        ReflectionTestUtils.setField(service, "activePostFormAllowlist",
                "http://example.com/search?mode=basic#fragment");
        assertEquals(Boolean.FALSE, ReflectionTestUtils.invokeMethod(service, "isConfiguredPostAction",
                URI.create("http://example.com/search?mode=basic")));
    }

    @Test
    void queryParametersDecodeFormEncodingAndRetainEmptyParameterSlots() {
        ScanExecutionService service = new ScanExecutionService(
                mock(ScanJobRepository.class), mock(ScanFindingRepository.class), false, null);

        List<?> parameters = ReflectionTestUtils.invokeMethod(service, "queryParameters",
                URI.create("http://example.com/?literal+name=one&literal%2Bname=two"
                        + "&space%20name=three&%69d=4&flag&flag=&&tail=x%2By"));

        assertEquals(List.of(
                "literal name=one@0",
                "literal+name=two@1",
                "space name=three@2",
                "id=4@3",
                "flag=@4",
                "flag=@5",
                "tail=x+y@7"),
                parameters.stream()
                        .map(parameter -> ReflectionTestUtils.getField(parameter, "name") + "="
                                + ReflectionTestUtils.getField(parameter, "value") + "@"
                                + ReflectionTestUtils.getField(parameter, "rawPartIndex"))
                        .toList());
    }

    private void permitTestTarget(ScanExecutionService service, ScanJob job) {
        URI target = URI.create(job.getTarget().getUrl());
        ReflectionTestUtils.setField(service, "allowedPrivateTargetOrigins",
                target.getScheme() + "://" + target.getRawAuthority());
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
        ScanFinding cspFinding = captor.getAllValues().stream()
                .filter(finding -> "MISSING_CONTENT_SECURITY_POLICY".equals(finding.getCheckType()))
                .findFirst().orElseThrow();
        assertEquals("OBSERVED", cspFinding.getVerificationStatus());
        ScanFinding cookieFinding = captor.getAllValues().stream()
                .filter(finding -> "COOKIE_MISSING_HTTP_ONLY".equals(finding.getCheckType()))
                .findFirst().orElseThrow();
        assertEquals("OBSERVED", cookieFinding.getVerificationStatus());
        assertEquals("LOW", cookieFinding.getSeverity());
        assertTrue(cookieFinding.getRationale().contains("exploitability was not verified"));
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
            byte[] body = ("<a href=\"child#section\">child</a>"
                    + "<a href=\"./child\">duplicate</a>"
                    + "<a href=\"/style.css\">static</a>"
                    + "<a href=\"http://127.0.0.1:" + secondaryServer.getAddress().getPort()
                    + "/outside\">outside</a>").getBytes();
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/child", exchange -> {
            byte[] body = ("<p>child</p><form method=\"POST\" action=\"/post-only\">"
                    + "<input name=\"username\" value=\"not-persisted\">"
                    + "<input name=\"password\" value=\"secret\"></form>"
                    + "<form method=\"GET\" action=\"/get-only\"><input name=\"search\"></form>").getBytes();
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        AtomicInteger postActionGetRequests = new AtomicInteger();
        AtomicInteger postActionPostRequests = new AtomicInteger();
        server.createContext("/post-only", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                postActionPostRequests.incrementAndGet();
            } else {
                postActionGetRequests.incrementAndGet();
            }

            byte[] body = "post action".getBytes();
            exchange.getResponseHeaders().add("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        AtomicInteger getActionRequests = new AtomicInteger();
        server.createContext("/get-only", exchange -> {
            getActionRequests.incrementAndGet();
            byte[] body = "get action".getBytes();
            exchange.getResponseHeaders().add("Content-Type", "text/plain");
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
        permitTestTarget(service, job);
        service.runClaimed(2L);

        ArgumentCaptor<ScanCrawlPage> pagesCaptor = ArgumentCaptor.forClass(ScanCrawlPage.class);
        verify(crawlPages, times(2)).save(pagesCaptor.capture());
        ScanCrawlPage childPage = pagesCaptor.getAllValues().stream()
                .filter(page -> page.getUrl().endsWith("/child"))
                .findFirst().orElseThrow();
        assertEquals(2, childPage.getDiscoveredForms().size());
        DiscoveredForm postForm = childPage.getDiscoveredForms().stream()
                .filter(form -> "POST".equals(form.method()))
                .findFirst().orElseThrow();
        assertTrue(postForm.actionUrl().endsWith("/post-only"));
        assertEquals(List.of("username", "password"), postForm.parameterNames());
        DiscoveredForm getForm = childPage.getDiscoveredForms().stream()
                .filter(form -> "GET".equals(form.method()))
                .findFirst().orElseThrow();
        assertTrue(getForm.actionUrl().endsWith("/get-only"));
        assertEquals(List.of("search"), getForm.parameterNames());
        assertEquals(0, postActionGetRequests.get());
        assertEquals(0, postActionPostRequests.get());
        assertEquals(1, getActionRequests.get());
        assertEquals(1, staticRequests.get());
        assertEquals(0, crossOriginRequests.get());
        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals(4, job.getDiscoveredPageCount());
        assertEquals(4, job.getVisitedPageCount());
        assertEquals(4, job.getTestedPassivePageCount());
        ArgumentCaptor<ScanFinding> findingsCaptor = ArgumentCaptor.forClass(ScanFinding.class);
        verify(findings, atLeastOnce()).save(findingsCaptor.capture());
        assertTrue(findingsCaptor.getAllValues().stream().anyMatch(finding ->
                "MISSING_CONTENT_SECURITY_POLICY".equals(finding.getCheckType())
                        && finding.getAffectedComponent().contains("/child [Content-Security-Policy]")));
    }

    @Test
    void discoversLinksFromHtmlEncodedWithTheDeclaredResponseCharset() {
        ScanExecutionService service = new ScanExecutionService(
                mock(ScanJobRepository.class), mock(ScanFindingRepository.class), false, null);
        URI origin = URI.create("http://example.test/");
        byte[] body = "<a href=\"/caf\u00e9\">café</a>".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        assertEquals("<a href=\"/café\">café</a>",
                new String(body, java.nio.charset.StandardCharsets.ISO_8859_1));
        assertEquals(java.nio.charset.StandardCharsets.ISO_8859_1,
                ReflectionTestUtils.invokeMethod(service, "responseCharset", "text/html; charset=ISO-8859-1"));

        Object discovery = ReflectionTestUtils.invokeMethod(service, "discoverPage",
                origin, origin, "text/html; charset=ISO-8859-1", body);

        assertEquals(List.of(URI.create("http://example.test/café")),
                ReflectionTestUtils.getField(discovery, "links"));
    }

    @Test
    void rejectsUnconfiguredPrivateTarget() {
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
    void acceptsPublicHttpAndHttpsAddressesWithoutAnOriginAllowlist() throws Exception {
        ScanExecutionService service = serviceResolving(InetAddress.getByName("93.184.216.34"),
                InetAddress.getByName("2606:2800:220:1:248:1893:25c8:1946"));

        service.validateResolvedAddresses(URI.create("https://public.example/"), new java.util.HashMap<>());
        service.validateResolvedAddresses(URI.create("http://public-v6.example/"), new java.util.HashMap<>());
    }

    @Test
    void explicitOriginAllowsPrivateLabAddressButLegacyGlobalFlagDoesNot() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        ScanExecutionService service = serviceResolving(loopback);
        URI allowedTarget = URI.create("http://127.0.0.1:8080/");

        assertThrows(ScanExecutionService.ScanExecutionException.class,
                () -> service.validateResolvedAddresses(allowedTarget, new java.util.HashMap<>()));

        ReflectionTestUtils.setField(service, "allowedPrivateTargetOrigins", "http://127.0.0.1:8080");
        service.validateResolvedAddresses(allowedTarget, new java.util.HashMap<>());
        assertThrows(ScanExecutionService.ScanExecutionException.class,
                () -> service.validateResolvedAddresses(
                        URI.create("http://127.0.0.1:8081/"), new java.util.HashMap<>()));
    }

    @Test
    void rejectsIpv4AndIpv6LoopbackAndUnsafeLinkLocalAndMetadataAddresses() throws Exception {
        for (String address : List.of("127.0.0.1", "::1", "169.254.10.20", "fe80::1",
                "169.254.169.254", "169.254.170.2", "fd00:ec2::254")) {
            ScanExecutionService service = serviceResolving(InetAddress.getByName(address));
            assertThrows(ScanExecutionService.ScanExecutionException.class,
                    () -> service.validateResolvedAddresses(
                            URI.create("http://target.example:8080/"), new java.util.HashMap<>()),
                    address);
        }
    }

    @Test
    void rejectsDnsAnswersMixingAllowedAndDisallowedAddresses() throws Exception {
        InetAddress publicAddress = InetAddress.getByAddress(
                new byte[]{93, (byte) 184, (byte) 216, 34});
        InetAddress privateAddress = InetAddress.getByAddress(
                new byte[]{10, 0, 0, 8});

        for (InetAddress[] addresses : List.of(
                new InetAddress[]{publicAddress, privateAddress},
                new InetAddress[]{privateAddress, publicAddress})) {
            ScanExecutionService service = serviceResolving(addresses);
            assertThrows(ScanExecutionService.ScanExecutionException.class,
                    () -> service.validateResolvedAddresses(
                            URI.create("https://mixed-dns.example/"), new java.util.HashMap<>()));
        }
    }

    @Test
    void rejectsDnsResolutionFailures() {
        ScanExecutionService service = new ScanExecutionService(
                mock(ScanJobRepository.class), mock(ScanFindingRepository.class), false, null) {
            @Override
            InetAddress[] resolveAddresses(String host) throws UnknownHostException {
                throw new UnknownHostException(host);
            }
        };

        assertThrows(UnknownHostException.class, () -> service.validateResolvedAddresses(
                URI.create("https://unresolvable.example/"), new java.util.HashMap<>()));
    }

    @Test
    void rejectsNonGlobalAndSpecialUseAddressRangesEvenIfAnOriginIsConfigured() throws Exception {
        for (String address : List.of("0.1.2.3", "100.64.0.1", "192.0.2.1",
                "198.18.0.1", "224.0.0.1", "240.0.0.1", "2001:db8::1", "2002::1")) {
            ScanExecutionService service = serviceResolving(InetAddress.getByName(address));
            ReflectionTestUtils.setField(service, "allowedPrivateTargetOrigins",
                    "https://target.example");
            assertThrows(ScanExecutionService.ScanExecutionException.class,
                    () -> service.validateResolvedAddresses(
                            URI.create("https://target.example/"), new java.util.HashMap<>()),
                    address);
        }
    }

    @Test
    void rejectsUnconfiguredPrivateNetworkAddressesEvenWhenLegacyFlagIsTrue() throws Exception {
        for (String address : List.of("10.0.0.8", "172.16.0.1", "192.168.1.10", "fc00::1")) {
            ScanExecutionService service = serviceResolving(InetAddress.getByName(address));
            assertThrows(ScanExecutionService.ScanExecutionException.class,
                    () -> service.validateResolvedAddresses(
                            URI.create("https://private.example/"), new java.util.HashMap<>()),
                    address);
        }
    }

    private ScanExecutionService serviceResolving(InetAddress... addresses) {
        return new ScanExecutionService(
                mock(ScanJobRepository.class), mock(ScanFindingRepository.class), true, null) {
            @Override
            InetAddress[] resolveAddresses(String host) {
                return addresses;
            }
        };
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

        assertEquals(ScanStatus.FAILED, job.getStatus());
        assertEquals("TARGET_URL_INVALID", job.getFailureReason());
        assertTrue(job.getStatusMessage().contains("outside the authorized target origin"));
        assertEquals(0, redirectedRequests.get());
    }

    @Test
    void followsValidatedSameOriginRedirectAndScansFinalResponse() throws Exception {
        AtomicInteger finalRequests = new AtomicInteger();
        AtomicInteger relativeRequests = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().add("Location", "/nested/landing");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.createContext("/nested/landing", exchange -> {
            finalRequests.incrementAndGet();
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            byte[] body = "<html><body><a href=\"child\">child</a></body></html>"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/nested/child", exchange -> {
            relativeRequests.incrementAndGet();
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            byte[] body = "<html><body>child</body></html>".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(104L);
        Target target = approvedTarget(organization,
                "http://127.0.0.1:" + server.getAddress().getPort() + "/redirect");
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));
        ScanExecutionService service = new ScanExecutionService(jobs, findings, false, null);
        permitTestTarget(service, job);

        service.runClaimed(104L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus(), job.getStatusMessage());
        assertEquals(1, finalRequests.get());
        assertEquals(1, relativeRequests.get());
        assertEquals(3, job.getDiscoveredPageCount());
        assertEquals(2, job.getVisitedPageCount());
    }

    @Test
    void crawlStopsAtConfiguredRequestBudgetAndKeepsDiscoveredAndVisitedCountsDistinct() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.incrementAndGet();
            byte[] body = "<a href=\"/one\">one</a><a href=\"/two\">two</a>"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/one", exchange -> {
            requests.incrementAndGet();
            byte[] body = "one".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/two", exchange -> {
            requests.incrementAndGet();
            byte[] body = "two".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        Organization organization = approvedOrganization(105L);
        Target target = approvedTarget(organization,
                "http://127.0.0.1:" + server.getAddress().getPort() + "/");
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));
        ScanExecutionService service = new ScanExecutionService(
                jobs, mock(ScanFindingRepository.class), true, null, null, null, 2, 6, 5);
        permitTestTarget(service, job);

        service.runClaimed(105L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus(), job.getStatusMessage());
        assertEquals(2, requests.get());
        assertEquals(3, job.getDiscoveredPageCount());
        assertEquals(2, job.getVisitedPageCount());
        assertEquals(2, job.getTestedPassivePageCount());
    }

    @Test
    void rejectsRedirectLoopsBeforeRepeatingAnOutboundRequest() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/first", exchange -> {
            requests.incrementAndGet();
            exchange.getResponseHeaders().add("Location", "/second");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.createContext("/second", exchange -> {
            requests.incrementAndGet();
            exchange.getResponseHeaders().add("Location", "/first");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.start();
        ScanJobRepository jobs = mock(ScanJobRepository.class);
        Organization organization = approvedOrganization(106L);
        Target target = approvedTarget(organization,
                "http://127.0.0.1:" + server.getAddress().getPort() + "/first");
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));
        ScanExecutionService service = new ScanExecutionService(
                jobs, mock(ScanFindingRepository.class), false, null);
        permitTestTarget(service, job);

        service.runClaimed(106L);

        assertEquals(ScanStatus.FAILED, job.getStatus());
        assertEquals("TARGET_URL_INVALID", job.getFailureReason());
        assertEquals(2, requests.get());
    }

    @Test
    void rejectsAmbiguousRedirectLocations() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Location", "/first");
            exchange.getResponseHeaders().add("Location", "/second");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.start();
        ScanJobRepository jobs = mock(ScanJobRepository.class);
        Organization organization = approvedOrganization(107L);
        Target target = approvedTarget(organization,
                "http://127.0.0.1:" + server.getAddress().getPort() + "/");
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));
        ScanExecutionService service = new ScanExecutionService(
                jobs, mock(ScanFindingRepository.class), false, null);
        permitTestTarget(service, job);

        service.runClaimed(107L);

        assertEquals(ScanStatus.FAILED, job.getStatus());
        assertEquals("TARGET_URL_INVALID", job.getFailureReason());
        assertTrue(job.getStatusMessage().contains("ambiguous redirect"));
    }

    @Test
    void connectsToTheValidatedDnsAddressWithoutResolvingHostnameAgain() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.incrementAndGet();
            byte[] body = "<html>pinned</html>".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(105L);
        String url = "http://scanner-target.test:" + server.getAddress().getPort() + "/";
        Target target = approvedTarget(organization, url);
        ScanJob job = approvedJob(organization, target);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));
        InetAddress resolvedAddress = InetAddress.getByName("127.0.0.1");
        ScanExecutionService service = new ScanExecutionService(jobs, findings, false, null) {
            @Override
            InetAddress[] resolveAddresses(String host) {
                assertEquals("scanner-target.test", host);
                return new InetAddress[]{resolvedAddress};
            }
        };
        ReflectionTestUtils.setField(service, "allowedPrivateTargetOrigins",
                "http://scanner-target.test:" + server.getAddress().getPort());

        service.runClaimed(105L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus(), job.getStatusMessage());
        assertEquals(1, requests.get());
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

        ScanExecutionService service = new ScanExecutionService(jobs, findings, true, null);
        permitTestTarget(service, job);
        service.runClaimed(4L);

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
                null, null, null, null);
        permitTestTarget(service, job);
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
                null, null, null, null);
        permitTestTarget(service, job);
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
        permitTestTarget(service, job);
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
        List<String> rawQueries = new CopyOnWriteArrayList<>();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.incrementAndGet();
            String rawQuery = exchange.getRequestURI().getRawQuery();
            rawQueries.add(rawQuery == null ? "" : rawQuery);
            String decoded = URLDecoder.decode(rawQuery == null ? "" : rawQuery, StandardCharsets.UTF_8);
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
                "http://127.0.0.1:" + server.getAddress().getPort()
                        + "/?id=1&keep=a%20b&id=2&tail=x%2By&literal=a+b"
                        + "&encoded=a%2Bb&space=a%20b&&flag&flag=");
        ScanJob job = approvedJob(organization, target);
        ReflectionTestUtils.setField(job, "scanType", ScanType.ZAP_ACTIVE);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));
        ZapClientService zap = mock(ZapClientService.class);
        when(zap.isEnabled()).thenReturn(true);
        when(zap.checkAvailability()).thenReturn(ZapClientService.AvailabilityStatus.AVAILABLE);
        when(zap.createTargetContext(any(), anyString()))
                .thenReturn(new ZapClientService.ScopeContext("test-context", "1"));
        when(zap.startSpider(anyString(), anyString())).thenReturn("spider-1");
        when(zap.getSpiderProgress("spider-1")).thenReturn(100);
        when(zap.startActiveScan(anyString(), any())).thenReturn("active-1");
        when(zap.getActiveScanProgress("active-1")).thenReturn(100);
        when(zap.getAlerts(anyString())).thenReturn(List.of());

        ScanExecutionService service = new ScanExecutionService(
                jobs, findings, true, null, null, null, 10, 9, 5,
                null, null, zap, new ZapScanAdapter());
        permitTestTarget(service, job);
        service.runClaimed(26L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus(), job.getStatusMessage());
        ArgumentCaptor<ScanFinding> captor = ArgumentCaptor.forClass(ScanFinding.class);
        verify(findings, atLeastOnce()).save(captor.capture());
        ScanFinding sqlFinding = captor.getAllValues().stream()
                .filter(finding -> "SQL_INJECTION_SUSPECTED".equals(finding.getCheckType()))
                .findFirst().orElseThrow();
        assertEquals("HIGH", sqlFinding.getSeverity());
        assertEquals("SUSPECTED", sqlFinding.getVerificationStatus());
        assertEquals("ACTIVE_QUERY_PARAMETER", sqlFinding.getDetectionSource());
        assertTrue(sqlFinding.getAffectedComponent().contains("[id]"));
        assertTrue(sqlFinding.getEvidence().contains("database error signature"));
        ScanFinding xssFinding = captor.getAllValues().stream()
                .filter(finding -> "REFLECTED_XSS_POTENTIAL".equals(finding.getCheckType()))
                .findFirst().orElseThrow();
        assertEquals("MEDIUM", xssFinding.getSeverity());
        assertEquals("POTENTIAL", xssFinding.getVerificationStatus());
        assertEquals("ACTIVE_QUERY_PARAMETER", xssFinding.getDetectionSource());
        assertTrue(xssFinding.getAffectedComponent().contains("[id]"));
        assertTrue(xssFinding.getEvidence().contains("unique test marker"));
        assertEquals(10, requests.get());
        assertEquals(10, rawQueries.size());
        String untouchedQuery = "&keep=a%20b&id=2&tail=x%2By&literal=a+b"
                + "&encoded=a%2Bb&space=a%20b&&flag&flag=";
        assertEquals("id=1" + untouchedQuery, rawQueries.get(0));
        assertTrue(rawQueries.subList(1, 4).stream()
                .allMatch(query -> query.startsWith("id=")
                        && query.endsWith(untouchedQuery)));
        assertTrue(rawQueries.subList(4, 7).stream()
                .allMatch(query -> query.startsWith("id=1&keep=")
                        && query.endsWith("&id=2&tail=x%2By&literal=a+b"
                                + "&encoded=a%2Bb&space=a%20b&&flag&flag=")));
        assertTrue(rawQueries.subList(7, 10).stream()
                .allMatch(query -> query.startsWith("id=1&keep=a%20b&id=")
                        && query.endsWith("&tail=x%2By&literal=a+b"
                                + "&encoded=a%2Bb&space=a%20b&&flag&flag=")));
    }

    @Test
    void activeModeProbesOnlyExplicitlyAllowlistedSafePostForms() throws Exception {
        AtomicInteger getRequests = new AtomicInteger();
        AtomicInteger postRequests = new AtomicInteger();
        AtomicInteger externalRequests = new AtomicInteger();
        List<String> postedPaths = new CopyOnWriteArrayList<>();
        secondaryServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        secondaryServer.createContext("/", exchange -> {
            externalRequests.incrementAndGet();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        secondaryServer.start();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            getRequests.incrementAndGet();
            byte[] body = ("<html>"
                    + "<form method=\"POST\" action=\"/search\"><input type=\"search\" name=\"q\" value=\"start\"></form>"
                    + "<form method=\"POST\" action=\"/delete\"><input name=\"q\" value=\"ignored\"></form>"
                    + "<form method=\"POST\" action=\"/secret\"><input type=\"hidden\" name=\"csrf\" value=\"secret\">"
                    + "<input name=\"q\" value=\"ignored\"></form>"
                    + "<form method=\"POST\" action=\"/password\"><input type=\"password\" name=\"password\"></form>"
                    + "<form method=\"POST\" action=\"/empty\"></form>"
                    + "<form method=\"POST\" action=\"/unlisted\"><input name=\"q\" value=\"ignored\"></form>"
                    + "<form method=\"POST\" action=\"/logout\"><input name=\"q\" value=\"ignored\"></form>"
                    + "<form method=\"POST\" action=\"/verify\"><input name=\"user\" value=\"analyst\">"
                    + "<input name=\"pin\" value=\"1234\"></form>"
                    + "<form method=\"POST\" action=\"/safe-search\"><input name=\"q\" value=\"term\"></form>"
                    + "<form method=\"POST\" action=\"/redirect\"><input name=\"q\" value=\"ignored\"></form>"
                    + "<form method=\"POST\" action=\"http://127.0.0.1:"
                    + secondaryServer.getAddress().getPort()
                    + "/outside\"><input name=\"q\" value=\"ignored\"></form>"
                    + "</html>").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/search", exchange -> {
            postRequests.incrementAndGet();
            postedPaths.add(exchange.getRequestURI().getPath());
            String decoded = URLDecoder.decode(
                    new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8),
                    StandardCharsets.UTF_8);
            String body;
            int status = 200;
            if (decoded.contains("' OR '1'='1") || decoded.contains("' OR '1'='2")) {
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
        server.createContext("/delete", exchange -> {
            postRequests.incrementAndGet();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.createContext("/secret", exchange -> {
            postRequests.incrementAndGet();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.createContext("/password", exchange -> {
            postRequests.incrementAndGet();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.createContext("/empty", exchange -> {
            postRequests.incrementAndGet();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.createContext("/unlisted", exchange -> {
            postRequests.incrementAndGet();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.createContext("/logout", exchange -> {
            postRequests.incrementAndGet();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.createContext("/verify", exchange -> {
            postRequests.incrementAndGet();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.createContext("/safe-search", exchange -> {
            postRequests.incrementAndGet();
            postedPaths.add(exchange.getRequestURI().getPath());
            exchange.getRequestBody().readAllBytes();
            byte[] body = "<html>safe result</html>".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/redirect", exchange -> {
            postRequests.incrementAndGet();
            postedPaths.add(exchange.getRequestURI().getPath());
            exchange.getResponseHeaders().add("Location",
                    "http://127.0.0.1:" + secondaryServer.getAddress().getPort() + "/redirected");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.start();

        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        Organization organization = approvedOrganization(42L);
        Target target = approvedTarget(organization,
                "http://127.0.0.1:" + server.getAddress().getPort() + "/");
        ScanJob job = approvedJob(organization, target);
        ReflectionTestUtils.setField(job, "scanType", ScanType.ZAP_ACTIVE);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        ScanExecutionService service = new ScanExecutionService(
                jobs, findings, true, null, null, null, 10, 16, 5,
                null, null, null, null);
        permitTestTarget(service, job);
        ReflectionTestUtils.setField(service, "activePostFormAllowlist",
                "http://127.0.0.1:" + server.getAddress().getPort() + "/search\n"
                        + "http://127.0.0.1:" + server.getAddress().getPort() + "/delete\n"
                        + "http://127.0.0.1:" + server.getAddress().getPort() + "/secret\n"
                        + "http://127.0.0.1:" + server.getAddress().getPort() + "/password\n"
                        + "http://127.0.0.1:" + server.getAddress().getPort() + "/empty\n"
                        + "http://127.0.0.1:" + server.getAddress().getPort() + "/logout\n"
                        + "http://127.0.0.1:" + server.getAddress().getPort() + "/verify\n"
                        + "http://127.0.0.1:" + server.getAddress().getPort() + "/safe-search\n"
                        + "http://127.0.0.1:" + server.getAddress().getPort() + "/redirect\n"
                        + "http://127.0.0.1:" + secondaryServer.getAddress().getPort() + "/outside");
        service.runClaimed(42L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus(), job.getStatusMessage());
        assertEquals(1, getRequests.get());
        assertEquals(12, postRequests.get());
        assertEquals(0, externalRequests.get());
        assertEquals(4, postedPaths.stream().filter("/search"::equals).count());
        assertEquals(4, postedPaths.stream().filter("/safe-search"::equals).count());
        assertEquals(4, postedPaths.stream().filter("/redirect"::equals).count());
        ArgumentCaptor<ScanFinding> captor = ArgumentCaptor.forClass(ScanFinding.class);
        verify(findings, atLeastOnce()).save(captor.capture());
        assertFalse(captor.getAllValues().stream().anyMatch(finding ->
                finding.getAffectedComponent().contains("/safe-search")
                        && ("SQL_INJECTION_SUSPECTED".equals(finding.getCheckType())
                        || "REFLECTED_XSS_POTENTIAL".equals(finding.getCheckType()))));
        assertTrue(captor.getAllValues().stream().anyMatch(finding ->
                "SQL_INJECTION_SUSPECTED".equals(finding.getCheckType())
                        && "ACTIVE_POST_FORM".equals(finding.getDetectionSource())
                        && finding.getAffectedComponent().contains("/search [q]")));
        assertTrue(captor.getAllValues().stream().anyMatch(finding ->
                "REFLECTED_XSS_POTENTIAL".equals(finding.getCheckType())
                        && "ACTIVE_POST_FORM".equals(finding.getDetectionSource())
                        && finding.getAffectedComponent().contains("/search [q]")));
        assertTrue(captor.getAllValues().stream().anyMatch(finding ->
                "MISSING_CONTENT_SECURITY_POLICY".equals(finding.getCheckType())
                        && finding.getAffectedComponent().contains("/search [Content-Security-Policy]")));
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

        ScanExecutionService service = new ScanExecutionService(jobs, findings, true, null);
        permitTestTarget(service, job);
        service.runClaimed(6L);

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

        ScanExecutionService service = new ScanExecutionService(jobs, findings, true, null);
        permitTestTarget(service, job);
        service.runClaimed(7L);

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
        permitTestTarget(service, job);
        service.runClaimed(99L);

        assertEquals(ScanStatus.COMPLETED, job.getStatus());
        assertEquals(100, job.getProgress());
        verify(crawlPages, times(1)).save(any(ScanCrawlPage.class));
    }

    @Test
    void repeatedCookieObservationsRemainDistinctByPageAndAttributeType() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            exchange.getResponseHeaders().add("Set-Cookie", "owasp-locale=en; Path=/");
            exchange.getResponseHeaders().add("Set-Cookie", "owasp-locale=en; Path=/");
            byte[] body = "<a href=\"/child\">child</a>".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/child", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            exchange.getResponseHeaders().add("Set-Cookie", "owasp-locale=en; Path=/");
            byte[] body = "<html><body>child</body></html>".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        Organization organization = approvedOrganization(101L);
        Target target = approvedTarget(organization, "http://127.0.0.1:" + server.getAddress().getPort() + "/");
        ScanJob job = approvedJob(organization, target);
        ScanJobRepository jobs = mock(ScanJobRepository.class);
        ScanFindingRepository findings = mock(ScanFindingRepository.class);
        when(jobs.findByIdForExecutionUpdate(anyLong())).thenReturn(Optional.of(job));

        ScanExecutionService service = new ScanExecutionService(jobs, findings, true, null);
        permitTestTarget(service, job);
        service.runClaimed(102L);

        ArgumentCaptor<ScanFinding> captor = ArgumentCaptor.forClass(ScanFinding.class);
        verify(findings, atLeastOnce()).save(captor.capture());
        List<ScanFinding> cookieFindings = captor.getAllValues().stream()
                .filter(finding -> finding.getCheckType().startsWith("COOKIE_MISSING_"))
                .toList();

        assertEquals(4, cookieFindings.size());
        assertEquals(2, cookieFindings.stream()
                .filter(finding -> "COOKIE_MISSING_HTTP_ONLY".equals(finding.getCheckType())).count());
        assertEquals(2, cookieFindings.stream()
                .filter(finding -> "COOKIE_MISSING_SAMESITE".equals(finding.getCheckType())).count());
        assertTrue(cookieFindings.stream().allMatch(finding -> "LOW".equals(finding.getSeverity())
                && "OBSERVED".equals(finding.getVerificationStatus())
                && finding.getRationale().contains("exploitability was not verified")
                && !finding.getEvidence().contains("owasp-locale=en")));
        assertEquals(2, cookieFindings.stream().map(ScanFinding::getAffectedComponent).distinct().count());
        assertFalse(cookieFindings.stream()
                .anyMatch(finding -> "COOKIE_MISSING_SECURE".equals(finding.getCheckType())),
                "Secure absence is not reported for an HTTP response.");
        assertEquals(2, job.getDiscoveredPageCount());
        assertEquals(2, job.getVisitedPageCount());
        assertEquals(2, job.getTestedPassivePageCount());
        assertEquals("COMPLETED", job.getNativeEngineStatus());
        assertEquals("NOT_CONFIGURED", job.getZapEngineStatus());
    }

    @Test
    void passiveHeaderScopeIncludesZapPassiveStagesButExcludesActiveChecks() {
        Organization organization = approvedOrganization(103L);
        ScanJob job = approvedJob(organization, approvedTarget(organization, "https://example.test/"));

        ScanExecutionSummary summary = ScanExecutionSummary.from(job);

        assertTrue(summary.zapRequested());
        assertEquals("NOT_STARTED", summary.zapEngineStatus());
        assertEquals(NvdLookupStatus.NOT_REQUESTED, summary.nvdLookupStatus());
        assertTrue(summary.checksInScope().contains("Set-Cookie attribute observations (Secure assessed only for HTTPS responses)"));
        assertTrue(summary.checksOutOfScope().contains("SQL injection and reflected XSS active probes"));
        assertTrue(summary.checksInScope().contains("OWASP ZAP spider and passive analysis"));
        assertFalse(summary.checksOutOfScope().contains("OWASP ZAP spider or passive analysis"));
        assertTrue(summary.checksOutOfScope().contains("Authorization and access-control testing"));
    }

    @Test
    void scanRecoveryRunnerMarksInterruptedScansAsFailed() {
        ScanJobRepository jobs = mock(ScanJobRepository.class);
        Organization organization = approvedOrganization(100L);
        Target target = approvedTarget(organization, "http://127.0.0.1:8080/");
        ScanJob crawlingJob = approvedJob(organization, target);
        crawlingJob.transitionTo(ScanStatus.CRAWLING, 10, "Discovering", null);
        crawlingJob.updateZapEngineStatus("RUNNING");
        crawlingJob.updateZapSpiderStatus("RUNNING");

        when(jobs.findByStatusIn(anyCollection())).thenReturn(java.util.List.of(crawlingJob));

        ScanRecoveryRunner runner = new ScanRecoveryRunner(jobs);
        runner.run(null);

        assertEquals(ScanStatus.FAILED, crawlingJob.getStatus());
        assertEquals("EXECUTOR_UNAVAILABLE", crawlingJob.getFailureReason());
        assertEquals("FAILED", crawlingJob.getZapEngineStatus());
        assertEquals("SERVER_RESTARTED_DURING_ZAP", crawlingJob.getZapFailureReason());
        assertEquals("FAILED", crawlingJob.getZapSpiderStatus());
        assertTrue(crawlingJob.getStatusMessage().contains("restart"));
        verify(jobs).save(crawlingJob);
    }

    @Test
    void cancellationBeforeFirstCrawlRequestEndsAsCancelledNotFailed() throws Exception {
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
        Organization organization = approvedOrganization(104L);
        ScanJob job = approvedJob(organization,
                approvedTarget(organization,
                        "http://127.0.0.1:" + server.getAddress().getPort() + "/"));
        setId(job, 104L);
        when(jobs.findByIdForExecutionUpdate(104L)).thenReturn(Optional.of(job));
        when(jobs.findCancellationRequestedById(104L)).thenReturn(Optional.of(true));

        ScanExecutionService service = new ScanExecutionService(jobs, findings, false, null);
        permitTestTarget(service, job);
        service.runClaimed(104L);

        assertEquals(ScanStatus.CANCELLED, job.getStatus());
        assertEquals("Scan cancelled during execution", job.getStatusMessage());
        assertEquals("CANCELLED", job.getNativeEngineStatus());
        assertEquals(0, requests.get());
        verify(findings, never()).save(any());
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

        ScanExecutionService service = new ScanExecutionService(jobs, findings, true, null);
        permitTestTarget(service, job);
        service.runClaimed(30L);

        verify(findings, never()).save(argThat(finding -> "REFLECTED_XSS_POTENTIAL".equals(finding.getCheckType())));
        assertEquals(ScanStatus.COMPLETED, job.getStatus());
    }

    @Test
    void matchesNvdCveWhenSoftwareVersionIsDisclosed() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "text/plain");
            exchange.getResponseHeaders().add("Server", "Apache/2.4.49");
            exchange.getResponseHeaders().add("X-Powered-By", "PHP/8.1.2");
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
        when(nvdService.parseSoftwareVersion("PHP/8.1.2"))
                .thenReturn(new NvdCveService.SoftwareVersion("PHP", "8.1.2"));
        when(nvdService.lookupCves("Apache", "2.4.49")).thenReturn(new NvdLookupResult(
                NvdLookupStatus.CANDIDATES_FOUND, java.util.List.of(
                new CveMatch("CVE-2021-41773", "Apache", "2.4.49", 7.5, "HIGH",
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Path traversal flaw in Apache HTTP Server 2.4.49"),
                new CveMatch("CVE-2024-1234", "Apache", "2.4.49", 0.0, "UNKNOWN",
                        "N/A", "CVSS data unavailable")
        )));
        when(nvdService.lookupCves("PHP", "8.1.2"))
                .thenReturn(new NvdLookupResult(NvdLookupStatus.TIMEOUT, java.util.List.of()));

        ScanExecutionService service = new ScanExecutionService(jobs, findings, true, null,
                null, null, 10, 6, 15, null, nvdService);
        permitTestTarget(service, job);
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
        ScanFinding missingCvssFinding = captor.getAllValues().stream()
                .filter(f -> "CVE_KEYWORD_CANDIDATE".equals(f.getCheckType()))
                .filter(f -> f.getEvidence().contains("CVE-2024-1234"))
                .findFirst().orElseThrow();
        assertTrue(missingCvssFinding.getEvidence().contains("NVD CVSS metrics unavailable"));
        assertFalse(missingCvssFinding.getEvidence().contains("NVD CVSS: 0.0"));
        assertEquals(NvdLookupStatus.PARTIAL_RESULTS, job.getNvdLookupStatus());
        assertEquals(NvdLookupStatus.PARTIAL_RESULTS, ScanExecutionSummary.from(job).nvdLookupStatus());
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
