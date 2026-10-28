package com.vulnscanner.application.scan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class ZapClientServiceTest {
    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void missingSpiderScanIdIsAnError() throws Exception {
        server = startServer("/JSON/spider/action/scan/", "{\"scan\":\"\"}");
        ZapClientService client = client();

        assertThrows(IOException.class, () -> client.startSpider("http://127.0.0.1/"));
    }

    @Test
    void missingProgressStatusIsAnError() throws Exception {
        server = startServer("/JSON/spider/view/status/", "{}");
        ZapClientService client = client();

        assertThrows(IOException.class, () -> client.getSpiderProgress("1"));
    }

    @Test
    void spiderDiscoveredCountUsesValidatedResultsArray() throws Exception {
        server = startServer("/JSON/spider/view/results/", "{\"results\":[\"http://example.test/\",\"http://example.test/a\"]}");
        ZapClientService client = client();

        assertEquals(2, client.getSpiderDiscoveredCount("1"));
    }

    @Test
    void invalidSpiderResultsResponseIsRejected() throws Exception {
        server = startServer("/JSON/spider/view/results/", "{\"results\":\"not-an-array\"}");
        ZapClientService client = client();

        assertThrows(IOException.class, () -> client.getSpiderDiscoveredCount("1"));
    }

    @Test
    void activeScanRequiresAnExplicitScopeContext() throws Exception {
        server = startServer("/JSON/ascan/action/scan/", "{\"scan\":\"1\"}");
        ZapClientService client = client();

        assertThrows(IOException.class, () -> client.startActiveScan("http://127.0.0.1/"));
    }

    @Test
    void passiveScanQueueCountCanBeRead() throws Exception {
        server = startServer("/JSON/pscan/view/recordsToScan/", "{\"recordsToScan\":\"0\"}");
        ZapClientService client = client();

        assertEquals(0, client.getPassiveScanRecordsToScan());
    }

    @Test
    void invalidPassiveScanQueueCountIsAnError() throws Exception {
        server = startServer("/JSON/pscan/view/recordsToScan/", "{\"recordsToScan\":\"pending\"}");
        ZapClientService client = client();

        assertThrows(IOException.class, client::getPassiveScanRecordsToScan);
    }

    @Test
    void readinessRequiresValidVersionResponseAndSendsApiKeyHeader() throws Exception {
        AtomicReference<String> receivedApiKey = new AtomicReference<>();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/JSON/core/view/version/", exchange -> {
            receivedApiKey.set(exchange.getRequestHeaders().getFirst("X-ZAP-API-Key"));
            byte[] body = "{\"version\":\"2.16.1\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        server.start();
        ZapClientService client = new ZapClientService("http://127.0.0.1:" + server.getAddress().getPort(),
                "test-api-key", true, 1, 1, new ObjectMapper());

        assertTrue(client.isAvailable());
        assertEquals("test-api-key", receivedApiKey.get());
    }

    @Test
    void readinessRejectsUnauthorizedOrMalformedVersionResponses() throws Exception {
        server = startServer("/JSON/core/view/version/", "{\"message\":\"unauthorized\"}");
        server.removeContext("/JSON/core/view/version/");
        server.createContext("/JSON/core/view/version/", exchange -> {
            exchange.sendResponseHeaders(401, -1);
            exchange.close();
        });
        ZapClientService unauthorizedClient = client();
        assertFalse(unauthorizedClient.isAvailable());

        server.stop(0);
        server = startServer("/JSON/core/view/version/", "{\"unexpected\":\"response\"}");
        assertFalse(client().isAvailable());
    }

    private ZapClientService client() {
        return new ZapClientService("http://127.0.0.1:" + server.getAddress().getPort(),
                "", true, 1, 1, new ObjectMapper());
    }

    private HttpServer startServer(String path, String responseBody) throws IOException {
        HttpServer testServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        testServer.createContext(path, exchange -> {
            byte[] body = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        testServer.start();
        return testServer;
    }
}
