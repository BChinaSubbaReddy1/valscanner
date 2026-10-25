package com.vulnscanner.application.scan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
