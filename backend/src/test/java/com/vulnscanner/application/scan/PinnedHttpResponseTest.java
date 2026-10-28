package com.vulnscanner.application.scan;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PinnedHttpResponseTest {
    private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

    @Test
    void readsValidChunkedBodyAndTrailers() throws Exception {
        PinnedHttpResponse.Response response = exchange(
                "HTTP/1.1 200 OK\r\n"
                        + "Transfer-Encoding: chunked\r\n"
                        + "\r\n"
                        + "4\r\nWiki\r\n"
                        + "5\r\npedia\r\n"
                        + "0\r\nX-Trace: completed\r\n\r\n",
                32);

        assertEquals(200, response.statusCode());
        assertArrayEquals("Wikipedia".getBytes(StandardCharsets.US_ASCII), response.body());
    }

    @Test
    void acceptsSupportedInformationalResponsesBeforeFinalResponse() throws Exception {
        PinnedHttpResponse.Response response = exchange(
                "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"
                        + "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                32);

        assertArrayEquals("ok".getBytes(StandardCharsets.US_ASCII), response.body());
    }

    @Test
    void rejectsMalformedStatusLine() {
        assertThrows(IOException.class, () -> exchange(
                "HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n", 32));
    }

    @Test
    void rejectsUnsupportedOrMalformedRequestAuthoritiesBeforeConnecting() {
        assertThrows(IOException.class, () -> send(URI.create("ftp://127.0.0.1/")));
        assertThrows(IOException.class, () -> send(URI.create("http://user@127.0.0.1/")));
        assertThrows(IOException.class, () -> send(URI.create("http://127.0.0.1:/")));
        assertThrows(IOException.class, () -> send(URI.create("http://127.0.0.1:70000/")));
    }

    @Test
    void sendsBoundedUrlEncodedPostBodyThroughPinnedTransport() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(LOOPBACK, 0), 0);
        AtomicReference<String> method = new AtomicReference<>();
        AtomicReference<String> contentType = new AtomicReference<>();
        AtomicReference<String> requestBody = new AtomicReference<>();
        server.createContext("/submit", exchange -> {
            method.set(exchange.getRequestMethod());
            contentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            requestBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            URI uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/submit");
            byte[] body = "q=search+term".getBytes(StandardCharsets.UTF_8);
            PinnedHttpResponse.Response response = PinnedHttpResponse.sendPost(uri,
                    new InetAddress[]{LOOPBACK}, Duration.ofSeconds(3), 32, "test", body);

            assertEquals(200, response.statusCode());
            assertEquals("POST", method.get());
            assertEquals("application/x-www-form-urlencoded", contentType.get());
            assertEquals("q=search+term", requestBody.get());
            assertThrows(IOException.class, () -> PinnedHttpResponse.sendPost(uri,
                    new InetAddress[]{LOOPBACK}, Duration.ofSeconds(3), 32, "test", new byte[8_193]));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void doesNotRetryPostWhenResponseIsLost() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 2, LOOPBACK)) {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            AtomicInteger accepted = new AtomicInteger();
            try {
                Future<?> requestReader = executor.submit(() -> {
                    try (Socket client = server.accept()) {
                        accepted.incrementAndGet();
                        client.setSoTimeout(3_000);
                        InputStream input = client.getInputStream();
                        int matched = 0;
                        while (matched < 4) {
                            int value = input.read();
                            if (value < 0) {
                                return;
                            }
                            matched = switch (matched) {
                                case 0 -> value == '\r' ? 1 : 0;
                                case 1 -> value == '\n' ? 2 : value == '\r' ? 1 : 0;
                                case 2 -> value == '\r' ? 3 : 0;
                                case 3 -> value == '\n' ? 4 : 0;
                                default -> matched;
                            };
                        }
                        input.readNBytes("q=test".length());
                    } catch (IOException exception) {
                        throw new RuntimeException(exception);
                    }
                });
                URI uri = URI.create("http://127.0.0.1:" + server.getLocalPort() + "/submit");
                assertThrows(IOException.class, () -> PinnedHttpResponse.sendPost(uri,
                        new InetAddress[]{LOOPBACK, LOOPBACK}, Duration.ofSeconds(3), 32,
                        "test", "q=test".getBytes(StandardCharsets.UTF_8)));
                requestReader.get();
                assertEquals(1, accepted.get());
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    void rejectsDuplicateAndConflictingContentLengths() {
        assertThrows(IOException.class, () -> exchange(
                "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na", 32));
        assertThrows(IOException.class, () -> exchange(
                "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\na", 32));
    }

    @Test
    void rejectsTransferEncodingCombinationsAndUnsupportedCodings() {
        assertThrows(IOException.class, () -> exchange(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n"
                        + "0\r\n\r\n", 32));
        assertThrows(IOException.class, () -> exchange(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n", 32));
        assertThrows(IOException.class, () -> exchange(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
                        + "0\r\n\r\n", 32));
        assertThrows(IOException.class, () -> exchange(
                "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 32));
    }

    @Test
    void rejectsTruncatedAndOversizedBodies() {
        assertThrows(IOException.class, () -> exchange(
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc", 32));
        assertThrows(PinnedHttpResponse.ResponseTooLargeException.class, () -> exchange(
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde", 4));
        assertThrows(PinnedHttpResponse.ResponseTooLargeException.class, () -> exchange(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabcde\r\n0\r\n\r\n", 4));
    }

    @Test
    void rejectsMalformedChunkFramingAndFramingTrailers() {
        assertThrows(IOException.class, () -> exchange(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                        + "1\r\naXX0\r\n\r\n", 32));
        assertThrows(IOException.class, () -> exchange(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n", 32));
        assertThrows(IOException.class, () -> exchange(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                        + "0\r\nContent-Length: 0\r\n\r\n", 32));
    }

    @Test
    void enforcesAggregateHeaderCountAndByteLimits() {
        StringBuilder manyHeaders = new StringBuilder("HTTP/1.1 200 OK\r\n");
        for (int index = 0; index < 201; index++) {
            manyHeaders.append("X-Test-").append(index).append(": value\r\n");
        }
        manyHeaders.append("\r\n");
        assertThrows(IOException.class, () -> exchange(manyHeaders.toString(), 32));

        StringBuilder largeHeaders = new StringBuilder("HTTP/1.1 200 OK\r\n");
        for (int index = 0; index < 70; index++) {
            largeHeaders.append("X-Test-").append(index).append(": ")
                    .append("a".repeat(1_000)).append("\r\n");
        }
        largeHeaders.append("\r\n");
        assertThrows(IOException.class, () -> exchange(largeHeaders.toString(), 32));
    }

    private PinnedHttpResponse.Response exchange(String response, int maxBodyBytes) throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, LOOPBACK)) {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> responseWriter = executor.submit(() -> writeResponse(server, response));
                URI uri = new URI("http", null, LOOPBACK.getHostAddress(), server.getLocalPort(), "/", null, null);
                PinnedHttpResponse.Response parsed = send(uri, maxBodyBytes);
                responseWriter.get();
                return parsed;
            } finally {
                executor.shutdownNow();
            }
        }
    }

    private PinnedHttpResponse.Response send(URI uri) throws IOException {
        return send(uri, 32);
    }

    private PinnedHttpResponse.Response send(URI uri, int maxBodyBytes) throws IOException {
        return PinnedHttpResponse.send(uri, new InetAddress[]{LOOPBACK},
                Duration.ofSeconds(3), maxBodyBytes, "test");
    }

    private void writeResponse(ServerSocket server, String response) {
        try (Socket client = server.accept();
             BufferedReader request = new BufferedReader(
                     new InputStreamReader(client.getInputStream(), StandardCharsets.ISO_8859_1))) {
            String line;
            while ((line = request.readLine()) != null && !line.isEmpty()) {
                // Consume the request headers before writing the test response.
            }
            client.getOutputStream().write(response.getBytes(StandardCharsets.ISO_8859_1));
            client.getOutputStream().flush();
        } catch (IOException exception) {
            throw new RuntimeException(exception);
        }
    }
}
