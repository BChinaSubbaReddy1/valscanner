package com.vulnscanner.application.scan;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

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
