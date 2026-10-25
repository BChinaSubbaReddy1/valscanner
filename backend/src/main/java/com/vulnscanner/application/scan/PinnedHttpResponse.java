package com.vulnscanner.application.scan;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class PinnedHttpResponse {
    private static final int MAX_HEADER_BYTES = 65_536;
    private static final int MAX_HEADER_COUNT = 200;
    private static final int MAX_STATUS_LINE_BYTES = 8_192;
    private static final int MAX_INFORMATIONAL_RESPONSES = 5;

    private PinnedHttpResponse() {
    }

    static Response send(URI uri, InetAddress[] addresses, Duration timeout, int maxBodyBytes,
                         String userAgent) throws IOException {
        validateRequestUri(uri);
        if (addresses == null || addresses.length == 0) {
            throw new IOException("No validated destination address is available");
        }
        long deadline = System.nanoTime() + timeout.toNanos();
        IOException lastFailure = null;
        for (InetAddress address : addresses) {
            try {
                return sendToAddress(uri, address, deadline, maxBodyBytes, userAgent);
            } catch (ResponseTooLargeException exception) {
                throw exception;
            } catch (IOException exception) {
                if (System.nanoTime() >= deadline) {
                    throw exception;
                }
                lastFailure = exception;
            }
        }
        if (lastFailure != null) {
            throw lastFailure;
        }
        throw new IOException("No validated destination address is available");
    }

    private static Response sendToAddress(URI uri, InetAddress address, long deadline, int maxBodyBytes,
                                         String userAgent) throws IOException {
        int port = uri.getPort() == -1 ? ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80) : uri.getPort();
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(address, port), remainingMillis(deadline));
            socket.setSoTimeout(remainingMillis(deadline));
            if ("https".equalsIgnoreCase(uri.getScheme())) {
                socket = wrapTls(socket, uri.getHost(), port, deadline);
            }
            socket.setSoTimeout(remainingMillis(deadline));
            OutputStream output = socket.getOutputStream();
            output.write(requestBytes(uri, port, userAgent));
            output.flush();
            InputStream input = socket.getInputStream();
            return readResponse(socket, input, deadline, maxBodyBytes);
        } finally {
            socket.close();
        }
    }

    private static Socket wrapTls(Socket socket, String host, int port, long deadline) throws IOException {
        SSLSocketFactory factory;
        try {
            factory = SSLContext.getDefault().getSocketFactory();
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IOException("Default TLS context is unavailable", exception);
        }
        SSLSocket tls = (SSLSocket) factory.createSocket(socket, stripBrackets(host), port, true);
        try {
            var parameters = tls.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            if (!isIpLiteral(host)) {
                parameters.setServerNames(List.of(new SNIHostName(stripBrackets(host))));
            }
            tls.setSSLParameters(parameters);
            tls.setSoTimeout(remainingMillis(deadline));
            tls.startHandshake();
            return tls;
        } catch (IllegalArgumentException exception) {
            try {
                tls.close();
            } catch (IOException closeException) {
                exception.addSuppressed(closeException);
            }
            throw new IOException("Target hostname is invalid for TLS", exception);
        } catch (IOException exception) {
            try {
                tls.close();
            } catch (IOException closeException) {
                exception.addSuppressed(closeException);
            }
            throw exception;
        }
    }

    private static byte[] requestBytes(URI uri, int port, String userAgent) {
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        if (uri.getRawQuery() != null) {
            path += "?" + uri.getRawQuery();
        }
        String host = uri.getHost();
        String authorityHost = host.contains(":") ? "[" + stripBrackets(host) + "]" : host;
        int defaultPort = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
        String authority = port == defaultPort ? authorityHost : authorityHost + ":" + port;
        String request = "GET " + path + " HTTP/1.1\r\n"
                + "Host: " + authority + "\r\n"
                + "User-Agent: " + userAgent + "\r\n"
                + "Accept-Encoding: identity\r\n"
                + "Connection: close\r\n\r\n";
        return request.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static Response readResponse(Socket socket, InputStream rawInput, long deadline, int maxBodyBytes)
            throws IOException {
        DeadlineInput input = new DeadlineInput(socket, rawInput, deadline);
        int totalHeaderBytes = 0;
        int totalHeaderCount = 0;
        for (int informationalResponses = 0; ; informationalResponses++) {
            String statusLine = readLine(input, Math.min(MAX_STATUS_LINE_BYTES,
                    MAX_HEADER_BYTES - totalHeaderBytes));
            totalHeaderBytes += statusLine.length() + 2;
            int status = parseStatus(statusLine);
            HeaderBlock block = readHeaders(input, MAX_HEADER_BYTES - totalHeaderBytes,
                    MAX_HEADER_COUNT - totalHeaderCount);
            totalHeaderBytes += block.bytes();
            totalHeaderCount += block.count();
            Map<String, List<String>> headers = block.headers();
            validateFraming(headers, statusLine.startsWith("HTTP/1.1"));
            if (status == 101) {
                throw new IOException("Target returned an unsupported protocol switch response");
            }
            if (status >= 100 && status < 200) {
                if (informationalResponses >= MAX_INFORMATIONAL_RESPONSES) {
                    throw new IOException("Target returned too many informational responses");
                }
                if (headers.containsKey("content-length") || headers.containsKey("transfer-encoding")) {
                    throw new IOException("Informational response contained unsupported body framing");
                }
                continue;
            }
            byte[] body = readBody(input, headers, status, maxBodyBytes,
                    MAX_HEADER_BYTES - totalHeaderBytes, MAX_HEADER_COUNT - totalHeaderCount);
            return new Response(status, headers, body);
        }
    }

    private static int parseStatus(String line) throws IOException {
        if (!line.matches("HTTP/1\\.[01] [1-5][0-9]{2}(?: [\\x20-\\x7e\\t]*)?")) {
            throw new IOException("Target returned an invalid HTTP status line");
        }
        return Integer.parseInt(line.substring(9, 12));
    }

    private static HeaderBlock readHeaders(DeadlineInput input, int maxBytes, int maxCount) throws IOException {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        int bytes = 0;
        int count = 0;
        while (true) {
            String line = readLine(input, Math.min(MAX_HEADER_BYTES - bytes, maxBytes - bytes));
            bytes += line.length() + 2;
            if (bytes > MAX_HEADER_BYTES || bytes > maxBytes) {
                throw new IOException("Target response headers exceeded the permitted size");
            }
            if (line.isEmpty()) {
                return new HeaderBlock(headers, bytes, count);
            }
            if (++count > MAX_HEADER_COUNT || count > maxCount) {
                throw new IOException("Target returned too many HTTP headers");
            }
            int separator = line.indexOf(':');
            if (separator < 1 || !line.substring(0, separator).matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")) {
                throw new IOException("Target returned a malformed HTTP header");
            }
            String name = line.substring(0, separator).toLowerCase(Locale.ROOT);
            String value = trimOws(line.substring(separator + 1));
            if (value.chars().anyMatch(character ->
                    (character < 0x20 && character != '\t') || character == 0x7f)) {
                throw new IOException("Target returned a malformed HTTP header value");
            }
            headers.computeIfAbsent(name, ignored -> new ArrayList<>()).add(value);
        }
    }

    private static byte[] readBody(DeadlineInput input, Map<String, List<String>> headers, int status,
                                   int maxBodyBytes, int remainingHeaderBytes, int remainingHeaderCount)
            throws IOException {
        if (status == 204 || status == 304) {
            if (headers.containsKey("transfer-encoding")
                    || (status == 204 && headers.containsKey("content-length"))) {
                throw new IOException("Target returned framing headers for a bodyless response");
            }
            return new byte[0];
        }
        String transferEncoding = firstHeader(headers, "transfer-encoding");
        if (transferEncoding != null) {
            return readChunked(input, maxBodyBytes, remainingHeaderBytes, remainingHeaderCount);
        }
        String contentLength = firstHeader(headers, "content-length");
        if (contentLength != null) {
            long length;
            try {
                length = Long.parseLong(contentLength);
            } catch (NumberFormatException exception) {
                throw new IOException("Target returned an invalid Content-Length", exception);
            }
            if (length < 0 || length > maxBodyBytes) {
                throw new ResponseTooLargeException();
            }
            ByteArrayOutputStream body = new ByteArrayOutputStream((int) length);
            byte[] buffer = new byte[8192];
            long remaining = length;
            while (remaining > 0) {
                int count = input.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                if (count < 0) {
                    throw new IOException("Target response ended before Content-Length bytes were received");
                }
                body.write(buffer, 0, count);
                remaining -= count;
            }
            return body.toByteArray();
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int count;
        while ((count = input.read(buffer, 0, buffer.length)) != -1) {
            if (body.size() + count > maxBodyBytes) {
                throw new ResponseTooLargeException();
            }
            body.write(buffer, 0, count);
        }
        return body.toByteArray();
    }

    private static byte[] readChunked(DeadlineInput input, int maxBodyBytes,
                                      int remainingHeaderBytes, int remainingHeaderCount) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int trailerBytes = 0;
        int trailerCount = 0;
        while (true) {
            String sizeLine = readLine(input, MAX_STATUS_LINE_BYTES);
            if (!sizeLine.matches("[0-9A-Fa-f]{1,16}")) {
                throw new IOException("Target returned an invalid chunk size");
            }
            long chunkSize;
            try {
                chunkSize = Long.parseLong(sizeLine, 16);
            } catch (NumberFormatException exception) {
                throw new IOException("Target returned an invalid chunk size", exception);
            }
            if (chunkSize < 0 || chunkSize > maxBodyBytes - body.size()) {
                throw new ResponseTooLargeException();
            }
            if (chunkSize == 0) {
                String trailer;
                while (true) {
                    trailer = readLine(input, Math.min(MAX_HEADER_BYTES - trailerBytes,
                            remainingHeaderBytes - trailerBytes));
                    trailerBytes += trailer.length() + 2;
                    if (trailerBytes > MAX_HEADER_BYTES || trailerBytes > remainingHeaderBytes) {
                        throw new IOException("Target response trailers exceeded the permitted size");
                    }
                    if (trailer.isEmpty()) {
                        break;
                    }
                    if (++trailerCount > MAX_HEADER_COUNT || trailerCount > remainingHeaderCount) {
                        throw new IOException("Target response trailers exceeded the permitted count");
                    }
                    int separator = trailer.indexOf(':');
                    if (separator < 1
                            || !trailer.substring(0, separator).matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")) {
                        throw new IOException("Target returned a malformed HTTP trailer");
                    }
                    String name = trailer.substring(0, separator).toLowerCase(Locale.ROOT);
                    if (name.equals("content-length") || name.equals("transfer-encoding")
                            || name.equals("trailer") || name.equals("host")) {
                        throw new IOException("Target returned a prohibited framing trailer");
                    }
                    String value = trimOws(trailer.substring(separator + 1));
                    if (value.chars().anyMatch(character ->
                            (character < 0x20 && character != '\t') || character == 0x7f)) {
                        throw new IOException("Target returned a malformed HTTP trailer value");
                    }
                }
                return body.toByteArray();
            }
            byte[] buffer = new byte[8192];
            long remaining = chunkSize;
            while (remaining > 0) {
                int count = input.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                if (count < 0) {
                    throw new IOException("Target response ended during a chunk");
                }
                body.write(buffer, 0, count);
                remaining -= count;
            }
            if (input.read() != '\r' || input.read() != '\n') {
                throw new IOException("Target returned malformed chunk framing");
            }
        }
    }

    private static void validateFraming(Map<String, List<String>> headers, boolean http11) throws IOException {
        List<String> contentLengths = headers.get("content-length");
        List<String> transferEncodings = headers.get("transfer-encoding");
        if (contentLengths != null) {
            if (contentLengths.size() != 1 || !contentLengths.getFirst().matches("[0-9]{1,19}")) {
                throw new IOException("Target returned duplicate or invalid Content-Length headers");
            }
            try {
                long length = Long.parseLong(contentLengths.getFirst());
                if (length < 0) {
                    throw new NumberFormatException("negative length");
                }
            } catch (NumberFormatException exception) {
                throw new IOException("Target returned an invalid Content-Length", exception);
            }
        }
        if (transferEncodings != null) {
            if (transferEncodings.size() != 1
                    || !"chunked".equalsIgnoreCase(transferEncodings.getFirst()) || !http11) {
                throw new IOException("Target returned an unsupported Transfer-Encoding");
            }
            if (contentLengths != null) {
                throw new IOException("Target returned both Transfer-Encoding and Content-Length");
            }
        }
    }

    private static void validateRequestUri(URI uri) throws IOException {
        if (uri == null || !uri.isAbsolute() || uri.isOpaque() || uri.getRawAuthority() == null
                || uri.getHost() == null || uri.getHost().isBlank() || uri.getRawUserInfo() != null
                || (uri.getPort() != -1 && (uri.getPort() < 1 || uri.getPort() > 65535))
                || (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme()))
                || !hasValidRawAuthority(uri)) {
            throw new IOException("Target URL is not a valid HTTP(S) authority");
        }
    }

    private static boolean hasValidRawAuthority(URI uri) {
        String host = stripBrackets(uri.getHost());
        String authorityHost = host.contains(":") ? "[" + host + "]" : host;
        String expected = uri.getPort() == -1 ? authorityHost : authorityHost + ":" + uri.getPort();
        return expected.equalsIgnoreCase(uri.getRawAuthority());
    }

    private static String readLine(DeadlineInput input, int maxBytes) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        boolean carriageReturn = false;
        while (line.size() <= maxBytes) {
            int value = input.read();
            if (value == -1) {
                throw new IOException("Target response ended while reading a line");
            }
            if (carriageReturn) {
                if (value != '\n') {
                    throw new IOException("Target returned malformed HTTP line endings");
                }
                return line.toString(StandardCharsets.ISO_8859_1);
            }
            if (value == '\r') {
                carriageReturn = true;
            } else {
                line.write(value);
            }
        }
        throw new IOException("Target returned an oversized HTTP line");
    }

    private static String firstHeader(Map<String, List<String>> headers, String name) {
        List<String> values = headers.get(name);
        return values == null || values.isEmpty() ? null : values.getFirst();
    }

    private static String trimOws(String value) {
        int start = 0;
        int end = value.length();
        while (start < end && (value.charAt(start) == ' ' || value.charAt(start) == '\t')) {
            start++;
        }
        while (end > start && (value.charAt(end - 1) == ' ' || value.charAt(end - 1) == '\t')) {
            end--;
        }
        return value.substring(start, end);
    }

    private static String stripBrackets(String host) {
        return host.startsWith("[") && host.endsWith("]")
                ? host.substring(1, host.length() - 1) : host;
    }

    private static boolean isIpLiteral(String host) {
        String value = stripBrackets(host);
        return value.contains(":") || value.matches("[0-9.]+");
    }

    private static int remainingMillis(long deadline) throws SocketTimeoutException {
        long nanos = deadline - System.nanoTime();
        if (nanos <= 0) {
            throw new SocketTimeoutException("HTTP request exceeded its deadline");
        }
        return (int) Math.max(1, Math.min(Integer.MAX_VALUE, (nanos + 999_999) / 1_000_000));
    }

    record Response(int statusCode, Map<String, List<String>> headers, byte[] body) {
    }

    private record HeaderBlock(Map<String, List<String>> headers, int bytes, int count) {
    }

    static final class ResponseTooLargeException extends IOException {
        ResponseTooLargeException() {
            super("HTTP response exceeded its size limit");
        }
    }

    private static final class DeadlineInput extends InputStream {
        private final Socket socket;
        private final InputStream delegate;
        private final long deadline;

        private DeadlineInput(Socket socket, InputStream delegate, long deadline) {
            this.socket = socket;
            this.delegate = delegate;
            this.deadline = deadline;
        }

        @Override
        public int read() throws IOException {
            socket.setSoTimeout(remainingMillis(deadline));
            return delegate.read();
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            socket.setSoTimeout(remainingMillis(deadline));
            return delegate.read(bytes, offset, length);
        }
    }
}
