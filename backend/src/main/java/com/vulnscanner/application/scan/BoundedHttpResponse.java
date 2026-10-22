package com.vulnscanner.application.scan;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

final class BoundedHttpResponse {
    private BoundedHttpResponse() {
    }

    static HttpResponse<byte[]> send(HttpClient client, HttpRequest request, int maxBytes, Duration timeout)
            throws IOException, InterruptedException {
        var response = client.sendAsync(request, ignored -> new Subscriber(maxBytes));
        try {
            return response.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException exception) {
            response.cancel(true);
            throw new HttpTimeoutException("HTTP response exceeded its read deadline");
        } catch (ExecutionException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof IOException ioException) {
                throw ioException;
            }
            throw new IOException("HTTP response body could not be read", cause);
        }
    }

    static final class ResponseTooLargeException extends IOException {
        private ResponseTooLargeException() {
            super("HTTP response exceeded its size limit");
        }
    }

    private static final class Subscriber implements HttpResponse.BodySubscriber<byte[]> {
        private final int maxBytes;
        private final ByteArrayOutputStream bodyBytes = new ByteArrayOutputStream();
        private final CompletableFuture<byte[]> body = new CompletableFuture<>();
        private Flow.Subscription subscription;
        private int received;

        private Subscriber(int maxBytes) {
            this.maxBytes = maxBytes;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return body;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(1);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                int size = buffer.remaining();
                if (received + size > maxBytes) {
                    subscription.cancel();
                    body.completeExceptionally(new ResponseTooLargeException());
                    return;
                }
                byte[] chunk = new byte[size];
                buffer.get(chunk);
                bodyBytes.write(chunk, 0, chunk.length);
                received += size;
            }
            subscription.request(1);
        }

        @Override
        public void onError(Throwable error) {
            body.completeExceptionally(error);
        }

        @Override
        public void onComplete() {
            body.complete(bodyBytes.toByteArray());
        }
    }
}
