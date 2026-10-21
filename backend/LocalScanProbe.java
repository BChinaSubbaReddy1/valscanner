import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

public class LocalScanProbe {
    public static void main(String[] args) throws Exception {
        URI uri = URI.create("http://127.0.0.1:5173/");

        System.out.println("HTTP_PROXY = " + System.getenv("HTTP_PROXY"));
        System.out.println("http.proxyHost = " + System.getProperty("http.proxyHost"));

        HttpClient client = HttpClient.newBuilder()
                .proxy(new ProxySelector() {
                    @Override
                    public List<Proxy> select(URI uri) {
                        return List.of(Proxy.NO_PROXY);
                    }

                    @Override
                    public void connectFailed(
                            URI uri, java.net.SocketAddress address,
                            java.io.IOException error) {
                        System.out.println("Connection failed: " + error);
                    }
                })
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(15))
                .GET()
                .build();

        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());

        System.out.println("Status: " + response.statusCode());
        System.out.println("Body length: " + response.body().length());
    }
}


