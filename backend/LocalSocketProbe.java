import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class LocalSocketProbe {
    public static void main(String[] args) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", 5173), 5000);
            socket.setSoTimeout(5000);

            System.out.println("TCP connected: " + socket.isConnected());

            OutputStream out = socket.getOutputStream();
            out.write((
                "GET / HTTP/1.1\r\n" +
                "Host: 127.0.0.1:5173\r\n" +
                "User-Agent: JavaSocketProbe/1.0\r\n" +
                "Connection: close\r\n\r\n"
            ).getBytes(StandardCharsets.US_ASCII));
            out.flush();

            BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream(),
                                      StandardCharsets.UTF_8));

            System.out.println("HTTP response: " + in.readLine());
        }
    }
}
