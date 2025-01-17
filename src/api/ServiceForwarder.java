package api;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ServiceForwarder {
    private final String host;
    private final int port;

    public ServiceForwarder(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public String forwardRequest(String encodedMessage) throws IOException {
        try (Socket socket = new Socket(host, port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            out.println(encodedMessage);

            StringBuilder response = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) {
                response.append(line).append("\n");
            }

            return response.toString();
        }
    }
}
