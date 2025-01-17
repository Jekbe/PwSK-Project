package api;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class API {
    private static final int GATEWAY_PORT = 8000;
    private static final ExecutorService executorService = Executors.newCachedThreadPool();
    private static final Map<String, ServiceForwarder> serviceMap = new HashMap<>();

    public static void main(String[] args) {
        registerService("registration_request", new ServiceForwarder("localhost", 8001));
        registerService("login_request", new ServiceForwarder("localhost", 8002));
        registerService("send_post_request", new ServiceForwarder("localhost", 8003));
        registerService("retrieve_last_10_posts_request", new ServiceForwarder("localhost", 8004));
        registerService("list_files_request", new ServiceForwarder("localhost", 8005));
        registerService("download_file_request", new ServiceForwarder("localhost", 8005));
        registerService("send_file_request", new ServiceForwarder("localhost", 8005));

        try (ServerSocket serverSocket = new ServerSocket(GATEWAY_PORT)) {
            System.out.println("API Gateway is running on port " + GATEWAY_PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                executorService.submit(() -> handleClient(clientSocket));
            }
        } catch (IOException e) {
            System.out.println("Could not start API Gateway: " + e.getMessage());
        }
    }

    private static void handleClient(Socket clientSocket) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

            String encodedMessage = in.readLine();
            String response = route(encodedMessage);

            out.println(response);
            System.out.println("Response sent back to client: " + response);

        } catch (Exception e) {
            System.out.println("Error handling client request: " + e.getMessage());
        }
    }

    public static void registerService(String messageType, ServiceForwarder forwarder) {
        serviceMap.put(messageType, forwarder);
        System.out.println("Registered service for message type: " + messageType);
    }

    public static String route(String encodedMessage) throws IOException {
        String decodedMessage = new String(Base64.getDecoder().decode(encodedMessage));
        Map<String, String> requestMap = parseKeyValueFormat(decodedMessage);
        String messageType = requestMap.get("message_type");

        System.out.println("Decoded message: " + decodedMessage);
        System.out.println("Parsed message type: " + messageType);

        ServiceForwarder forwarder = serviceMap.get(messageType);
        if (forwarder != null) {
            System.out.println("Found operation for message type: " + messageType);
            return forwarder.forwardRequest(encodedMessage);
        } else {
            System.out.println("No operation found for message type: " + messageType);
            return "Invalid message type";
        }
    }

    private static Map<String, String> parseKeyValueFormat(String message) {
        Map<String, String> map;
        String[] pairs = message.split(";");
        map = Arrays.stream(pairs).filter(pair -> pair.contains(":")).map(pair -> pair.split(":", 2)).collect(Collectors.toMap(keyValue -> keyValue[0], keyValue -> keyValue[1], (a, b) -> b));
        return map;
    }
}
