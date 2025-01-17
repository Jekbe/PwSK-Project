package login;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class Login {
    private static final int PORT = 8002;
    private static final ExecutorService executorService = Executors.newCachedThreadPool();
    private static final String DB_URL = "jdbc:mysql://localhost:3306/sieci";
    private static final String DB_USER = "user";
    private static final String DB_PASSWORD = "password";

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("LoginServer is running on port " + PORT);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                executorService.submit(() -> handleClient(clientSocket));
            }
        } catch (IOException e) {
            System.out.println("Could not start server: " + e.getMessage());
        }
    }

    private static void handleClient(Socket clientSocket) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

            System.out.println("Received a login request from " + clientSocket.getRemoteSocketAddress());

            String encodedMessage = in.readLine();
            String decodedMessage = new String(Base64.getDecoder().decode(encodedMessage));
            System.out.println("Decoded Message: " + decodedMessage);

            Map<String, String> requestMap = parseKeyValueFormat(decodedMessage);

            String messageType = requestMap.get("message_type");
            int messageId = Integer.parseInt(requestMap.getOrDefault("message_id", "0"));
            String username = requestMap.get("username");

            if (!"login_request".equals(messageType)) {
                String errorResponse = String.format("message_type:login_response;message_id:%d;error_message:%s;username:%s;status:%d;", messageId, "Invalid message type", username, 400);
                out.println(Base64.getEncoder().encodeToString(errorResponse.getBytes()));
                return;
            }

            String password = requestMap.get("password");
            LoginResponse response = loginUser(username, password);
            String responseMessage = response.status() == 200 ? String.format("message_type:login_response;message_id:%d;username:%s;status:%d;", messageId, username, response.status()) : String.format("message_type:login_response;message_id:%d;error_message:%s;username:%s;status:%d;", messageId, response.message(), username, response.status());
            System.out.println("Returning login response for user " + username + " with status: " + response.status());
            out.println(Base64.getEncoder().encodeToString(responseMessage.getBytes()));

        } catch (Exception e) {
            System.out.println("Error handling client request: " + e.getMessage());
        }
    }

    public static LoginResponse loginUser(String username, String password) {
        String query = "SELECT password FROM users WHERE username = ?";

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                String storedPassword = rs.getString("password");

                if (storedPassword.equals(password)) {
                    System.out.println("User " + username + " logged in successfully.");
                    return new LoginResponse(200, "Login successful");
                } else {
                    System.out.println("Invalid password for user " + username);
                    return new LoginResponse(401, "Invalid password");
                }
            } else {
                System.out.println("Username not found: " + username);
                return new LoginResponse(404, "Username not found");
            }
        } catch (SQLException e) {
            System.out.println("Database error during login: " + e.getMessage());
            return new LoginResponse(500, "Database error: " + e.getMessage());
        }
    }

    private static Map<String, String> parseKeyValueFormat(String message) {
        Map<String, String> map;
        String[] pairs = message.split(";");
        map = Arrays.stream(pairs).filter(pair -> pair.contains(":")).map(pair -> pair.split(":", 2)).collect(Collectors.toMap(keyValue -> keyValue[0], keyValue -> keyValue[1], (a, b) -> b));
        return map;
    }
}
