package register;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class Register {
    private static final int PORT = 8001;
    private static final ExecutorService executorService = Executors.newCachedThreadPool();
    private static final String DB_URL = "jdbc:mysql://localhost:3306/sieci";
    private static final String DB_USER = "user";
    private static final String DB_PASSWORD = "password";

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
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

            System.out.println("Received a request from " + clientSocket.getRemoteSocketAddress());

            String encodedMessage = in.readLine();
            String decodedMessage = new String(Base64.getDecoder().decode(encodedMessage));
            System.out.println("Decoded Message: " + decodedMessage);
            Map<String, String> requestMap = parseKeyValueFormat(decodedMessage);
            String messageType = requestMap.get("message_type");
            int messageId = Integer.parseInt(requestMap.getOrDefault("message_id", "0"));

            if (!"registration_request".equals(messageType)) {
                String errorResponse = String.format("message_type:registration_response;message_id:%d;error_message:%s;status:%d;", messageId, "Invalid message type", 400);
                out.println(Base64.getEncoder().encodeToString(errorResponse.getBytes()));
                return;
            }

            String username = requestMap.get("username");
            String password = requestMap.get("password");
            RegisterResponse response = registerUser(username, password);
            String responseMessage = response.status() == 200 ? String.format("message_type:login_response;message_id:%d;username:%s;status:%d;", messageId, username, response.status()) : String.format("message_type:login_response;message_id:%d;error_message:%s;username:%s;status:%d;", messageId, response.message(), username, response.status());
            System.out.println("Returning registration response for user " + username + " with status: " + response.status());
            out.println(Base64.getEncoder().encodeToString(responseMessage.getBytes()));
        } catch (Exception e) {
            System.out.println("Error handling client request: " + e.getMessage());
        }
    }

    public static RegisterResponse registerUser(String username, String password) {
        String validationError = validateUsernameAndPassword(username, password);
        if (validationError != null) {
            System.out.println("Registration failed for username " + username + ": " + validationError);
            return new RegisterResponse(422, validationError); // Validation error
        }

        String query = "INSERT INTO users (username, password) VALUES (?, ?)";

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement(query)) {

            stmt.setString(1, username);
            stmt.setString(2, password);
            stmt.executeUpdate();

            System.out.println("User registered successfully with username: " + username);
            return new RegisterResponse(200, "Registration successful");

        } catch (SQLException e) {
            if (e.getErrorCode() == 1062) {
                System.out.println("Username already exists: " + username);
                return new RegisterResponse(409, "Username already exists");
            }
            System.out.println("Database error while registering user " + username + ": " + e.getMessage());
            return new RegisterResponse(500, "Database error: " + e.getMessage());
        }
    }

    private static String validateUsernameAndPassword(String username, String password) {
        if (username == null || username.length() < 3 || username.length() > 20) return "Username must be between 3 and 20 characters long.";
        if (!username.matches("^[a-zA-Z0-9_]+$")) return "Username can only contain letters, numbers, and underscores.";

        if (password == null || password.length() < 8) return "Password must be at least 8 characters long.";
        if (!password.matches(".*[A-Z].*")) return "Password must contain at least one uppercase letter.";
        if (!password.matches(".*[a-z].*")) return "Password must contain at least one lowercase letter.";
        if (!password.matches(".*\\d.*")) return "Password must contain at least one digit.";
        if (!password.matches(".*[!@#$%^&*()].*")) return "Password must contain at least one special character (!@#$%^&*()).";

        return null;
    }

    private static Map<String, String> parseKeyValueFormat(String message) {
        Map<String, String> map;
        String[] pairs = message.split(";");
        map = Arrays.stream(pairs).filter(pair -> pair.contains(":")).map(pair -> pair.split(":", 2)).collect(Collectors.toMap(keyValue -> keyValue[0], keyValue -> keyValue[1], (a, b) -> b));
        return map;
    }
}
