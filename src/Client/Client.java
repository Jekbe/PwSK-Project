package Client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

import java.util.Base64;

public class Client {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 8000;
    private static int messageId = 1;

    private static boolean isLoggedIn = false;
    private static String loggedUsername = "";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String currentMode = "[Main Menu] ";

        while (true) {
            // Display the command prompt based on current mode
            System.out.print("\n" + currentMode);
            String command = scanner.nextLine().trim().toLowerCase();

            // Determine if input is a number or command name

            // Handle command
            switch (command) {
                case "login" -> handleLogin(scanner, currentMode);
                case "register" -> handleRegistration(scanner, currentMode);
                case "send_post" -> handleSendPost(scanner, currentMode);
                case "get_10_last_posts" -> handleGetLastPosts(currentMode);
                case "exit" -> exitApplication();
                case "help" -> HelpBox();
                case "file_transfer_mode" -> enterFileTransferMode(scanner);
                case "logout" -> handleLogout(currentMode);
                default -> System.out.println("Invalid option. Please try again.");

            }
        }
    }

    private static void handleLogin(Scanner scanner, String currentMode) {
        if (isLoggedIn) {
            System.out.println("You're already logged in.");
            return;
        }
        String mode = currentMode + "[Login]";
        System.out.print(mode + " Enter username: ");
        String username = scanner.nextLine();
        System.out.print(mode + " Enter password: ");
        String password = scanner.nextLine();
        String request = encode(String.format("message_type:login_request;message_id:%d;username:%s;password:%s;", messageId, username, password));
        sendRequestAndHandleResponse(request);
        messageId++;
    }

    private static void sendRequestAndHandleResponse(String request) {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            // Send the request to the server
            out.println(request);

            // Handle the server's response
            String encodedResponse = in.readLine();
            ResponseHandler.handleResponse(encodedResponse);

        } catch (IOException e) {
            System.out.println("Failed to connect to the server: " + e.getMessage());
        }
    }

    private static String encode(String message) {
        return Base64.getEncoder().encodeToString(message.getBytes());
    }
}
