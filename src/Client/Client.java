package Client;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.stream.Collectors;

public class Client {
    private static final String HOST = "localhost";
    private static final int PORT = 8000;
    private static int messageId = 1;
    private static boolean isLoggedIn = false;
    private static String username = "";
    private static PublicKey publicKey;
    private static PrivateKey privateKey;
    private static PublicKey sendPublicKey;

    public static void main(String[] args) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        Scanner scanner = new Scanner(System.in);
        String currentMode = "[Main Menu] ";

        boolean go = true;
        while (go) {
            System.out.print("\n" + currentMode);
            String command = scanner.nextLine().trim().toLowerCase();

            switch (command) {
                case "login" -> login(scanner, currentMode);
                case "register" -> register(scanner, currentMode);
                case "send_post" -> sendPost(scanner, currentMode);
                case "get_10_last_posts" -> getPosts(currentMode);
                case "exit" -> go = false;
                //case "help" -> HelpBox();
                case "file_transfer_mode" -> filesMode(scanner);
                case "logout" -> logout(currentMode);
                default -> System.out.println("Invalid option. Please try again.");

            }
        }

        System.out.println("Bye!");
    }

    private static void login(Scanner scanner, String currentMode) {
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
        send(request);
        messageId++;
    }

    private static void register(Scanner scanner, String currentMode) {
        if (isLoggedIn) {
            System.out.println("You can't register while login.");
            return;
        }
        String mode = currentMode + "[Register]";
        System.out.print(mode + " Enter username: ");
        String username = scanner.nextLine();
        System.out.print(mode + " Enter password: ");
        String password = scanner.nextLine();
        String request = encode(String.format("message_type:registration_request;message_id:%d;username:%s;password:%s;", messageId, username, password));
        send(request);
    }

    private static void sendPost(Scanner scanner, String currentMode) {
        if (!isLoggedIn) {
            System.out.println("You must be logged in to enter this Mode.");
            return;
        }

        String mode = currentMode + "[Send Post]";
        System.out.print(mode + " Enter post title: ");
        String title = scanner.nextLine();
        System.out.print(mode + " Enter post body: ");
        String body = scanner.nextLine();
        String request = encode(String.format("message_type:send_post_request;message_id:%d;title:%s;body:%s;username:%s;", messageId, title, body, username));
        send(request);
    }

    private static void getPosts(String currentMode) {
        String mode = currentMode + "[Get 10 Last Posts]";
        System.out.print(mode);
        String request = encode(String.format("message_type:retrieve_last_10_posts_request;message_id:%d;post_count:10;", messageId));
        send(request);
    }

    private static void logout(String currentMode) {
        if (isLoggedIn) {
            isLoggedIn = false;
            username = "";
            System.out.println("You have been logged out.");
        } else {
            System.out.println("You are not logged in.");
        }
    }

    private static void filesMode(Scanner scanner) {
        if (!isLoggedIn) {
            System.out.println("You must be logged in to enter this Mode.");
            return;
        }
        String currentMode = "[File Transfer Mode]";
        while (true) {
            System.out.print(currentMode + "[Command]: ");
            String input = scanner.nextLine().trim().toLowerCase();

            switch (input) {
                case "list_files" -> {
                    currentMode = "[File Transfer Mode][List Files]";
                    System.out.print(currentMode);
                    String request = encode(String.format("message_type:list_files_request;message_id:%d;", messageId));
                    send(request);
                }
                case "get_file" -> getFile(scanner, currentMode);
                case "send_file" -> sendFile(scanner, currentMode);
                case "exit" -> {
                    System.out.println("Exiting File Transfer Mode...");
                    return;
                }
                default -> System.out.println("Invalid option. Please try again.");
            }
        }
    }

    private static void getFile(Scanner scanner, String currentMode) {
        String mode = currentMode + "[Get File]";
        System.out.print(mode + " Enter filename to download: ");
        String filename = scanner.nextLine();
        String request = encode(String.format("message_type:download_file_request;message_id:%d;file_name:%s;", messageId, filename));
        send(request);
    }

    private static void sendFile(Scanner scanner, String currentMode) {
        String mode = currentMode + "[Send File]";
        System.out.print(mode + " Enter the file name to upload (located in files): ");
        String fileNameClient = scanner.nextLine();
        System.out.print(mode + " Enter what file name you want set: ");
        String fileNameServer = scanner.nextLine();
        uploadFile(fileNameClient, fileNameServer);
    }

    public static void uploadFile(String fileNameClient, String fileNameServer) {
        File file = new File("files", fileNameClient);
        if (!file.exists() || !file.isFile()) {
            System.out.print("Error: The file does not exist or is not a valid file.");
            return;
        }

        byte[] fileContent;
        long fileSize;
        long packetSize;

        fileSize = file.length();
        packetSize = fileSize;
        fileContent = new byte[(int) fileSize];

        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(fileContent);
        } catch (IOException e) {
            System.out.print("Error reading file: " + e.getMessage());
            return;
        }

        String encodedContent = java.util.Base64.getEncoder().encodeToString(fileContent);
        String request = encode(String.format("message_type:send_file_request;message_id:%d;file_name:%s;file_content:%s;file_size:%d;packet_size:%d;", messageId, fileNameClient, encodedContent, fileSize, packetSize));
        send(request);
    }

    private static void send(String request) {
        try (Socket socket = new Socket(HOST, PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();

            String signedReqest = sign(request);
            String encryptedRequest = encrypt(request, secretKey);
            String key = encryptKey(secretKey);
            out.println(signedReqest);
            out.println(encryptedRequest);
            out.println(key);

            String encodedSign = in.readLine();
            String encodedResponse = in.readLine();
            String encodedKey = in.readLine();
            secretKey = decryptKey(encodedKey);
            String text = decrypt(encodedResponse, secretKey);
            if (verify(encodedSign, text)){
                System.out.println(text);
            } else System.out.println("Nie udało się zweryfikować nadawcy");

            response(text);
        } catch (IOException e) {
            System.out.println("Failed to connect to the server: " + e.getMessage());
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException |
                 InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    private static String sign(String text){
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(text.getBytes(StandardCharsets.UTF_8));

            byte[] bytes = signature.sign();

            return Base64.getEncoder().encodeToString(bytes);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e){
            System.out.println("Sign error " + e.getMessage());
            return null;
        }
    }

    private static String encrypt(String text, SecretKey secretKey){
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] bytes = cipher.doFinal(text.getBytes());

            return Base64.getEncoder().encodeToString(bytes);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e){
            System.out.println("Encrypt error " + e.getMessage());
            return  null;
        }
    }

    private static String encryptKey(SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, sendPublicKey);

        byte[] bytes = cipher.doFinal(secretKey.getEncoded());

        return Base64.getEncoder().encodeToString(bytes);
    }

    private static SecretKey decryptKey(String encryptedKey) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(encryptedKey));

        return new SecretKeySpec(bytes, 0, bytes.length, "AES");
    }

    private static boolean verify(String sign, String text) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(sendPublicKey);
        signature.update(text.getBytes(StandardCharsets.UTF_8));

        byte[] bytes = Base64.getDecoder().decode(sign);

        return signature.verify(bytes);
    }

    private static String decrypt(String encryptedText, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static String encode(String message) {
        return Base64.getEncoder().encodeToString(message.getBytes());
    }

    public static void response(String encodedResponse) {
        String decodedResponse = decodeBase64(encodedResponse);
        Map<String, String> parsedResponse = parseKeyValueFormat(decodedResponse);

        String messageType = parsedResponse.get("message_type");

        switch (messageType) {
            case "login_response" -> loginResponse(parsedResponse);
            case "registration_response" -> registerResponse(parsedResponse);
            case "send_post_response" -> sendPostResponse(parsedResponse);
            case "retrieve_last_10_posts_response" -> lastPostsResponse(parsedResponse.get("posts"));
            case "list_files_response" -> filesListResponse(parsedResponse);
            case "download_file_response" -> fileDownloadResponse(parsedResponse);
            case "send_file_response" -> fileUploadResponse(parsedResponse);
            default -> System.out.println("Unknown response type: " + messageType);
        }
    }

    private static String decodeBase64(String encodedString) {
        try {
            return new String(Base64.getDecoder().decode(encodedString));
        } catch (IllegalArgumentException e) {
            System.out.println("Failed to decode Base64 content: " + e.getMessage());
            return "";
        }
    }

    private static void loginResponse(Map<String, String> parsedResponse) {
        String statusCode = parsedResponse.getOrDefault("status", "0");

        if ("200".equals(statusCode)) {
            String username = parsedResponse.get("username");
            isLoggedIn = true;
            Client.username = username;
        }
    }

    private static void registerResponse(Map<String, String> parsedResponse) {
        System.out.println("Registration Response: " + parsedResponse.getOrDefault("status", "Unknown status"));
    }

    private static void sendPostResponse(Map<String, String> parsedResponse) {
        String status = parsedResponse.get("status");
        if ("error".equalsIgnoreCase(status)) {
            String errorMessage = parsedResponse.getOrDefault("error_message", "Unknown post error.");
            System.out.println("Post Error: " + errorMessage);
        } else {
            System.out.println("Post Sent Successfully!");
        }
    }

    private static void lastPostsResponse(String postsSection) {
        if (postsSection == null || postsSection.isEmpty()) {
            System.out.println("No posts found.");
            return;
        }

        String[] posts = postsSection.split("\\|");
        System.out.println("\n=== Last 10 Posts ===");
        for (int i = 0; i < posts.length; i++) {
            System.out.printf("[%d] %s%n", i + 1, posts[i]);
        }
    }

    private static void filesListResponse(Map<String, String> parsedResponse) {
        String fileList = parsedResponse.get("file_list");

        if (fileList == null || fileList.isEmpty()) {
            System.out.println("Server responded, but no files are available.");
        } else {
            String[] files = fileList.split("\\|");
            System.out.println("\n=== Available Files ===");
            for (int i = 0; i < files.length; i++) {
                String fileName = files[i].replaceFirst("^File:\\s*", ""); // Clean up file names
                System.out.printf("[%d] %s%n", i + 1, fileName);
            }
        }
    }

    private static void fileDownloadResponse(Map<String, String> parsedResponse) {
        String fileContent = parsedResponse.get("file_content");
        String fileName = parsedResponse.get("file_name");

        if (fileContent == null || fileContent.isEmpty()) {
            System.out.println("No file content found.");
            return;
        }

        byte[] decodedFileContent = Base64.getDecoder().decode(fileContent);

        try {
            saveFile(fileName, decodedFileContent);
        } catch (IOException e) {
            System.out.println("Failed to save the file: " + e.getMessage());
        }
    }

    private static void saveFile(String fileName, byte[] fileContent) throws IOException {
        File outputFile = new File("files", fileName);

        if (outputFile.exists()) {
            System.out.println("Error: The file already exists at: " + outputFile.getAbsolutePath());

            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter a new filename to save the file: ");
            String newFileName = scanner.nextLine().trim();
            if (newFileName.isEmpty()) {
                System.out.println("No new filename provided. File not saved.");
                return;
            }

            outputFile = new File("files", newFileName);

            if (outputFile.exists()) {
                System.out.println("Error: The new file already exists at: " + outputFile.getAbsolutePath());
                return;
            }
        }

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(fileContent);
            System.out.println("File saved at: " + outputFile.getAbsolutePath());
        } catch (IOException e) {
            System.out.println("Error saving the file: " + e.getMessage());
            throw e;
        }
    }

    private static void fileUploadResponse(Map<String, String> parsedResponse) {
        String status = parsedResponse.get("status");
        if ("200".equalsIgnoreCase(status)) {
            System.out.println("File upload completed successfully.");
        } else {
            String errorMessage = parsedResponse.getOrDefault("error_message", "Unknown error during file upload.");
            System.out.println("File upload failed: " + errorMessage);
        }
    }

    private static Map<String, String> parseKeyValueFormat(String message) {
        Map<String, String> map;
        String[] pairs = message.split(";");
        map = Arrays.stream(pairs).filter(pair -> pair.contains(":")).map(pair -> pair.split(":", 2)).collect(Collectors.toMap(keyValue -> keyValue[0], keyValue -> keyValue[1], (a, b) -> b));
        return map;
    }
}
