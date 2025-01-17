package api;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
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
    private static PublicKey publicKey;
    private static PrivateKey privateKey;
    private static PublicKey sendPublicKey;

    public static void main(String[] args) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

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

            String encodedSign = in.readLine();
            String encodedResponse = in.readLine();
            String encodedKey = in.readLine();
            SecretKey secretKey = decryptKey(encodedKey);
            String text = decrypt(encodedResponse, secretKey);
            if (verify(encodedSign, text)){
                System.out.println(text);
            } else System.out.println("Nie udało się zweryfikować nadawcy");

            String response = route(text);
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            secretKey = keyGenerator.generateKey();

            String signedReqest = sign(response);
            String encryptedRequest = encrypt(response, secretKey);
            String key = encryptKey(secretKey);
            out.println(signedReqest);
            out.println(encryptedRequest);
            out.println(key);

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

    private static String sign(String text) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(text.getBytes(StandardCharsets.UTF_8));

        byte[] bytes = signature.sign();

        return Base64.getEncoder().encodeToString(bytes);
    }

    private static String encrypt(String text, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] bytes = cipher.doFinal(text.getBytes());

        return Base64.getEncoder().encodeToString(bytes);
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

    private static Map<String, String> parseKeyValueFormat(String message) {
        Map<String, String> map;
        String[] pairs = message.split(";");
        map = Arrays.stream(pairs).filter(pair -> pair.contains(":")).map(pair -> pair.split(":", 2)).collect(Collectors.toMap(keyValue -> keyValue[0], keyValue -> keyValue[1], (a, b) -> b));
        return map;
    }
}
