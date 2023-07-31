package SCREW.Auth.System4TT;

import java.security.SecureRandom;
import java.util.Base64;

public class System4TT {
    private final String CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";

    public String generateSecretKey() {
        StringBuilder codeBuilder = new StringBuilder();
        SecureRandom random = new SecureRandom();

        for (int i = 0; i < 64; i++) {
            int index = random.nextInt(CHARS.length());
            codeBuilder.append(CHARS.charAt(index));
        }

        return codeBuilder.toString();
    }

    public String encodeSecretKey(String secretKey) {
        byte[] bytesToEncode = secretKey.getBytes();
        String base64String = Base64.getEncoder().encodeToString(bytesToEncode);
        return base64String;
    }

    public String decodeSecretKey(String base64Key) {
        byte[] bytesToDecode = Base64.getDecoder().decode(base64Key);
        String decodedString = new String(bytesToDecode);
        return decodedString;
    }
}
