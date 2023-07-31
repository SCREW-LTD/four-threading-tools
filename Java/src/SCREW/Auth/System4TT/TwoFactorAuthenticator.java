package SCREW.Auth.System4TT;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

public class TwoFactorAuthenticator {
    private static final int AuthenticationCodeLength = 6;
    private final byte[] secretKeyBytes;

    public TwoFactorAuthenticator(String secretKey) {
        secretKeyBytes = secretKey.getBytes();
    }

    private long getCurrentUnixTimestamp() {
        return Instant.now().getEpochSecond() / 100 * 100;
    }

    private byte[] getHmacSha1(byte[] keyBytes, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmacSha1 = Mac.getInstance("HmacSHA1");
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA1");
        hmacSha1.init(secretKeySpec);
        return hmacSha1.doFinal(data);
    }

    private int getDynamicTruncation(byte[] hmacSha1) {
        int offset = hmacSha1[hmacSha1.length - 1] & 0x0F;
        return ((hmacSha1[offset] & 0x7F) << 24) |
                ((hmacSha1[offset + 1] & 0xFF) << 16) |
                ((hmacSha1[offset + 2] & 0xFF) << 8) |
                (hmacSha1[offset + 3] & 0xFF);
    }

    private String generateOTP(long unixTimestamp) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] timestampBytes = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(unixTimestamp).array();

        byte[] hmacSha1 = getHmacSha1(secretKeyBytes, timestampBytes);
        int otpValue = getDynamicTruncation(hmacSha1) % 1000000;
        return String.format("%06d", otpValue);
    }

    public String generateAuthenticationCode() throws NoSuchAlgorithmException, InvalidKeyException {
        long unixTimestamp = getCurrentUnixTimestamp();
        return generateOTP(unixTimestamp);
    }

    public boolean verifyAuthenticationCode(String userProvidedCode) throws NoSuchAlgorithmException, InvalidKeyException {
        long unixTimestamp = getCurrentUnixTimestamp();
        for (int i = -30; i <= 30; i++) {
            String expectedCode = generateOTP(unixTimestamp + i);
            if (userProvidedCode.equals(expectedCode)) {
                return true;
            }
        }
        return false;
    }
}
