// Java secure coding compliance template
import java.security.SecureRandom;

public class SecureDemo {
    // Secure random token generation (32-byte hex = 256-bit entropy)
    // NOTE: 6-digit numeric codes should only be used for low-sensitivity
    // scenarios (e.g., one-time email verification), NOT for session tokens
    // or password reset tokens. For security tokens, use at least 32 bytes.
    public static String secureToken(){
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Parameterized queries, data masking utilities, secure config reference template
}
