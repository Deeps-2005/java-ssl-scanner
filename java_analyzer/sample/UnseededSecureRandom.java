import java.security.SecureRandom;

public class UnseededSecureRandom {
    public static void main(String[] args) {
        SecureRandom sr = new SecureRandom();  // No explicit seeding or entropy check
    }
}
