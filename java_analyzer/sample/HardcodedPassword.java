import java.io.FileInputStream;
import java.security.KeyStore;

public class HardcodedPassword {
    public static void main(String[] args) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream("keystore.jks"), "password".toCharArray());
    }
}
