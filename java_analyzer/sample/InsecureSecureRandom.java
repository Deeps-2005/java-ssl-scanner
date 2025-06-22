
import javax.net.ssl.*;
import java.security.KeyStore;

public class SafeSSL {
    public static void main(String[] args) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore ks = KeyStore.getInstance("JKS");
        // Initialize ks...
        tmf.init(ks);

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());
    }
}
