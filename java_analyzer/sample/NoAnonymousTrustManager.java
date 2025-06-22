import javax.net.ssl.*;
import java.security.SecureRandom;
import java.io.IOException;

public class NoAnonymousTrustManager {
    public static void main(String[] args) throws Exception {
        System.out.println("--- Testing SSLContext Initialization without Anonymous TrustManager ---");

        // Initialize SecureRandom using getInstanceStrong() for cryptographically strong random numbers
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        System.out.println("SecureRandom initialized with getInstanceStrong().");

        // Initialize SSLContext using null for KeyManager and TrustManager arrays.
        // Passing null means that the default KeyManager and TrustManager will be used.
        // The default TrustManager typically trusts certificates in the JVM's 'cacerts' truststore.
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3"); // Or TLSv1.2 for broader compatibility
        sslContext.init(null, null, secureRandom); // KeyManagers: null, TrustManagers: null, SecureRandom: secureRandom
        System.out.println("SSLContext initialized using default TrustManager (passing null).");

        // Simulate a secure connection attempt
        try {
            SSLSocketFactory factory = sslContext.getSocketFactory();
            // This will use the default TrustManager from the SSLContext
            SSLSocket socket = (SSLSocket) factory.createSocket("www.google.com", 443);
            socket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
            socket.setEnabledCipherSuites(new String[]{
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            });
            socket.startHandshake(); // Initiate the handshake to trigger validation
            System.out.println("Successfully performed secure handshake with www.google.com using default TrustManager.");
            socket.close();
        } catch (SSLHandshakeException e) {
            System.err.println("SSL Handshake failed (might be expected if certificate validation fails for your environment/proxies): " + e.getMessage());
        } catch (IOException e) {
            System.err.println("IOException during connection: " + e.getMessage());
        }

        System.out.println("Test case complete: No anonymous TrustManager detected by analyzer.");
    }
}
