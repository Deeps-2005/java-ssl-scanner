import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException; // Added for the specific exception

public class AllVulnerabilitiesTest {
    public static void main(String[] args) throws Exception {

        System.out.println("--- Testing Insecure TrustManager ---");
        // 1. ❌ Insecure TrustManager (Empty methods, unconditional return true, swallowing exceptions)
        TrustManager[] trustAllEmpty = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { /* Insecure: Empty body */ }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { } // Insecure: Empty body variant
            }
        };
        SSLContext sslContextEmpty = SSLContext.getInstance("TLS");
        sslContextEmpty.init(null, trustAllEmpty, new SecureRandom());

        TrustManager[] trustAllTrue = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { } // Empty body
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    System.out.println("Always trusting server certs.");
                    return true; // Insecure: Unconditional true
                }
            }
        };
        SSLContext sslContextTrue = SSLContext.getInstance("TLS");
        sslContextTrue.init(null, trustAllTrue, new SecureRandom());

        TrustManager[] trustAllSwallow = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    try { /* Some validation logic */ if (certs == null) throw new IOException("No certs"); }
                    catch (IOException e) { e.printStackTrace(); } // Insecure: Catches specific but prints stack trace
                }
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    try { /* Some validation logic */ if (certs == null) throw new KeyManagementException("No certs"); }
                    catch (KeyManagementException e) { /* Insecure: Swallowing specific exception */ }
                }
            }
        };
        SSLContext sslContextSwallow = SSLContext.getInstance("TLS");
        sslContextSwallow.init(null, trustAllSwallow, new SecureRandom());


        System.out.println("\n--- Testing Insecure HostnameVerifier ---");
        // 2. ❌ Insecure HostnameVerifier (lambda always returns true)
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        // 2. ❌ Insecure HostnameVerifier (anonymous class always returns true)
        HostnameVerifier customVerifier = new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true; // Vulnerable: always trusts
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(customVerifier);


        System.out.println("\n--- Testing Weak Cipher Suites & Protocols ---");
        SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();

        // 3. ❌ Weak Cipher Suites via setEnabledCipherSuites()
        socket.setEnabledCipherSuites(new String[]{"TLS_RSA_WITH_NULL_MD5", "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "TLS_DES_WITH_3DES_EDE_CBC_SHA"});

        // 4. ❌ Outdated SSLContext Protocol
        SSLContext sslContextOldProtocol = SSLContext.getInstance("SSLv3");
        sslContextOldProtocol.init(null, null, null);

        SSLContext sslContextTLS10 = SSLContext.getInstance("TLSv1");
        sslContextTLS10.init(null, null, null);

        // 5. ❌ Weak Enabled Protocols (via setEnabledProtocols)
        SSLSocket socketWeakProtocols = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
        socketWeakProtocols.setEnabledProtocols(new String[]{"SSLv2Hello", "TLSv1.2", "TLSv1.3"});


        System.out.println("\n--- Testing System Property & Resource Usage ---");
        // 6. ❌ Debug Logging Enabled
        System.setProperty("javax.net.debug", "ssl:handshake");

        // 7. ❌ TLS Renegotiation Not Disabled
        System.setProperty("com.ibm.jsse2.renegotiate", "ALLOW");

        // 8. ❌ Unseeded SecureRandom
        SecureRandom unseededRandom = new SecureRandom();
        SecureRandom anotherUnseeded = new SecureRandom(); // Another instance

        // 9. ❌ Hardcoded KeyStore Password
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            char[] passwordArray = "mysecretpassword123".toCharArray();
            ks.load(new FileInputStream("mykeystore.jks"), passwordArray);
        } catch (Exception e) {
            // Ignore for test
        }

        // 10. ❌ Hardcoded Sensitive Variable
        String apiKey = "my_hardcoded_api_key_abc123";
        String adminPass = "super_admin_pass";
        String secretToken = "token_xyz_secret";


        System.out.println("\n--- Testing Loop and Exception Handling ---");
        // 11. ❌ Potential DoS via Infinite Loop (Handshake Flooding)
        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket sss = (SSLServerSocket) ssf.createServerSocket(8443);
        while (true) {
            sss.accept(); // Simulates endless handshake/connection acceptance
            // In a real test, you might add a break or counter to prevent actual hanging
            if (System.currentTimeMillis() % 10000 == 0) break; // Example to break out
        }

        // 12. ❌ Overly Broad Catch for Exception
        try {
            if (true) throw new KeyManagementException("Simulated SSL error");
        } catch (Exception e) { // Vulnerable: Catches generic Exception
            System.err.println("Caught generic exception: " + e.getMessage());
            // No specific handling, just logging.
        }

        // 13. ❌ Overly Broad Catch for Throwable (empty block)
        try {
            if (true) throw new RuntimeException("Another runtime issue");
        } catch (Throwable t) { // Vulnerable: Catches Throwable
            // Empty catch block - completely swallows
        }


        System.out.println("\n--- Testing URL Usage & Cipher Array Declaration ---");
        // 14. ❌ HTTP URL Usage
        try {
            URL insecureUrl = new URL("http://www.insecure-api.com/data");
            insecureUrl.openConnection(); // Just to trigger URL usage
            URL localhostUrl = new URL("http://localhost:8080/api"); // Should NOT be flagged (localhost exclusion)
        } catch (IOException e) {
            // Ignore for test
        }

        // 15. ❌ Weak Cipher Suites Array (Variable Declaration)
        String[] weakCiphersArray = {
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", // Strong
            "SSL_RSA_WITH_NULL_SHA",          // Weak
            "TLS_DHE_RSA_WITH_DES_CBC_SHA"      // Weak
        };
        System.out.println("Defined weak cipher suites array variable.");

        System.out.println("\n--- All vulnerability patterns included in this test file ---");
    }
}