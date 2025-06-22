import javax.net.ssl.*;
import java.security.cert.X509Certificate;

public class TestCipherBug { // Class name remains AllVulnerabilitiesTest
    public static void main(String[] args) throws Exception {
        // ❌ Insecure TrustManager
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { } // FIX: Removed extra 'void' here
            }
        };

        // ❌ Insecure HostnameVerifier
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        // ❌ Weak Cipher Suites
        SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
        socket.setEnabledCipherSuites(new String[]{"TLS_RSA_WITH_NULL_MD5"});

        // ❌ Debug Logging Enabled
        System.setProperty("javax.net.debug", "ssl");

        // ❌ TLS Renegotiation not disabled
        System.setProperty("com.ibm.jsse2.renegotiate", "ALLOW");

        // ❌ Potential DoS via Handshake Flooding
        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket sss = (SSLServerSocket) ssf.createServerSocket(8443);
        while (true) {
            sss.accept(); // endless handshake
        }
    }
}
