import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

public class AnonymousTrustManager {
    public static void main(String[] args) {
        X509TrustManager tm = new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return null; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) { }
            public void checkServerTrusted(X509Certificate[] certs, String authType) { }
        };
    }
}
