
import javax.net.ssl.*;

public class HostnameVerifierTrue {
    public static void main(String[] args) {
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
    }
}
