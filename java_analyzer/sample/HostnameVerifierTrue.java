import javax.net.ssl.*;

public class HostnameVerifierTrue {

    public static void main(String[] args) {
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> {
            return hostname.equals("yourdomain.com");
        });
    }
}

