import javax.net.ssl.HttpsURLConnection;

public class InsecureHostnameVerifier {
    public static void main(String[] args) {
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }
}
