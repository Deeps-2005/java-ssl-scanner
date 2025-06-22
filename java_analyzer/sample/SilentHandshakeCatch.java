import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SilentHandshakeCatch {
    public static void main(String[] args) {
        try {
            SSLSocket sslSocket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            sslSocket.startHandshake();
        } catch (Exception e) {
            // nothing here
        }
    }
}
