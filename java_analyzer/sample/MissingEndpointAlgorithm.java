import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLParameters;

public class MissingEndpointAlgorithm {
    public static void main(String[] args) throws Exception {
        SSLSocket sslSocket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
        SSLParameters params = sslSocket.getSSLParameters();
        sslSocket.setSSLParameters(params);  // No call to setEndpointIdentificationAlgorithm
    }
}
