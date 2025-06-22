 import javax.net.ssl; 
 import java.security.cert.X509Certificate; 
 public class TestInput { 
     public static void main(String[] args) { 
         TrustManager[] trustAll = new TrustManager[] { 
             new X509TrustManager() { 
                 public X509Certificate[] getAcceptedIssuers() { return null; } 
                 public void checkClientTrusted(X509Certificate[] certs, String authType) { } 
                 public void checkServerTrusted(X509Certificate[] certs, String authType) { } 
             } 
         }; 
     } 
 } 
