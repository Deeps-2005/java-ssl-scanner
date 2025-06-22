public class RenegotiationEnabled {
    public static void main(String[] args) {
        System.setProperty("com.ibm.jsse2.renegotiate", "true");
    }
}
