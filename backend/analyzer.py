import subprocess
import tempfile
import re
import os

def analyze_java_code(code: str):
    """
    Analyzes the provided Java code string for SSL/JSSE vulnerabilities
    using an external Java Analyzer tool.

    Args:
        code (str): The Java source code to analyze.

    Returns:
        list: A list of dictionaries, each representing a detected vulnerability
              with 'line', 'issue', 'suggestion', 'sanitized_code', and 'severity'.
              Returns an empty list [] if no issues are found,
              or an error dictionary if the analysis fails.
    """
    # Helper function to extract structured data from analyzer output lines.
    # It now handles "ISSUE:", "WARNING:", and indented "SUB-ISSUE:" formats.
    def extract_issue_data(line):
        match_issue = re.match(r"\[Line (\d+)\] ISSUE: (.*)", line)
        if match_issue:
            return (int(match_issue.group(1)), "ISSUE: " + match_issue.group(2))
        
        match_warning = re.match(r"\[Line (\d+)\] WARNING: (.*)", line)
        if match_warning:
            return (int(match_warning.group(1)), "WARNING: " + match_warning.group(2))
        
        # This regex matches the indented sub-messages for TrustManager/HostnameVerifier
        match_sub_issue = re.match(r"  \[Line (\d+)\]  - (.*)", line)
        if match_sub_issue:
            return (int(match_sub_issue.group(1)), "SUB-ISSUE: " + match_sub_issue.group(2))

        return (None, line.strip()) # Returns None for line_num if no match

    java_file_path = None # Initialize to None for finally block cleanup
    try:
        # Aggressive line ending normalization:
        # 1. Replace all CRLF with LF.
        # 2. Replace all standalone CR with LF.
        # This ensures only LF characters are used for newlines.
        normalized_code = code.replace('\r\n', '\n').replace('\r', '\n')

        # Create a temporary Java file to write the code for analysis.
        # delete=False is used for easier debugging to inspect the temp file.
        with tempfile.NamedTemporaryFile(delete=False, suffix=".java", mode="w", encoding="utf-8") as temp:
            temp.write(normalized_code) # Write the normalized code
            java_file_path = os.path.abspath(temp.name)

        # Determine the base path of the Python script (e.g., 'my_project/backend')
        base_path_of_python_script = os.path.abspath(os.path.dirname(__file__))
        
        # Construct the path to the directory containing Analyzer.class and javaparser JAR.
        # This now correctly navigates from 'my_project/backend' up to 'my_project'
        # and then into 'java_analyzer'.
        analyzer_class_dir = os.path.join(os.path.dirname(base_path_of_python_script), "java_analyzer")
        
        # Construct the path to the javaparser JAR
        javaparser_jar = os.path.join(analyzer_class_dir, "javaparser-core-3.26.4.jar")
        
        # Build the Java classpath: include the directory containing Analyzer.class
        # and the javaparser JAR.
        classpath = f"{analyzer_class_dir}{os.pathsep}{javaparser_jar}"

        # Execute the Java Analyzer tool.
        # 'check=True' will raise a CalledProcessError if the command returns a non-zero exit code.
        result = subprocess.run(["java", "-cp", classpath, "Analyzer", java_file_path],
                                stdout=subprocess.PIPE,  # Capture standard output
                                stderr=subprocess.PIPE,  # Capture standard error
                                text=True,               # Decode stdout/stderr as text
                                check=True)              # Raise error on non-zero exit code
        
        output_lines = result.stdout.strip().splitlines()
        report = []

        # Process each line from the Java Analyzer's output
        for line in output_lines:
            line_num, issue_text = extract_issue_data(line)
            
            # Skip lines that don't conform to the expected issue/warning format
            if line_num is None:
                continue

            suggestion = "Review the code for security best practices."
            sanitized_code = None
            severity = "UNKNOWN"

            # --- Vulnerability Mapping and Suggestions ---
            # These conditions map the issue text from the Java Analyzer to a severity,
            # a user-friendly suggestion, and an example of sanitized/secure code.

            if "Anonymous X509TrustManager/TrustManager detected" in issue_text or \
               "Method 'checkClientTrusted' has an empty body" in issue_text or \
               "Method 'checkServerTrusted' has an empty body" in issue_text or \
               "Method 'checkClientTrusted' unconditionally returns true" in issue_text or \
               "Method 'checkServerTrusted' unconditionally returns true" in issue_text or \
               "Method 'checkClientTrusted' catches" in issue_text or \
               "Method 'checkServerTrusted' catches" in issue_text:
                suggestion = "Implement proper certificate validation by using `TrustManagerFactory` initialized with a trusted `KeyStore` or by implementing strict checks within custom `TrustManager` methods. Avoid empty method bodies or unconditionally returning `true`."
                sanitized_code = """
// Example of secure TrustManager initialization
TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
// Load trusted certificates into ts (e.g., from a .jks file)
// ts.load(new FileInputStream("path/to/truststore.jks"), "truststore_password".toCharArray());
tmf.init(ts);
SSLContext sslContext = SSLContext.getInstance("TLSv1.3"); // Prefer modern TLS protocols
sslContext.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());
                """
                severity = "CRITICAL"

            elif "Anonymous HostnameVerifier detected" in issue_text or \
                 "Method 'verify' has an empty body" in issue_text or \
                 "Method 'verify' unconditionally returns true" in issue_text or \
                 "Insecure HostnameVerifier (lambda always returns true)" in issue_text or \
                 "Insecure HostnameVerifier (lambda block always returns true)" in issue_text:
                suggestion = "Implement strict hostname verification. Ensure the hostname in the certificate matches the expected hostname of the server. Do not unconditionally return `true` as this bypasses critical security checks."
                sanitized_code = """
// Example of secure HostnameVerifier
HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
    @Override
    public boolean verify(String hostname, SSLSession session) {
        // Use default verifier for standard checks and add custom logic if needed
        HostnameVerifier defaultVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
        boolean verified = defaultVerifier.verify(hostname, session);
        // Add additional, strict checks, e.g., for specific domain
        // return verified && hostname.equalsIgnoreCase("api.yourdomain.com");
        return verified; // Or more complex, secure logic
    }
});
                """
                severity = "CRITICAL"

            elif "Weak cipher suite keyword detected in array" in issue_text or \
                 "Insecure SSL/TLS protocol requested" in issue_text or \
                 "Insecure SSL/TLS protocol enabled via setEnabledProtocols" in issue_text or \
                 "Weak cipher suite enabled via setEnabledCipherSuites" in issue_text or \
                 "Weak cipher suite keyword detected in array" in issue_text:
                suggestion = "Use only strong, modern TLS protocols (e.g., TLSv1.2 or TLSv1.3) and secure cipher suites. Disable known weak protocols (e.g., SSLv2, SSLv3, TLSv1.0, TLSv1.1) and cipher suites (e.g., those using RC4, DES, NULL ciphers, ANONYMOUS, EXPORT)."
                sanitized_code = """
// Example: Enable only TLSv1.3 and TLSv1.2 protocols
String[] protocols = {"TLSv1.3", "TLSv1.2"};
// For SSLSocket or SSLEngine:
// socket.setEnabledProtocols(protocols);

// Example: Enable only strong cipher suites
String[] strongCiphers = {
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    // Add other strong suites as per security guidelines
};
// For SSLSocket or SSLEngine:
// socket.setEnabledCipherSuites(strongCiphers);
                """
                severity = "HIGH"

            elif "Debug logging enabled" in issue_text:
                suggestion = "Remove or comment out `System.setProperty(\"javax.net.debug\")` in production environments. Debug logging exposes sensitive SSL/TLS handshake details that could aid attackers. Enable only for debugging in non-production or test environments."
                sanitized_code = "// System.setProperty(\"javax.net.debug\", \"all\"); // Remove or comment out in production"
                severity = "MEDIUM"

            elif "TLS renegotiation potentially enabled" in issue_text:
                suggestion = "Disable client-initiated TLS renegotiation to mitigate potential Denial-of-Service (DoS) attacks. For OpenJDK/Oracle JVMs, use `System.setProperty(\"jdk.tls.rejectClientInitiatedRenegotiation\", \"true\");`. For IBM JSSE, ensure `com.ibm.jsse2.renegotiate` is set to `DISABLED`."
                sanitized_code = 'System.setProperty("jdk.tls.rejectClientInitiatedRenegotiation", "true");\n// For IBM JSSE: System.setProperty("com.ibm.jsse2.renegotiate", "DISABLED");'
                severity = "HIGH"

            elif "Hardcoded literal password passed to KeyStore.load()" in issue_text or \
                 "Hardcoded password/sensitive string assigned to variable" in issue_text:
                suggestion = "Avoid hardcoding passwords, keys, or any sensitive strings directly in the source code. Implement secure credential management using environment variables, Java KeyStore (JKS) with external management, or dedicated secrets management systems (e.g., HashiCorp Vault, AWS Secrets Manager)."
                sanitized_code = 'char[] password = System.getenv("APP_KEYSTORE_PASSWORD") != null ? System.getenv("APP_KEYSTORE_PASSWORD").toCharArray() : null; // Load from environment variable'
                severity = "CRITICAL"

            elif "Potential infinite loop (while(true))" in issue_text:
                suggestion = "Review and refactor any infinite loop logic involved in SSL handshake or connection handling to prevent potential Denial-of-Service (DoS) vulnerabilities. Implement proper timeouts, maximum retry limits, and exponential backoff strategies for network operations."
                sanitized_code = """
// Example: Add a timeout or counter for connection attempts
int attempts = 0;
int MAX_ATTEMPTS = 5;
long TIMEOUT_MS = 5000; // 5 seconds
boolean connected = false;
while (attempts < MAX_ATTEMPTS && !connected) {
    try {
        // SSL/TLS handshake or connection logic
        // connected = performSecureConnection();
    } catch (Exception e) {
        System.err.println("Connection attempt failed: " + e.getMessage());
    }
    attempts++;
    if (!connected && attempts < MAX_ATTEMPTS) {
        Thread.sleep(TIMEOUT_MS); // Add a delay before retrying
    }
}
                """
                severity = "HIGH"

            elif "Unseeded SecureRandom instance" in issue_text:
                suggestion = "Always seed `SecureRandom` instances explicitly with a strong entropy source, or preferably, use `SecureRandom.getInstanceStrong()` which provides a default, strong, cryptographically secure random number generator (CSPRNG) suitable for generating keys, nonces, and other cryptographic values."
                sanitized_code = "SecureRandom secureRandom = SecureRandom.getInstanceStrong();"
                severity = "HIGH"
            
            elif "URL constructed with 'http://' scheme" in issue_text:
                suggestion = "Ensure all network connections, especially those handling sensitive data, exclusively use the `https://` scheme to enforce TLS encryption. Avoid sending sensitive data over insecure `http://` connections, which are vulnerable to eavesdropping and Man-in-the-Middle (MitM) attacks."
                sanitized_code = 'URL url = new URL("https://www.secure-example.com/api/data"); // Always use HTTPS for secure communication'
                severity = "MEDIUM"
            
            elif "Overly broad catch for" in issue_text and "with minimal error handling" in issue_text:
                suggestion = "Refactor exception handling to catch specific exceptions relevant to SSL/TLS operations (e.g., `SSLHandshakeException`, `CertificateException`, `KeyStoreException`). Log detailed error information for debugging and incident response, and avoid swallowing exceptions or using empty catch blocks, as this can hide critical security failures and make systems vulnerable."
                sanitized_code = """
try {
    // Perform SSL/TLS related operation
} catch (javax.net.ssl.SSLHandshakeException e) {
    System.err.println("ERROR: SSL Handshake Failed: " + e.getMessage());
    // Specific error handling, potentially re-throw as a custom exception
} catch (java.security.cert.CertificateException e) {
    System.err.println("ERROR: Certificate Validation Failed: " + e.getMessage());
    // Specific error handling
} catch (Exception e) { // Catch remaining specific exceptions, then a general one if truly necessary
    System.err.println("ERROR: An unexpected error occurred: " + e.getMessage());
    // Log more details or re-throw
}
                """
                severity = "MEDIUM"

            elif "Weak hashing algorithm used:" in issue_text:
                suggestion = "Replace weak hashing algorithms (like MD5 or SHA-1) with strong, modern cryptographic hash functions such as SHA-256 or SHA-512 for data integrity, digital signatures, and password storage. For password storage, consider using adaptive functions like Argon2, scrypt, or bcrypt via a secure library."
                sanitized_code = 'MessageDigest secureHash = MessageDigest.getInstance("SHA-256"); // Use SHA-256 or SHA-512\nsecureHash.update(data.getBytes());'
                severity = "HIGH"

            elif "Potentially hardcoded cryptographic key/salt/IV" in issue_text:
                suggestion = "Never hardcode cryptographic keys, salts, or Initialization Vectors (IVs) directly in the source code. Externalize these sensitive values to secure configuration management systems, environment variables (with proper access control), or Hardware Security Modules (HSMs) for robust protection."
                sanitized_code = 'byte[] keyBytes = System.getenv("AES_KEY").getBytes(StandardCharsets.UTF_8); // Load key from secure environment variable\nSecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");'
                severity = "CRITICAL"

            elif "Deserialization of untrusted data via ObjectInputStream" in issue_text:
                suggestion = "Avoid deserializing untrusted data using `ObjectInputStream` as it is a frequent source of Remote Code Execution (RCE) vulnerabilities. If deserialization is unavoidable, implement robust serialization filters (available in Java 9+) or use alternative, safer data formats like JSON, XML (with XXE protection), or Protocol Buffers."
                sanitized_code = """
// WARNING: Avoid ObjectInputStream with untrusted data.
// If deserialization is strictly necessary and from trusted source:
// FileInputStream fis = new FileInputStream("trusted_data.ser");
// ObjectInputStream ois = new ObjectInputStream(fis);
// Consider: ois.setObjectInputFilter(YourCustomFilter.createDenyAllFilter()); // Java 9+ security
"""
                severity = "CRITICAL"

            elif "XML parsing factory created without explicit XXE hardening" in issue_text:
                suggestion = "Configure XML parsing factories (DocumentBuilderFactory, SAXParserFactory, XMLInputFactory) to explicitly disable DTD processing and external entity resolution. This prevents XML External Entity (XXE) attacks, which can lead to information disclosure, Server-Side Request Forgery (SSRF), or Denial-of-Service."
                sanitized_code = """
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
try {
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
} catch (ParserConfigurationException e) {
    // Handle configuration error
}
"""
                severity = "CRITICAL"
            
            report.append({
                "line": line_num,
                "issue": issue_text,
                "suggestion": suggestion,
                "sanitized_code": sanitized_code,
                "severity": severity
            })

        return report

    except subprocess.CalledProcessError as e:
        return [{
            "line": None,
            "issue": "Analyzer execution failed",
            "suggestion": f"Please check the Java code for syntax errors or issues preventing compilation/execution of the Analyzer. Java Analyzer's stderr: {e.stderr.strip()}",
            "sanitized_code": None,
            "severity": "ERROR"
        }]
    except FileNotFoundError:
        return [{
            "line": None,
            "issue": "Java or Analyzer dependencies not found",
            "suggestion": "Ensure Java Development Kit (JDK) is installed and accessible in your system's PATH. Verify that 'Analyzer.class' (or 'analyzer.jar' if packaged) and 'javaparser-core-3.26.4.jar' are correctly placed in the 'java_analyzer' directory relative to this Python script.",
            "sanitized_code": None,
            "severity": "ERROR"
        }]
    except Exception as e:
        return [{
            "line": None,
            "issue": "An unexpected error occurred in Python script",
            "suggestion": f"Error details: {str(e)}",
            "sanitized_code": None,
            "severity": "ERROR"
        }]
    finally:
        if java_file_path and os.path.exists(java_file_path):
            os.remove(java_file_path)
