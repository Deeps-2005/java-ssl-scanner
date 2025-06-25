import com.github.javaparser.*;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*; // This import already covers ArrayCreationExpr, ArrayAccessExpr, ArrayInitializerExpr
import com.github.javaparser.ast.stmt.*;
import com.github.javaparser.ast.visitor.ModifierVisitor;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.type.Type;
// REMOVED these incorrect/redundant imports:
// import com.github.javaparser.ast.ArrayCreationLevel;
// import com.github.javaparser.ast.ArrayCreationExpr;
// import com.github.javaparser.ast.ArrayAccessExpr;
// import com.github.javaparser.ast.ArrayInitializerExpr;


import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.HashSet;


public class Analyzer {

    // SSL/JSSE related constants
    private static final List<String> INSECURE_PROTOCOLS = Arrays.asList("sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1");
    private static final List<String> WEAK_CIPHER_KEYWORDS = Arrays.asList("null", "anon", "export", "rc4", "des", "md5");

    // NEW: Cryptography related constants
    private static final List<String> WEAK_HASHING_ALGORITHMS = Arrays.asList("md5", "sha-1");
    private static final Set<String> XML_FACTORIES = new HashSet<>(Arrays.asList(
        "DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory"
    ));
    private static final String HARDCODED_KEY_PATTERN = ".*(key|secret|password|salt|token|cipher|auth).*";


    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Usage: java Analyzer <JavaFile>");
            return;
        }

        File file = new File(args[0]);
        if (!file.exists()) {
            System.err.println("Error: File not found - " + args[0]);
            return;
        }
        if (!file.isFile()) {
            System.err.println("Error: Not a file - " + args[0]);
            return;
        }

        CompilationUnit cu = StaticJavaParser.parse(new FileInputStream(file));

        cu.accept(new ModifierVisitor<Void>() {

            @Override
            public MethodCallExpr visit(MethodCallExpr mce, Void arg) {
                super.visit(mce, arg); // Call super to ensure full traversal

                int line = mce.getBegin().map(p -> p.line).orElse(-1);

                // Check for System.setProperty calls (debug logging, renegotiation)
                if (mce.getNameAsString().equals("setProperty") && mce.getArguments().size() == 2) {
                    Expression arg0 = mce.getArgument(0);
                    if (arg0.isStringLiteralExpr()) {
                        String propName = arg0.asStringLiteralExpr().getValue();
                        if (propName.contains("javax.net.debug")) {
                            System.out.println("[Line " + line + "] ISSUE: Debug logging enabled (javax.net.debug) - Exposes sensitive SSL/TLS handshaking details. Severity: HIGH");
                        }
                        if (propName.contains("com.ibm.jsse2.renegotiate")) {
                            System.out.println("[Line " + line + "] ISSUE: TLS renegotiation potentially enabled - Can be abused for DoS attacks. Severity: HIGH");
                        }
                    }
                }

                // Check for HostnameVerifier related issues
                if (mce.getNameAsString().equals("setDefaultHostnameVerifier") && mce.getArguments().size() == 1) {
                    Expression arg0 = mce.getArgument(0);
                    if (arg0.isLambdaExpr()) {
                        LambdaExpr lambda = arg0.asLambdaExpr();
                        if (lambda.getBody().isExpressionStmt() &&
                            lambda.getBody().asExpressionStmt().getExpression().isBooleanLiteralExpr() &&
                            lambda.getBody().asExpressionStmt().getExpression().asBooleanLiteralExpr().getValue()) {
                            System.out.println("[Line " + line + "] ISSUE: Insecure HostnameVerifier (lambda always returns true) - Bypasses hostname validation, vulnerable to MITM. Severity: CRITICAL");
                        } else if (lambda.getBody().isBlockStmt()) {
                            BlockStmt block = lambda.getBody().asBlockStmt();
                            for (Statement stmt : block.getStatements()) {
                                if (stmt instanceof ReturnStmt) {
                                    ReturnStmt returnStmt = (ReturnStmt) stmt;
                                    if (returnStmt.getExpression().isPresent() &&
                                        returnStmt.getExpression().get().isBooleanLiteralExpr() &&
                                        returnStmt.getExpression().get().asBooleanLiteralExpr().getValue()) {
                                        System.out.println("[Line " + line + "] ISSUE: Insecure HostnameVerifier (lambda block always returns true) - Bypasses hostname validation, vulnerable to MITM. Severity: CRITICAL");
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                // Check for hardcoded password passed to keystore load()
                if (mce.getNameAsString().equals("load") &&
                    mce.getScope().isPresent() &&
                    mce.getScope().get().toString().contains("KeyStore") &&
                    mce.getArguments().size() == 2 &&
                    (mce.getArgument(1).isCharLiteralExpr() || mce.getArgument(1).isStringLiteralExpr())) {
                    System.out.println("[Line " + line + "] ISSUE: Hardcoded literal password passed to KeyStore.load() - Sensitive info in source code. Severity: HIGH");
                }

                // Check for outdated/weak SSL/TLS protocols in SSLContext.getInstance()
                if (mce.getNameAsString().equals("getInstance") &&
                    mce.getScope().isPresent() &&
                    mce.getScope().get().toString().contains("SSLContext") &&
                    mce.getArguments().size() >= 1) {
                    Expression arg0 = mce.getArgument(0);
                    if (arg0.isStringLiteralExpr()) {
                        String protocol = arg0.asStringLiteralExpr().getValue().toLowerCase();
                        if (INSECURE_PROTOCOLS.contains(protocol)) {
                            System.out.println("[Line " + line + "] ISSUE: Insecure SSL/TLS protocol requested: " + protocol.toUpperCase() + " - Known vulnerabilities exist. Severity: CRITICAL");
                        }
                    }
                }

                // Check for enabling weak/outdated PROTOCOLS via setEnabledProtocols()
                if (mce.getNameAsString().equals("setEnabledProtocols") &&
                    mce.getScope().isPresent() &&
                    (mce.getScope().get().toString().contains("SSLSocket") || mce.getScope().get().toString().contains("SSLEngine"))) {
                    
                    mce.getArguments().forEach(argExpr -> {
                        if (argExpr.isArrayInitializerExpr()) {
                            argExpr.asArrayInitializerExpr().getValues().forEach(protoExpr -> {
                                if (protoExpr.isStringLiteralExpr()) {
                                    String protocol = protoExpr.asStringLiteralExpr().getValue().toLowerCase();
                                    if (INSECURE_PROTOCOLS.contains(protocol)) {
                                        System.out.println("[Line " + line + "] ISSUE: Insecure SSL/TLS protocol enabled via setEnabledProtocols(): " + protocol.toUpperCase() + " - Known vulnerabilities exist. Severity: CRITICAL");
                                    }
                                }
                            });
                        } else if (argExpr.isStringLiteralExpr()) {
                            String protocol = argExpr.asStringLiteralExpr().getValue().toLowerCase();
                            if (INSECURE_PROTOCOLS.contains(protocol)) {
                                System.out.println("[Line " + line + "] ISSUE: Insecure SSL/TLS protocol enabled via setEnabledProtocols(): " + protocol.toUpperCase() + " - Known vulnerabilities exist. Severity: CRITICAL");
                            }
                        }
                    });
                }

                // Check for enabling weak CIPHER SUITES via setEnabledCipherSuites()
                if (mce.getNameAsString().equals("setEnabledCipherSuites") &&
                    mce.getScope().isPresent() &&
                    (mce.getScope().get().toString().contains("SSLSocket") || mce.getScope().get().toString().contains("SSLEngine"))) {
                    
                    mce.getArguments().forEach(argExpr -> {
                        if (argExpr.isArrayInitializerExpr()) {
                            argExpr.asArrayInitializerExpr().getValues().forEach(cipherExpr -> {
                                if (cipherExpr.isStringLiteralExpr()) {
                                    String cipherSuite = cipherExpr.asStringLiteralExpr().getValue().toLowerCase();
                                    if (WEAK_CIPHER_KEYWORDS.stream().anyMatch(cipherSuite::contains)) {
                                        System.out.println("[Line " + line + "] ISSUE: Weak cipher suite enabled via setEnabledCipherSuites(): " + cipherSuite.toUpperCase() + " - Use stronger cryptographic algorithms. Severity: CRITICAL");
                                    }
                                }
                            });
                        } else if (argExpr.isStringLiteralExpr()) {
                            String cipherSuite = argExpr.asStringLiteralExpr().getValue().toLowerCase();
                            if (WEAK_CIPHER_KEYWORDS.stream().anyMatch(cipherSuite::contains)) {
                                System.out.println("[Line " + line + "] ISSUE: Weak cipher suite enabled via setEnabledCipherSuites(): " + cipherSuite.toUpperCase() + " - Use stronger cryptographic algorithms. Severity: CRITICAL");
                            }
                        }
                    });
                }

                // Check for potential HttpURLConnection usage for HTTPS (insecure default)
                if (mce.getNameAsString().equals("URL") &&
                    mce.getArguments().size() == 1) {
                    Expression arg0 = mce.getArgument(0);
                    if (arg0.isStringLiteralExpr()) {
                        String urlString = arg0.asStringLiteralExpr().getValue();
                        if (urlString.startsWith("http://") && !urlString.contains("localhost") && !urlString.contains("127.0.0.1")) { // Exclude localhost
                            System.out.println("[Line " + line + "] WARNING: URL constructed with 'http://' scheme: " + urlString + " - Ensure sensitive data is not sent over insecure HTTP. Severity: MEDIUM");
                        }
                    }
                }

                // NEW: Weak Hashing Algorithms (MD5, SHA-1)
                if (mce.getNameAsString().equals("getInstance") &&
                    mce.getScope().isPresent() &&
                    mce.getScope().get().toString().contains("MessageDigest") &&
                    mce.getArguments().size() >= 1) {
                    Expression arg0 = mce.getArgument(0);
                    if (arg0.isStringLiteralExpr()) {
                        String algorithm = arg0.asStringLiteralExpr().getValue().toLowerCase();
                        if (WEAK_HASHING_ALGORITHMS.contains(algorithm)) {
                            System.out.println("[Line " + line + "] ISSUE: Weak hashing algorithm used: " + algorithm.toUpperCase() + " - Use stronger algorithms like SHA-256 or SHA-512. Severity: HIGH");
                        }
                    }
                }

                // NEW: XML External Entity (XXE) Vulnerability - factory instantiation
                // Flagging instantiation and suggesting secure features
                if (mce.getNameAsString().equals("newInstance") &&
                    mce.getScope().isPresent() &&
                    XML_FACTORIES.contains(mce.getScope().get().toString())) {
                    System.out.println("[Line " + line + "] ISSUE: XML parsing factory created without explicit XXE hardening - Potentially vulnerable to XXE attacks. Ensure external entities and DTDs are disabled. Severity: CRITICAL");
                }


                return mce;
            }

            @Override
            public ObjectCreationExpr visit(ObjectCreationExpr oce, Void arg) {
                super.visit(oce, arg); // Call super to ensure full traversal

                int line = oce.getBegin().map(p -> p.line).orElse(-1);

                // Check for Anonymous X509TrustManager/TrustManager
                if (oce.getAnonymousClassBody().isPresent() &&
                    (oce.getType().getNameAsString().equals("X509TrustManager") ||
                     oce.getType().getNameAsString().equals("TrustManager"))) {

                    System.out.println("[Line " + line + "] ISSUE: Anonymous X509TrustManager/TrustManager detected - Verify implementation for proper certificate validation. Severity: CRITICAL");

                    oce.getAnonymousClassBody().get().forEach(bodyDeclaration -> {
                        if (bodyDeclaration instanceof MethodDeclaration) {
                            MethodDeclaration md = (MethodDeclaration) bodyDeclaration;
                            String methodName = md.getNameAsString();

                            if (("checkClientTrusted".equals(methodName) || "checkServerTrusted".equals(methodName)) && md.getBody().isPresent()) {
                                BlockStmt methodBody = md.getBody().get();
                                for (Statement stmt : methodBody.getStatements()) {
                                    if (stmt instanceof ReturnStmt) {
                                        ReturnStmt returnStmt = (ReturnStmt) stmt;
                                        if (returnStmt.getExpression().isPresent() &&
                                            returnStmt.getExpression().get().isBooleanLiteralExpr() &&
                                            returnStmt.getExpression().get().asBooleanLiteralExpr().getValue()) {
                                            System.out.println("  [Line " + line + "]  - Method '" + methodName + "' unconditionally returns true, implying no validation. Severity: CRITICAL");
                                            break;
                                        }
                                    } else if (stmt instanceof TryStmt) {
                                        TryStmt ts = (TryStmt) stmt;
                                        ts.getCatchClauses().forEach(catchClause -> {
                                            Type caughtType = catchClause.getParameter().getType();
                                            if (caughtType instanceof ClassOrInterfaceType) {
                                                String typeName = ((ClassOrInterfaceType) caughtType).getNameAsString();
                                                if (typeName.equals("Exception") || typeName.equals("Throwable") ||
                                                    typeName.equals("CertificateException") || typeName.equals("NoSuchAlgorithmException")) {
                                                    if (catchClause.getBody().getStatements().isEmpty() ||
                                                        (catchClause.getBody().getStatements().size() == 1 &&
                                                         catchClause.getBody().getStatement(0).isExpressionStmt() &&
                                                         catchClause.getBody().getStatement(0).asExpressionStmt().getExpression().isMethodCallExpr() &&
                                                         catchClause.getBody().getStatement(0).asExpressionStmt().getExpression().asMethodCallExpr().getNameAsString().equals("printStackTrace"))) {
                                                        System.out.println("  [Line " + line + "]  - Method '" + methodName + "' catches " + typeName + " and may swallow validation errors. Severity: CRITICAL");
                                                    }
                                                }
                                            }
                                        });
                                    }
                                }
                            }
                        }
                    });
                }

                // Check for Unseeded SecureRandom instance
                if (oce.getType().getNameAsString().equals("SecureRandom") &&
                    oce.getArguments().isEmpty()) {
                    System.out.println("[Line " + line + "] ISSUE: Unseeded SecureRandom instance - May lead to predictable keys or nonce values if not explicitly seeded. Severity: HIGH");
                }

                // Check for Anonymous HostnameVerifier
                if (oce.getAnonymousClassBody().isPresent() &&
                    oce.getType().getNameAsString().equals("HostnameVerifier")) {
                    System.out.println("[Line " + line + "] ISSUE: Anonymous HostnameVerifier detected - Verify implementation for proper hostname validation. Severity: CRITICAL");
                    oce.getAnonymousClassBody().get().forEach(bodyDeclaration -> {
                        if (bodyDeclaration instanceof MethodDeclaration) {
                            MethodDeclaration md = (MethodDeclaration) bodyDeclaration;
                            if (md.getNameAsString().equals("verify") && md.getBody().isPresent()) {
                                BlockStmt methodBody = md.getBody().get();
                                for (Statement stmt : methodBody.getStatements()) {
                                    if (stmt instanceof ReturnStmt) {
                                        ReturnStmt returnStmt = (ReturnStmt) stmt;
                                        if (returnStmt.getExpression().isPresent() &&
                                            returnStmt.getExpression().get().isBooleanLiteralExpr() &&
                                            returnStmt.getExpression().get().asBooleanLiteralExpr().getValue()) {
                                            System.out.println("  [Line " + line + "]  - Method 'verify' unconditionally returns true, implying no validation. Severity: CRITICAL");
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    });
                }

                // NEW: Hardcoded Cryptographic Keys/Salts
                if (oce.getType().getNameAsString().equals("SecretKeySpec") ||
                    oce.getType().getNameAsString().equals("IvParameterSpec")) {
                    boolean hasLiteralArgument = false;
                    for (Expression argExpr : oce.getArguments()) {
                        if (argExpr.isStringLiteralExpr() || (argExpr.isMethodCallExpr() && argExpr.asMethodCallExpr().getNameAsString().equals("getBytes"))) {
                            // Check for "hardcoded_key".getBytes() or similar
                            if (argExpr.isStringLiteralExpr() && argExpr.asStringLiteralExpr().getValue().toLowerCase().matches(HARDCODED_KEY_PATTERN)) {
                                hasLiteralArgument = true;
                                break;
                            } else if (argExpr.isMethodCallExpr() && argExpr.asMethodCallExpr().getScope().isPresent() && argExpr.asMethodCallExpr().getScope().get().isStringLiteralExpr() && argExpr.asMethodCallExpr().getScope().get().asStringLiteralExpr().getValue().toLowerCase().matches(HARDCODED_KEY_PATTERN)) {
                                hasLiteralArgument = true;
                                break;
                            }
                        } else if (argExpr.isArrayCreationExpr()) {
                             // Check for new byte[]{...} with suspicious values
                            ArrayCreationExpr ace = argExpr.asArrayCreationExpr();
                            if (ace.getInitializer().isPresent()) {
                                ArrayInitializerExpr init = ace.getInitializer().get();
                                for (Expression valExpr : init.getValues()) {
                                    if (valExpr.isIntegerLiteralExpr() || valExpr.isCharLiteralExpr() || valExpr.isStringLiteralExpr()) {
                                        hasLiteralArgument = true; // Flag any literal here, needs manual review
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if (hasLiteralArgument) {
                        System.out.println("[Line " + line + "] ISSUE: Potentially hardcoded cryptographic key/salt/IV in " + oce.getType().getNameAsString() + " initialization. Store sensitive keys securely (e.g., environment variables, KeyVault). Severity: CRITICAL");
                    }
                }

                // NEW: Deserialization of Untrusted Data
                if (oce.getType().getNameAsString().equals("ObjectInputStream")) {
                    System.out.println("[Line " + line + "] ISSUE: Deserialization of untrusted data via ObjectInputStream - Vulnerable to Remote Code Execution (RCE) if input is malicious. Avoid deserializing untrusted data. Severity: CRITICAL");
                }

                return oce;
            }

            @Override
            public WhileStmt visit(WhileStmt ws, Void arg) {
                super.visit(ws, arg);

                int line = ws.getBegin().map(p -> p.line).orElse(-1);

                if (ws.getCondition().isBooleanLiteralExpr() &&
                    ws.getCondition().asBooleanLiteralExpr().getValue()) {
                    System.out.println("[Line " + line + "] ISSUE: Potential infinite loop (while(true)) - Could indicate a DoS vulnerability if related to resource consumption. Severity: HIGH");
                }

                return ws;
            }

            @Override
            public VariableDeclarator visit(VariableDeclarator vd, Void arg) {
                super.visit(vd, arg);

                int line = vd.getBegin().map(p -> p.line).orElse(-1);

                // Weak cipher suites in array declaration
                if (vd.getType().isArrayType() &&
                    vd.getType().asArrayType().getComponentType().toString().equals("String") &&
                    vd.getInitializer().isPresent() &&
                    vd.getInitializer().get() instanceof ArrayInitializerExpr) {

                    ArrayInitializerExpr init = (ArrayInitializerExpr) vd.getInitializer().get();
                    
                    for (Expression expr : init.getValues()) {
                        if (expr.isStringLiteralExpr()) {
                            String value = expr.asStringLiteralExpr().getValue().toLowerCase();
                            if (WEAK_CIPHER_KEYWORDS.stream().anyMatch(value::contains)) {
                                System.out.println("[Line " + line + "] ISSUE: Weak cipher suite keyword detected in array: '" + value + "' - Use stronger cryptographic algorithms. Severity: CRITICAL");
                                break;
                            }
                        }
                    }
                }

                // Check for hardcoded password assigned to variable
                if (vd.getInitializer().isPresent() && vd.getInitializer().get().isStringLiteralExpr()) {
                    String val = vd.getInitializer().get().asStringLiteralExpr().getValue().toLowerCase();
                    if (val.matches(".*(password|pass|secret|key|pwd|123).*") && val.length() > 3) {
                        System.out.println("[Line " + line + "] ISSUE: Hardcoded password/sensitive string assigned to variable: '" + val + "' - Store credentials securely (e.g., environment variables, KeyVault). Severity: CRITICAL");
                    }
                }

                return vd;
            }

            @Override
            public TryStmt visit(TryStmt ts, Void arg) {
                super.visit(ts, arg);

                int line = ts.getBegin().map(p -> p.line).orElse(-1);

                ts.getCatchClauses().forEach(catchClause -> {
                    Type caughtType = catchClause.getParameter().getType();
                    if (caughtType instanceof ClassOrInterfaceType) {
                        String typeName = ((ClassOrInterfaceType) caughtType).getNameAsString();
                        if (typeName.equals("Exception") || typeName.equals("Throwable")) {
                            if (catchClause.getBody().getStatements().isEmpty() ||
                                (catchClause.getBody().getStatements().size() == 1 &&
                                 catchClause.getBody().getStatement(0).isExpressionStmt() &&
                                 catchClause.getBody().getStatement(0).asExpressionStmt().getExpression().isMethodCallExpr() &&
                                 catchClause.getBody().getStatement(0).asExpressionStmt().getExpression().asMethodCallExpr().getNameAsString().equals("printStackTrace"))) {
                                System.out.println("[Line " + line + "] WARNING: Overly broad catch for '" + typeName + "' with minimal error handling - May hide critical exceptions. Severity: MEDIUM");
                            }
                        }
                    }
                });
                return ts;
            }
        }, null);
    }
}
