import com.github.javaparser.*;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import com.github.javaparser.ast.visitor.ModifierVisitor;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.type.Type;

import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.List;

public class Analyzer {

    // List of known insecure protocols for quick lookup
    private static final List<String> INSECURE_PROTOCOLS = Arrays.asList("sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1");
    // List of keywords for weak cipher suites
    private static final List<String> WEAK_CIPHER_KEYWORDS = Arrays.asList("null", "anon", "export", "rc4", "des", "md5");

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Usage: java Analyzer <JavaSourceFile>");
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

        System.out.println("\nAnalyzing File: " + args[0]);
        CompilationUnit cu = StaticJavaParser.parse(new FileInputStream(file));

        cu.accept(new ModifierVisitor<Void>() {

            @Override
            public MethodCallExpr visit(MethodCallExpr mce, Void arg) {
                super.visit(mce, arg);
                int line = mce.getBegin().map(p -> p.line).orElse(-1);

                // System.setProperty checks
                if (mce.getNameAsString().equals("setProperty") && mce.getArguments().size() == 2) {
                    Expression arg0 = mce.getArgument(0);
                    if (arg0.isStringLiteralExpr()) {
                        String propName = arg0.asStringLiteralExpr().getValue();
                        if (propName.contains("javax.net.debug")) {
                            System.out.println("[Line " + line + "] ISSUE: Debug logging enabled (javax.net.debug) - Exposes sensitive SSL/TLS handshaking details.");
                        }
                        if (propName.contains("com.ibm.jsse2.renegotiate")) {
                            System.out.println("[Line " + line + "] ISSUE: TLS renegotiation potentially enabled - Can be abused for DoS attacks.");
                        }
                    }
                }

                // HostnameVerifier checks
                if (mce.getNameAsString().equals("setDefaultHostnameVerifier") && mce.getArguments().size() == 1) {
                    Expression arg0 = mce.getArgument(0);
                    if (arg0.isLambdaExpr()) {
                        LambdaExpr lambda = arg0.asLambdaExpr();
                        if (lambda.getBody().isExpressionStmt() &&
                            lambda.getBody().asExpressionStmt().getExpression().isBooleanLiteralExpr() &&
                            lambda.getBody().asExpressionStmt().getExpression().asBooleanLiteralExpr().getValue()) {
                            System.out.println("[Line " + line + "] ISSUE: Insecure HostnameVerifier (lambda always returns true) - Bypasses hostname validation, vulnerable to MITM.");
                        } else if (lambda.getBody().isBlockStmt()) {
                            BlockStmt block = lambda.getBody().asBlockStmt();
                            for (Statement stmt : block.getStatements()) {
                                if (stmt instanceof ReturnStmt) {
                                    ReturnStmt returnStmt = (ReturnStmt) stmt;
                                    if (returnStmt.getExpression().isPresent() &&
                                        returnStmt.getExpression().get().isBooleanLiteralExpr() &&
                                        returnStmt.getExpression().get().asBooleanLiteralExpr().getValue()) {
                                        System.out.println("[Line " + line + "] ISSUE: Insecure HostnameVerifier (lambda block always returns true) - Bypasses hostname validation, vulnerable to MITM.");
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                // Hardcoded password in KeyStore.load()
                if (mce.getNameAsString().equals("load") &&
                    mce.getScope().isPresent() &&
                    mce.getScope().get().toString().contains("KeyStore") &&
                    mce.getArguments().size() == 2 &&
                    (mce.getArgument(1).isCharLiteralExpr() || mce.getArgument(1).isStringLiteralExpr())) {
                    System.out.println("[Line " + line + "] ISSUE: Hardcoded literal password passed to KeyStore.load() - Sensitive info in source code.");
                }

                // Outdated/weak SSL/TLS protocols in SSLContext.getInstance()
                if (mce.getNameAsString().equals("getInstance") &&
                    mce.getScope().isPresent() &&
                    mce.getScope().get().toString().contains("SSLContext") &&
                    mce.getArguments().size() >= 1) {
                    Expression arg0 = mce.getArgument(0);
                    if (arg0.isStringLiteralExpr()) {
                        String protocol = arg0.asStringLiteralExpr().getValue().toLowerCase();
                        if (INSECURE_PROTOCOLS.contains(protocol)) {
                            System.out.println("[Line " + line + "] ISSUE: Insecure SSL/TLS protocol requested: " + protocol.toUpperCase() + " - Known vulnerabilities exist.");
                        }
                    }
                }

                // setEnabledProtocols() check
                if (mce.getNameAsString().equals("setEnabledProtocols") &&
                    mce.getScope().isPresent() &&
                    (mce.getScope().get().toString().contains("SSLSocket") || mce.getScope().get().toString().contains("SSLEngine"))) {
                    mce.getArguments().forEach(argExpr -> {
                        if (argExpr.isArrayInitializerExpr()) {
                            argExpr.asArrayInitializerExpr().getValues().forEach(protoExpr -> {
                                if (protoExpr.isStringLiteralExpr()) {
                                    String protocol = protoExpr.asStringLiteralExpr().getValue().toLowerCase();
                                    if (INSECURE_PROTOCOLS.contains(protocol)) {
                                        System.out.println("[Line " + line + "] ISSUE: Insecure SSL/TLS protocol enabled via setEnabledProtocols(): " + protocol.toUpperCase() + " - Known vulnerabilities exist.");
                                    }
                                }
                            });
                        } else if (argExpr.isStringLiteralExpr()) {
                            String protocol = argExpr.asStringLiteralExpr().getValue().toLowerCase();
                            if (INSECURE_PROTOCOLS.contains(protocol)) {
                                System.out.println("[Line " + line + "] ISSUE: Insecure SSL/TLS protocol enabled via setEnabledProtocols(): " + protocol.toUpperCase() + " - Known vulnerabilities exist.");
                            }
                        }
                    });
                }

                // --- FIXED: setEnabledCipherSuites() now handles ArrayCreationExpr ---
                if (mce.getNameAsString().equals("setEnabledCipherSuites") &&
                    mce.getScope().isPresent() &&
                    (mce.getScope().get().toString().contains("SSLSocket") || mce.getScope().get().toString().contains("SSLEngine"))) {
                    mce.getArguments().forEach(argExpr -> {
                        // Handles: setEnabledCipherSuites(new String[] { ... })
                        if (argExpr.isArrayCreationExpr()) {
                            ArrayCreationExpr ace = argExpr.asArrayCreationExpr();
                            if (ace.getInitializer().isPresent()) {
                                ArrayInitializerExpr init = ace.getInitializer().get();
                                for (Expression cipherExpr : init.getValues()) {
                                    if (cipherExpr.isStringLiteralExpr()) {
                                        String cipherSuite = cipherExpr.asStringLiteralExpr().getValue().toLowerCase();
                                        if (WEAK_CIPHER_KEYWORDS.stream().anyMatch(cipherSuite::contains)) {
                                            System.out.println("[Line " + line + "] ISSUE: Weak cipher suite enabled via setEnabledCipherSuites(): " + cipherSuite.toUpperCase() + " - Use stronger cryptographic algorithms.");
                                        }
                                    }
                                }
                            }
                        // Handles: setEnabledCipherSuites({"A", "B"})
                        } else if (argExpr.isArrayInitializerExpr()) {
                            argExpr.asArrayInitializerExpr().getValues().forEach(cipherExpr -> {
                                if (cipherExpr.isStringLiteralExpr()) {
                                    String cipherSuite = cipherExpr.asStringLiteralExpr().getValue().toLowerCase();
                                    if (WEAK_CIPHER_KEYWORDS.stream().anyMatch(cipherSuite::contains)) {
                                        System.out.println("[Line " + line + "] ISSUE: Weak cipher suite enabled via setEnabledCipherSuites(): " + cipherSuite.toUpperCase() + " - Use stronger cryptographic algorithms.");
                                    }
                                }
                            });
                        // Handles: setEnabledCipherSuites("A")
                        } else if (argExpr.isStringLiteralExpr()) {
                            String cipherSuite = argExpr.asStringLiteralExpr().getValue().toLowerCase();
                            if (WEAK_CIPHER_KEYWORDS.stream().anyMatch(cipherSuite::contains)) {
                                System.out.println("[Line " + line + "] ISSUE: Weak cipher suite enabled via setEnabledCipherSuites(): " + cipherSuite.toUpperCase() + " - Use stronger cryptographic algorithms.");
                            }
                        }
                    });
                }

                // URL usage (HTTP)
                if (mce.getNameAsString().equals("URL") && mce.getArguments().size() == 1) {
                    Expression arg0 = mce.getArgument(0);
                    if (arg0.isStringLiteralExpr()) {
                        String urlString = arg0.asStringLiteralExpr().getValue();
                        if (urlString.startsWith("http://") && !urlString.contains("localhost")) {
                            System.out.println("[Line " + line + "] WARNING: URL constructed with 'http://' scheme: " + urlString + " - Ensure sensitive data is not sent over insecure HTTP.");
                        }
                    }
                }

                return mce;
            }

            @Override
            public ObjectCreationExpr visit(ObjectCreationExpr oce, Void arg) {
                super.visit(oce, arg);
                int line = oce.getBegin().map(p -> p.line).orElse(-1);

                // Anonymous X509TrustManager/TrustManager
                if (oce.getAnonymousClassBody().isPresent() &&
                    (oce.getType().getNameAsString().equals("X509TrustManager") ||
                     oce.getType().getNameAsString().equals("TrustManager"))) {
                    System.out.println("[Line " + line + "] ISSUE: Anonymous X509TrustManager/TrustManager detected - Verify implementation for proper certificate validation.");
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
                                            System.out.println(" [Line " + line + "] - Method '" + methodName + "' unconditionally returns true, implying no validation.");
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
                                                        System.out.println(" [Line " + line + "] - Method '" + methodName + "' catches " + typeName + " and may swallow validation errors.");
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

                // Unseeded SecureRandom instance
                if (oce.getType().getNameAsString().equals("SecureRandom") &&
                    oce.getArguments().isEmpty()) {
                    System.out.println("[Line " + line + "] ISSUE: Unseeded SecureRandom instance - May lead to predictable keys or nonce values if not explicitly seeded.");
                }

                // Anonymous HostnameVerifier
                if (oce.getAnonymousClassBody().isPresent() &&
                    oce.getType().getNameAsString().equals("HostnameVerifier")) {
                    System.out.println("[Line " + line + "] ISSUE: Anonymous HostnameVerifier detected - Verify implementation for proper hostname validation.");
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
                                            System.out.println(" [Line " + line + "] - Method 'verify' unconditionally returns true, implying no validation.");
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    });
                }

                return oce;
            }

            @Override
            public WhileStmt visit(WhileStmt ws, Void arg) {
                super.visit(ws, arg);
                int line = ws.getBegin().map(p -> p.line).orElse(-1);
                if (ws.getCondition().isBooleanLiteralExpr() &&
                    ws.getCondition().asBooleanLiteralExpr().getValue()) {
                    System.out.println("[Line " + line + "] ISSUE: Potential infinite loop (while(true)) - Could indicate a DoS vulnerability if related to SSL/TLS operations.");
                }
                return ws;
            }

            @Override
            public VariableDeclarator visit(VariableDeclarator vd, Void arg) {
                super.visit(vd, arg);
                int line = vd.getBegin().map(p -> p.line).orElse(-1);

                // Weak cipher suites defined as array variable
                if (vd.getType().isArrayType() &&
                    vd.getType().asArrayType().getComponentType().toString().equals("String") &&
                    vd.getInitializer().isPresent() &&
                    vd.getInitializer().get() instanceof ArrayInitializerExpr) {
                    ArrayInitializerExpr init = (ArrayInitializerExpr) vd.getInitializer().get();
                    for (Expression expr : init.getValues()) {
                        if (expr.isStringLiteralExpr()) {
                            String value = expr.asStringLiteralExpr().getValue().toLowerCase();
                            if (WEAK_CIPHER_KEYWORDS.stream().anyMatch(value::contains)) {
                                System.out.println("[Line " + line + "] ISSUE: Weak cipher suite keyword detected in array: '" + value + "' - Use stronger cryptographic algorithms.");
                                break;
                            }
                        }
                    }
                }

                // Hardcoded password assigned to variable
                if (vd.getInitializer().isPresent() && vd.getInitializer().get().isStringLiteralExpr()) {
                    String val = vd.getInitializer().get().asStringLiteralExpr().getValue().toLowerCase();
                    if (val.matches(".*(password|pass|secret|key|pwd|123).*") && val.length() > 3) {
                        System.out.println("[Line " + line + "] ISSUE: Hardcoded password/sensitive string assigned to variable: '" + val + "' - Store credentials securely (e.g., environment variables, KeyVault).");
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
                                System.out.println("[Line " + line + "] WARNING: Overly broad catch for '" + typeName + "' with minimal error handling - May hide critical SSL/TLS exceptions.");
                            }
                        }
                    }
                });
                return ts;
            }

        }, null);
    }
}
