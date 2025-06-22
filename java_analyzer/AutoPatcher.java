import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import com.github.javaparser.ast.visitor.ModifierVisitor;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.type.Type;

import java.io.FileInputStream;
import java.util.Arrays;
import java.util.List;

public class AutoPatcher {
    
    private static final List<String> INSECURE_PROTOCOLS = Arrays.asList(
        "sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"
    );
    
    private static final List<String> WEAK_CIPHER_KEYWORDS = Arrays.asList(
        "null", "anon", "export", "rc4", "des", "md5"
    );
    
    private static final String STRONG_CIPHERS = 
        "new String[]{\"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\", " +
        "\"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\"}";
    
    private static final String STRONG_PROTOCOLS = 
        "new String[]{\"TLSv1.2\", \"TLSv1.3\"}";

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("Usage: java AutoPatcher <JavaFile>");
            return;
        }

        System.err.println("\nPatching the file :" + args[0]); // Moved to stderr

        CompilationUnit cu = StaticJavaParser.parse(new FileInputStream(args[0]));
        cu.accept(new SecurityPatchVisitor(), null);
        System.out.println(cu);
    }

    private static class SecurityPatchVisitor extends ModifierVisitor<Void> {

        @Override
        public MethodCallExpr visit(MethodCallExpr mce, Void arg) {
            super.visit(mce, arg);
            int line = mce.getBegin().map(p -> p.line).orElse(-1);

            handleSystemProperties(mce, line);
            handleHostnameVerifier(mce, line);
            handleKeyStorePasswords(mce, line);
            handleSSLContext(mce, line);
            handleProtocols(mce, line);
            handleCipherSuites(mce, line);
            
            return mce;
        }

        private void handleSystemProperties(MethodCallExpr mce, int line) {
            if (mce.getNameAsString().equals("setProperty") && mce.getArguments().size() == 2) {
                Expression arg0 = mce.getArgument(0);
                if (arg0.isStringLiteralExpr()) {
                    String key = arg0.asStringLiteralExpr().getValue();
                    if (key.equals("javax.net.debug") || key.equals("com.ibm.jsse2.renegotiate")) {
                        logPatch(line, "Removed insecure system property: " + key);
                        mce.remove();
                    }
                }
            }
        }

        private void handleHostnameVerifier(MethodCallExpr mce, int line) {
            if (mce.getNameAsString().equals("setDefaultHostnameVerifier")) {
                mce.setArgument(0, StaticJavaParser.parseExpression(
                    "(hostname, session) -> hostname.equals(\"yourdomain.com\")"
                ));
                logPatch(line, "Replaced insecure HostnameVerifier with domain check");
            }
        }

        private void handleKeyStorePasswords(MethodCallExpr mce, int line) {
            if (mce.getNameAsString().equals("load") &&
                mce.getScope().isPresent() &&
                mce.getScope().get().toString().contains("KeyStore") &&
                mce.getArguments().size() == 2) {
                mce.setArgument(1, StaticJavaParser.parseExpression(
                    "System.getenv(\"KEYSTORE_PASSWORD\").toCharArray()"
                ));
                logPatch(line, "Replaced hardcoded KeyStore password with environment variable");
            }
        }

        private void handleSSLContext(MethodCallExpr mce, int line) {
            if (mce.getNameAsString().equals("getInstance") &&
                mce.getScope().isPresent() &&
                mce.getScope().get().toString().contains("SSLContext") &&
                mce.getArguments().size() >= 1) {
                
                Expression arg0 = mce.getArgument(0);
                if (arg0.isStringLiteralExpr()) {
                    String protocol = arg0.asStringLiteralExpr().getValue().toLowerCase();
                    if (INSECURE_PROTOCOLS.contains(protocol)) {
                        mce.setArgument(0, StaticJavaParser.parseExpression("\"TLSv1.2\""));
                        logPatch(line, "Upgraded insecure SSLContext protocol to TLSv1.2");
                    }
                }
            }
        }

        private void handleProtocols(MethodCallExpr mce, int line) {
            if (mce.getNameAsString().equals("setEnabledProtocols") &&
                mce.getScope().isPresent() &&
                (mce.getScope().get().toString().contains("SSLSocket") || 
                 mce.getScope().get().toString().contains("SSLEngine"))) {
                
                if (containsInsecureProtocols(mce.getArgument(0))) {
                    mce.setArgument(0, StaticJavaParser.parseExpression(STRONG_PROTOCOLS));
                    logPatch(line, "Replaced insecure protocols with TLSv1.2/TLSv1.3");
                }
            }
        }

        private void handleCipherSuites(MethodCallExpr mce, int line) {
            if (mce.getNameAsString().equals("setEnabledCipherSuites") &&
                mce.getScope().isPresent() &&
                (mce.getScope().get().toString().contains("SSLSocket") || 
                 mce.getScope().get().toString().contains("SSLEngine"))) {
                
                if (containsWeakCiphers(mce.getArgument(0))) {
                    mce.setArgument(0, StaticJavaParser.parseExpression(STRONG_CIPHERS));
                    logPatch(line, "Replaced weak cipher suites with strong defaults");
                }
            }
        }

        private boolean containsInsecureProtocols(Expression expr) {
            return checkExpressionValues(expr, INSECURE_PROTOCOLS::contains);
        }

        private boolean containsWeakCiphers(Expression expr) {
            return checkExpressionValues(expr, 
                value -> WEAK_CIPHER_KEYWORDS.stream().anyMatch(value::contains));
        }

        private boolean checkExpressionValues(Expression expr, java.util.function.Predicate<String> checker) {
            if (expr.isArrayCreationExpr()) {
                return expr.asArrayCreationExpr().getInitializer()
                    .map(init -> init.getValues().stream()
                        .filter(Expression::isStringLiteralExpr)
                        .map(e -> e.asStringLiteralExpr().getValue().toLowerCase())
                        .anyMatch(checker))
                    .orElse(false);
            }
            if (expr.isArrayInitializerExpr()) {
                return expr.asArrayInitializerExpr().getValues().stream()
                    .filter(Expression::isStringLiteralExpr)
                    .map(e -> e.asStringLiteralExpr().getValue().toLowerCase())
                    .anyMatch(checker);
            }
            if (expr.isStringLiteralExpr()) {
                return checker.test(expr.asStringLiteralExpr().getValue().toLowerCase());
            }
            return false;
        }

        @Override
        public ObjectCreationExpr visit(ObjectCreationExpr oce, Void arg) {
            super.visit(oce, arg);
            int line = oce.getBegin().map(p -> p.line).orElse(-1);

            // Patch insecure TrustManager implementations
            if (oce.getAnonymousClassBody().isPresent() &&
                (oce.getType().getNameAsString().equals("X509TrustManager") ||
                 oce.getType().getNameAsString().equals("TrustManager"))) {
                
                oce.getAnonymousClassBody().get().forEach(bodyDecl -> {
                    if (bodyDecl instanceof MethodDeclaration) {
                        MethodDeclaration md = (MethodDeclaration) bodyDecl;
                        if (md.getNameAsString().matches("check(Client|Server)Trusted")) {
                            md.setBody(StaticJavaParser.parseBlock(
                                "{ throw new java.security.cert.CertificateException(\"Insecure TrustManager patched\"); }"
                            ));
                        }
                    }
                });
                logPatch(line, "Replaced insecure TrustManager implementation");
            }

            // Patch unseeded SecureRandom
            if (oce.getType().getNameAsString().equals("SecureRandom") && 
                oce.getArguments().isEmpty()) {
                oce.replace(StaticJavaParser.parseExpression("SecureRandom.getInstanceStrong()"));
                logPatch(line, "Replaced unseeded SecureRandom with getInstanceStrong()");
            }

            return oce;
        }

        @Override
        public VariableDeclarator visit(VariableDeclarator vd, Void arg) {
            super.visit(vd, arg);
            int line = vd.getBegin().map(p -> p.line).orElse(-1);

            // Patch hardcoded credentials
            if (vd.getInitializer().isPresent() && 
                vd.getInitializer().get().isStringLiteralExpr()) {
                
                String value = vd.getInitializer().get().asStringLiteralExpr().getValue();
                if (value.matches(".*(pass|secret|key|pwd).*")) {
                    vd.setInitializer(StaticJavaParser.parseExpression(
                        "System.getenv(\"" + vd.getNameAsString().toUpperCase() + "_SECRET\")"
                    ));
                    logPatch(line, "Replaced hardcoded secret with environment variable");
                }
            }

            // Patch weak cipher array declarations
            if (vd.getInitializer().isPresent() &&
                vd.getInitializer().get().isArrayInitializerExpr()) {
                
                ArrayInitializerExpr init = vd.getInitializer().get().asArrayInitializerExpr();
                if (containsWeakCiphers(init)) {
                    vd.setInitializer(StaticJavaParser.parseExpression(STRONG_CIPHERS));
                    logPatch(line, "Replaced weak cipher array with strong defaults");
                }
            }

            return vd;
        }

        private void logPatch(int line, String message) {
            System.err.printf("[Line %d] PATCHED: %s%n", line, message);
        }
    }
}
