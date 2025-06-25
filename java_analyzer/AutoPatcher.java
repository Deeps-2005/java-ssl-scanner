import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import com.github.javaparser.ast.visitor.ModifierVisitor;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.type.Type;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map; // Import for Map
import java.util.LinkedHashMap; // Import for LinkedHashMap to maintain order
import java.util.ArrayList; // Import for ArrayList
import java.util.Comparator; // Import for Comparator

public class AutoPatcher {

    // Lists for quick lookup, shared across methods to reduce object creation
    private static final List<String> INSECURE_PROTOCOLS = Arrays.asList("sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1");
    private static final List<String> WEAK_CIPHER_KEYWORDS = Arrays.asList("null", "anon", "export", "rc4", "des", "md5");

    // Using LinkedHashMap to maintain insertion order for more readable logs
    private static Map<Integer, String> patchLogs = new LinkedHashMap<>(); // Store logs here

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("Usage: java AutoPatcher <JavaFile>"); // Print usage to stderr
            System.err.println("This tool attempts to automatically patch known SSL/JSSE vulnerabilities.");
            System.err.println("The patched code will be printed to standard output.");
            return;
        }

        String filePath = args[0];
        CompilationUnit cu;
        try (FileInputStream in = new FileInputStream(filePath)) {
            cu = StaticJavaParser.parse(in);
        } catch (IOException e) {
            System.err.println("Error reading file: " + filePath + " - " + e.getMessage());
            return;
        }

        System.err.println("Attempting to patch: " + filePath); // Print status to stderr

        // Apply patches using the visitor
        cu.accept(new SecurityPatchVisitor(), null);

        // Print ONLY the patched code to standard output (stdout)
        System.out.println(cu.toString());

        // Print patch logs to standard error (stderr), wrapped in markers
        System.err.println("--- PATCH LOG START ---");
        // Sort logs by line number before printing for consistent output
        List<Map.Entry<Integer, String>> sortedLogs = new ArrayList<>(patchLogs.entrySet());
        sortedLogs.sort(Comparator.comparingInt(Map.Entry::getKey));

        for (Map.Entry<Integer, String> entry : sortedLogs) {
            System.err.println("Line " + entry.getKey() + ": " + entry.getValue());
        }
        System.err.println("--- PATCH LOG END ---");
    }

    private static class SecurityPatchVisitor extends ModifierVisitor<Void> {

        /**
         * Helper method to record patch logs.
         * @param line The line number where the patch was applied.
         * @param message A description of the patch.
         */
        private void logPatch(int line, String message) {
            patchLogs.put(line, message);
        }

        /**
         * Visits MethodCallExpr nodes to apply patches related to method calls.
         * This includes system property settings, protocol enabling, hostname verification,
         * and keystore password loading.
         *
         * @param mce The MethodCallExpr node being visited.
         * @param arg A generic argument (not used here).
         * @return The modified MethodCallExpr (or null if the node is removed).
         */
        @Override
        public MethodCallExpr visit(MethodCallExpr mce, Void arg) {
            super.visit(mce, arg); // Call super to ensure full traversal and allow nested modifications

            // 1. Patch: Remove debug logging and TLS renegotiation system properties
            if (mce.getNameAsString().equals("setProperty") &&
                mce.getArguments().size() == 2) {
                Expression arg0 = mce.getArgument(0);
                if (arg0.isStringLiteralExpr()) {
                    String key = arg0.asStringLiteralExpr().getValue();
                    if (key.equals("javax.net.debug") || key.equals("com.ibm.jsse2.renegotiate")) {
                        logPatch(mce.getBegin().map(p -> p.line).orElse(-1), "Removed System.setProperty(\"" + key + "\", ...)");
                        return null; // Removing the method call expression
                    }
                }
            }

            // 2. Patch: Insecure HostnameVerifier (lambda or anonymous class always returns true)
            if (mce.getNameAsString().equals("setDefaultHostnameVerifier") &&
                mce.getArguments().size() == 1) {
                Expression argExpr = mce.getArgument(0);
                boolean patched = false;

                if (argExpr.isLambdaExpr()) {
                    LambdaExpr lambda = argExpr.asLambdaExpr();
                    if ((lambda.getBody().isExpressionStmt() && lambda.getBody().asExpressionStmt().getExpression().isBooleanLiteralExpr() &&
                         lambda.getBody().asExpressionStmt().getExpression().asBooleanLiteralExpr().getValue()) ||
                        (lambda.getBody().isBlockStmt() && lambda.getBody().asBlockStmt().getStatements().stream()
                            .filter(stmt -> stmt instanceof ReturnStmt)
                            .map(stmt -> (ReturnStmt) stmt)
                            .anyMatch(returnStmt -> returnStmt.getExpression().isPresent() && returnStmt.getExpression().get().isBooleanLiteralExpr() &&
                                                     returnStmt.getExpression().get().asBooleanLiteralExpr().getValue()))) {
                        mce.setArgument(0, StaticJavaParser.parseExpression("(hostname, session) -> hostname.equals(\"yourdomain.com\")"));
                        patched = true;
                    }
                } else if (argExpr.isObjectCreationExpr()) {
                    ObjectCreationExpr oce = argExpr.asObjectCreationExpr();
                    if (oce.getType().getNameAsString().equals("HostnameVerifier") && oce.getAnonymousClassBody().isPresent()) {
                        if (oce.getAnonymousClassBody().get().stream()
                            .filter(bodyDecl -> bodyDecl instanceof MethodDeclaration)
                            .map(bodyDecl -> (MethodDeclaration) bodyDecl)
                            .filter(md -> md.getNameAsString().equals("verify") && md.getBody().isPresent())
                            .anyMatch(md -> md.getBody().get().getStatements().isEmpty() ||
                                            md.getBody().get().getStatements().stream()
                                                .filter(stmt -> stmt instanceof ReturnStmt)
                                                .map(stmt -> (ReturnStmt) stmt)
                                                .anyMatch(returnStmt -> returnStmt.getExpression().isPresent() && returnStmt.getExpression().get().isBooleanLiteralExpr() &&
                                                                         returnStmt.getExpression().get().asBooleanLiteralExpr().getValue()))) {
                            mce.setArgument(0, StaticJavaParser.parseExpression("(hostname, session) -> hostname.equals(\"yourdomain.com\")"));
                            patched = true;
                        }
                    }
                }
                if (patched) {
                    logPatch(mce.getBegin().map(p -> p.line).orElse(-1), "Insecure HostnameVerifier replaced with domain check.");
                }
            }

            // 3. Patch: Hardcoded password passed to keystore load()
            if (mce.getNameAsString().equals("load") &&
                mce.getScope().isPresent() &&
                mce.getScope().get().toString().contains("KeyStore") &&
                mce.getArguments().size() == 2 &&
                (mce.getArgument(1).isCharLiteralExpr() || mce.getArgument(1).isStringLiteralExpr())) {
                logPatch(mce.getBegin().map(p -> p.line).orElse(-1), "Hardcoded password in KeyStore.load() replaced with environment variable lookup.");
                mce.setArgument(1, StaticJavaParser.parseExpression("System.getenv(\"KEYSTORE_PASSWORD\").toCharArray()"));
            }

            // 4. Patch: Use of outdated/weak SSL/TLS protocols in SSLContext.getInstance()
            if (mce.getNameAsString().equals("getInstance") &&
                mce.getScope().isPresent() &&
                mce.getScope().get().toString().contains("SSLContext") &&
                mce.getArguments().size() >= 1 &&
                mce.getArgument(0).isStringLiteralExpr()) {
                String protocol = mce.getArgument(0).asStringLiteralExpr().getValue().toLowerCase();
                if (INSECURE_PROTOCOLS.contains(protocol)) {
                    logPatch(mce.getBegin().map(p -> p.line).orElse(-1), "Insecure SSLContext protocol '" + protocol.toUpperCase() + "' changed to 'TLSv1.2'.");
                    mce.setArgument(0, StaticJavaParser.parseExpression("\"TLSv1.2\""));
                }
            }

            // 5. Patch: Enabling weak/outdated protocols via setEnabledProtocols()
            if (mce.getNameAsString().equals("setEnabledProtocols") &&
                mce.getScope().isPresent() &&
                (mce.getScope().get().toString().contains("SSLSocket") || mce.getScope().get().toString().contains("SSLEngine"))) {
                
                Expression protocolsArg = mce.getArgument(0);
                boolean shouldPatch = false;

                if (protocolsArg.isArrayInitializerExpr()) {
                    ArrayInitializerExpr init = protocolsArg.asArrayInitializerExpr();
                    for (Expression expr : init.getValues()) {
                        if (expr.isStringLiteralExpr()) {
                            String protocol = expr.asStringLiteralExpr().getValue().toLowerCase();
                            if (INSECURE_PROTOCOLS.contains(protocol)) {
                                shouldPatch = true;
                                break;
                            }
                        }
                    }
                } else if (protocolsArg.isStringLiteralExpr()) {
                    String protocol = protocolsArg.asStringLiteralExpr().getValue().toLowerCase();
                    if (INSECURE_PROTOCOLS.contains(protocol)) {
                        shouldPatch = true;
                    }
                }
                
                if (shouldPatch) {
                    logPatch(mce.getBegin().map(p -> p.line).orElse(-1), "setEnabledProtocols() to use only 'TLSv1.2' and 'TLSv1.3'.");
                    mce.setArgument(0, StaticJavaParser.parseExpression("new String[]{\"TLSv1.2\", \"TLSv1.3\"}"));
                }
            }

            return mce;
        }

        /**
         * Visits ObjectCreationExpr nodes to apply patches during object instantiation.
         * This includes insecure TrustManager implementations and unseeded SecureRandom.
         *
         * @param oce The ObjectCreationExpr node being visited.
         * @param arg A generic argument (not used here).
         * @return The modified ObjectCreationExpr.
         */
        @Override
        public ObjectCreationExpr visit(ObjectCreationExpr oce, Void arg) {
            super.visit(oce, arg); // Call super to ensure full traversal

            // 6. Patch: Insecure TrustManager (anonymous class with empty methods or return true)
            if (oce.getAnonymousClassBody().isPresent() &&
                (oce.getType().getNameAsString().equals("X509TrustManager") ||
                 oce.getType().getNameAsString().equals("TrustManager"))) {

                boolean patchedTrustManager = false;
                for (BodyDeclaration bodyDecl : oce.getAnonymousClassBody().get()) {
                    if (bodyDecl instanceof MethodDeclaration) {
                        MethodDeclaration md = (MethodDeclaration) bodyDecl;
                        String methodName = md.getNameAsString();

                        if (("checkClientTrusted".equals(methodName) || "checkServerTrusted".equals(methodName)) && md.getBody().isPresent()) {
                            BlockStmt methodBody = md.getBody().get();
                            boolean foundInsecurePattern = false;

                            // Check for empty body or body with 'return true'
                            if (methodBody.getStatements().isEmpty() ||
                                methodBody.getStatements().stream()
                                    .filter(stmt -> stmt instanceof ReturnStmt)
                                    .map(stmt -> (ReturnStmt) stmt)
                                    .anyMatch(returnStmt -> returnStmt.getExpression().isPresent() && returnStmt.getExpression().get().isBooleanLiteralExpr() &&
                                                             returnStmt.getExpression().get().asBooleanLiteralExpr().getValue())) {
                                foundInsecurePattern = true;
                            }

                            if (foundInsecurePattern) {
                                logPatch(md.getBegin().map(p -> p.line).orElse(-1), "Insecure TrustManager method '" + methodName + "' patched to throw CertificateException.");
                                md.setBody(StaticJavaParser.parseBlock("{ throw new java.security.cert.CertificateException(\"Insecure TrustManager automatically patched: Manual review required.\"); }"));
                                patchedTrustManager = true;
                            }
                        }
                    }
                }
            }

            return oce;
        }

        /**
         * Visits VariableDeclarator nodes to apply patches related to variable declarations.
         * This includes hardcoded passwords and weak cipher suites arrays, and SecureRandom initialization.
         *
         * @param vd The VariableDeclarator node being visited.
         * @param arg A generic argument (not used here).
         * @return The modified VariableDeclarator.
         */
        @Override
        public VariableDeclarator visit(VariableDeclarator vd, Void arg) {
            super.visit(vd, arg); // Call super to ensure full traversal

            // 7. Patch: Unseeded SecureRandom instance
            if (vd.getType() instanceof ClassOrInterfaceType) {
                ClassOrInterfaceType classType = (ClassOrInterfaceType) vd.getType();
                if (classType.getNameAsString().equals("SecureRandom") &&
                    vd.getInitializer().isPresent() &&
                    vd.getInitializer().get().isObjectCreationExpr()) {
                    ObjectCreationExpr oce = vd.getInitializer().get().asObjectCreationExpr();
                    if (oce.getType().getNameAsString().equals("SecureRandom") && oce.getArguments().isEmpty()) {
                        logPatch(vd.getBegin().map(p -> p.line).orElse(-1), "Unseeded SecureRandom replaced with SecureRandom.getInstanceStrong() for variable: " + vd.getNameAsString());
                        vd.setInitializer(StaticJavaParser.parseExpression("SecureRandom.getInstanceStrong()"));
                    }
                }
            }

            // 8. Patch: Hardcoded password assigned to variable
            if (vd.getInitializer().isPresent() && vd.getInitializer().get().isStringLiteralExpr()) {
                String val = vd.getInitializer().get().asStringLiteralExpr().getValue().toLowerCase();
                if (val.matches(".*(password|pass|secret|key|pwd|123).*") && val.length() > 3) {
                    logPatch(vd.getBegin().map(p -> p.line).orElse(-1), "Hardcoded sensitive string assigned to variable '" + vd.getNameAsString() + "' replaced with environment lookup.");
                    vd.setInitializer(StaticJavaParser.parseExpression("System.getenv(\"APP_SENSITIVE_DATA\")"));
                }
            }

            // 9. Patch: Weak cipher suites in array initialization
            if (vd.getType().isArrayType() &&
                vd.getType().asArrayType().getComponentType().toString().equals("String") &&
                vd.getInitializer().isPresent() &&
                vd.getInitializer().get() instanceof ArrayInitializerExpr) {

                ArrayInitializerExpr init = (ArrayInitializerExpr) vd.getInitializer().get();
                
                boolean weak = init.getValues().stream()
                        .filter(Expression::isStringLiteralExpr)
                        .map(expr -> expr.asStringLiteralExpr().getValue().toLowerCase())
                        .anyMatch(val -> WEAK_CIPHER_KEYWORDS.stream().anyMatch(val::contains));

                if (weak) {
                    logPatch(vd.getBegin().map(p -> p.line).orElse(-1), "Weak cipher suites array replaced with strong defaults.");
                    vd.setInitializer(StaticJavaParser.parseExpression("new String[]{\"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\", \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\"}"));
                }
            }

            return vd;
        }

        // Note: Patching `WhileStmt` (infinite loops for DoS) and `TryStmt` (overly broad catches)
        // are typically too risky or complex for automated static patching without deeper semantic
        // understanding and are left for manual review.
    }
}
