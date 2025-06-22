@echo off
setlocal enabledelayedexpansion

:: Configuration
set JAVAPARSER_JAR=javaparser-core-3.26.4.jar
set ANALYZER_SRC=Analyzer.java
set ANALYZER_CLASS=Analyzer.class
set ANALYZER_JAR=analyzer.jar
set TEST_FILE=TestInput.java

:: Clean up
echo 🔄 Cleaning previous files...
del /Q %ANALYZER_CLASS% Analyzer$1.class %ANALYZER_JAR% %TEST_FILE% 2>nul

:: Compile
echo 🔨 Compiling Analyzer.java...
javac -cp %JAVAPARSER_JAR% %ANALYZER_SRC%
if errorlevel 1 (
    echo ❌ Compilation failed!
    exit /b 1
)

:: Package into JAR
echo 📦 Creating %ANALYZER_JAR%...
jar cfe %ANALYZER_JAR% Analyzer Analyzer*.class

if errorlevel 1 (
    echo ❌ JAR creation failed!
    exit /b 1
)

:: Create TestInput.java line by line (no parentheses!)
echo 🧪 Creating %TEST_FILE%...
echo. import javax.net.ssl; >> %TEST_FILE%
echo. import java.security.cert.X509Certificate; >> %TEST_FILE%
echo. public class TestInput ^{ >> %TEST_FILE%
echo.     public static void main(String[] args) ^{ >> %TEST_FILE%
echo.         TrustManager[] trustAll = new TrustManager[] ^{ >> %TEST_FILE%
echo.             new X509TrustManager() ^{ >> %TEST_FILE%
echo.                 public X509Certificate[] getAcceptedIssuers() ^{ return null; ^} >> %TEST_FILE%
echo.                 public void checkClientTrusted(X509Certificate[] certs, String authType) ^{ ^} >> %TEST_FILE%
echo.                 public void checkServerTrusted(X509Certificate[] certs, String authType) ^{ ^} >> %TEST_FILE%
echo.             } >> %TEST_FILE%
echo.         }; >> %TEST_FILE%
echo.     } >> %TEST_FILE%
echo. } >> %TEST_FILE%

:: Run analyzer
echo 🚀 Running analyzer on %TEST_FILE%...
java -cp %ANALYZER_JAR%;%JAVAPARSER_JAR% Analyzer %TEST_FILE%
if errorlevel 1 (
    echo ❌ Analyzer failed!
    exit /b 1
)

echo ✅ Analyzer ran successfully!
endlocal
