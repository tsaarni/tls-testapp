// https://www.java.com/en/configure_crypto.html
// https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
// https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html
// https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html
// https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html

package testapp;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;

public class Ciphers {

    public static void main(String[] args) throws NoSuchAlgorithmException, KeyManagementException {
        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

        // Ciphers enabled by default.
        List<String> defaultCiphers = Arrays.asList(ssf.getDefaultCipherSuites());

        System.out.println("Ciphers enabled by default:\n");
        System.out.print(String.join(",\n", defaultCiphers));

        // Ciphers that could be enabled.
        List<String> availableCiphers = new ArrayList<>();
        Collections.addAll(availableCiphers, ssf.getSupportedCipherSuites());
        availableCiphers.removeAll(defaultCiphers);

        System.out.println("\n\nCiphers available but not enabled:\n");
        System.out.print(String.join(",\n", availableCiphers));

        // TLS versions

        System.out.println("\n\nDefault protocols SSLContext.getDefault()\n");
        SSLContext sslContext = SSLContext.getDefault();
        System.out.println("- SSLContext.getProtocol():\t\t\t\t\t" + sslContext.getProtocol());
        System.out.println("- SSLContext.getSupportedSSLParameters().getProtocols():\t"
                + String.join(", ", sslContext.getSupportedSSLParameters().getProtocols()));
        System.out.println("- SSLContext.getDefaultSSLParameters().getProtocols():\t\t"
                + String.join(", ", sslContext.getDefaultSSLParameters().getProtocols()));

        System.out.println("\n\nDefault protocols SSLContext.getInstance(\"TLSv1.1\")\n");
        sslContext = SSLContext.getInstance("TLSv1.1");
        sslContext.init(null, null, null);
        System.out.println("- SSLContext.getProtocol():\t\t\t\t\t" + sslContext.getProtocol());
        System.out.println("- SSLContext.getSupportedSSLParameters().getProtocols():\t"
                + String.join(", ", sslContext.getSupportedSSLParameters().getProtocols()));
        System.out.println("- SSLContext.getDefaultSSLParameters().getProtocols():\t\t"
                + String.join(", ", sslContext.getDefaultSSLParameters().getProtocols()));

        System.out.println("\n\nDefault protocols SSLContext.getInstance(\"TLSv1.2\")\n");
        sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, null);
        System.out.println("- SSLContext.getProtocol():\t\t\t\t\t" + sslContext.getProtocol());
        System.out.println("- SSLContext.getSupportedSSLParameters().getProtocols():\t"
                + String.join(", ", sslContext.getSupportedSSLParameters().getProtocols()));
        System.out.println("- SSLContext.getDefaultSSLParameters().getProtocols():\t\t"
                + String.join(", ", sslContext.getDefaultSSLParameters().getProtocols()));

        System.out.println("\n\nDefault protocols SSLContext.getInstance(\"TLSv1.3\")\n");
        sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(null, null, null);
        System.out.println("- SSLContext.getProtocol():\t\t\t\t\t" + sslContext.getProtocol());
        System.out.println("- SSLContext.getSupportedSSLParameters().getProtocols():\t"
                + String.join(", ", sslContext.getSupportedSSLParameters().getProtocols()));
        System.out.println("- SSLContext.getDefaultSSLParameters().getProtocols():\t\t"
                + String.join(", ", sslContext.getDefaultSSLParameters().getProtocols()));
    }
}
