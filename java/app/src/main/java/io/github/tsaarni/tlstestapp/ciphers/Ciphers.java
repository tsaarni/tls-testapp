// https://www.java.com/en/configure_crypto.html
// https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
// https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html
// https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html
// https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html

package io.github.tsaarni.tlstestapp.ciphers;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;

public class Ciphers {

    public static void main(String[] args) throws NoSuchAlgorithmException, KeyManagementException, IOException {

        // SSLServerSocketFactory ciphers suites.
        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        printCipherSuite("SSLServerSocketFactory.getDefault()", ssf.getDefaultCipherSuites());

        List<String> selectedCiphers = Arrays.asList(ssf.getDefaultCipherSuites());
        List<String> availableCiphers = new ArrayList<>();
        Collections.addAll(availableCiphers, ssf.getSupportedCipherSuites());
        availableCiphers.removeAll(selectedCiphers);

        System.out.println("\n\nCiphers available but not enabled for SSLServerSocketFactory.getDefault():");
        System.out.print(String.join(",\n", availableCiphers));


        SSLContext ctxDefault = SSLContext.getDefault();
        SSLContext ctxTLS11 = SSLContext.getInstance("TLSv1.1");
        SSLContext ctxTLS12 = SSLContext.getInstance("TLSv1.2");
        SSLContext ctxTLS13 = SSLContext.getInstance("TLSv1.3");
        ctxTLS11.init(null, null, null);
        ctxTLS12.init(null, null, null);
        ctxTLS13.init(null, null, null);

        printCipherSuiteDiff("SSLContext.getInstance(\"TLSv1.1\")", ctxTLS11.getDefaultSSLParameters(), ctxDefault.getDefaultSSLParameters());
        printCipherSuiteDiff("SSLContext.getInstance(\"TLSv1.2\")", ctxTLS12.getDefaultSSLParameters(), ctxDefault.getDefaultSSLParameters());
        printCipherSuiteDiff("SSLContext.getInstance(\"TLSv1.3\")", ctxTLS13.getDefaultSSLParameters(), ctxDefault.getDefaultSSLParameters());
    }

    static void printCipherSuiteDiff(String context, SSLParameters a, SSLParameters b) {
        System.out.println("\n" + context + " ciphers missing compared to default:");

        String[] ciphersNotPresent = missing(a.getCipherSuites(), b.getCipherSuites());
        for (String c : ciphersNotPresent) {
            System.out.println("\t" + c);
        }

        String[] ciphersExtra = extra(a.getCipherSuites(), b.getCipherSuites());
        System.out.println("\n" + context + " ciphers extra compared to default:");
        for (String c : ciphersExtra) {
            System.out.println("\t" + c);
        }

    }

    static void printCipherSuite(String context, String[] ciphers) {
        System.out.println("\n\n" + context + " ciphers:");
        for (String c : ciphers) {
            System.out.println("\t" + c);
        }
    }

    static String[] missing(String[] a, String[] b) {
        List<String> list = new ArrayList<>();
        for (String s : b) {
            if (!Arrays.asList(a).contains(s)) {
                list.add(s);
            }
        }
        return list.toArray(new String[0]);
    }

    static String[] extra(String[] a, String[] b) {
        List<String> list = new ArrayList<>();
        for (String s : a) {
            if (!Arrays.asList(b).contains(s)) {
                list.add(s);
            }
        }
        return list.toArray(new String[0]);
    }

}
