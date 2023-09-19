package testapp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App {

    private static final Logger log = LoggerFactory.getLogger(App.class);

    private static String address = "server.127-0-0-1.nip.io";
    private static int port = 9090;


    public void client() throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(Files.newInputStream(Path.of("client-truststore.p12")), "secret".toCharArray());

        List<CertStore> certStores =  new ArrayList<>();
        Collection<CRL> crls = new HashSet<>();
        crls.add(CertificateFactory.getInstance("X.509").generateCRL( Files.newInputStream(Path.of("server-ca-crl.pem"))));
        certStores.add(CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls)));

        PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) CertPathBuilder.getInstance("PKIX").getRevocationChecker();
        revocationChecker.setOptions(
                EnumSet.of(PKIXRevocationChecker.Option.PREFER_CRLS, PKIXRevocationChecker.Option.NO_FALLBACK));
        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustStore, new X509CertSelector());
        pkixParams.setCertStores(certStores);
        pkixParams.addCertPathChecker(revocationChecker);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(new CertPathTrustManagerParameters(pkixParams));

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(Files.newInputStream(Path.of("client-keystore.p12")), "secret".toCharArray());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "secret".toCharArray());

        SSLContext newDefaultContext = SSLContext.getInstance("TLS");
        newDefaultContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        SSLContext.setDefault(newDefaultContext);

        try (SSLSocket sock = (SSLSocket) SSLSocketFactory.getDefault().createSocket(address, port)) {

            log.info("Connected to server local={} remote={}", sock.getLocalSocketAddress(),
                    sock.getRemoteSocketAddress());

            while (true) {
                try {
                    log.info("Sending data");

                    OutputStream outputStream = sock.getOutputStream();
                    outputStream.write("Hello World".getBytes());
                    outputStream.flush();

                    InputStream inputStream = sock.getInputStream();
                    byte[] buffer = new byte[1024];
                    int read = inputStream.read(buffer);
                    log.info("Received response (bytes={})", read);

                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    log.error("Error:", e);
                    Thread.currentThread().interrupt();
                }
            }
        }

    }


    private void server() throws IOException {
        try (SSLServerSocket sslServerSocket = (SSLServerSocket) SSLServerSocketFactory.getDefault().createServerSocket(port)) {

            // Force TLSv1.2 for better visibility of the TLS handshake.
            sslServerSocket.setEnabledProtocols(new String[] { "TLSv1.2" });
            sslServerSocket.setNeedClientAuth(true);

            log.info("Server started on port {}", sslServerSocket.getLocalPort());
            while (true) {
                try {
                    SSLSocket sock = (SSLSocket) sslServerSocket.accept();
                    log.info("Client connected local={} remote={}", sock.getLocalSocketAddress(), sock.getRemoteSocketAddress());

                    InputStream inputStream = sock.getInputStream();
                    OutputStream outputStream = sock.getOutputStream();
                    byte[] buffer = new byte[1024];
                    int read;
                    while ((read = inputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, read);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static void main(String[] args) {

        try {
        if (args.length != 1) {
            log.error("Usage: java -jar testapp.jar <client|server>");
            System.exit(1);
        }

        if (args[0].equals("client")) {
            log.info("Starting in {} mode", args[0]);
            new App().client();
        } else if (args[0].equals("server")) {
            log.info("Starting in {} mode", args[0]);
            new App().server();
        } else {
            log.error("Usage: java -jar testapp.jar <client|server>");
            System.exit(1);
        }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
