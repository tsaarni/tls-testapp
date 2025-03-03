package io.github.tsaarni.tlstestapp.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class Tls {

    private static final Logger log = LogManager.getLogger(Tls.class);

    private static String address = "server.127-0-0-1.nip.io";
    private static int port = 14443;

    private static final String CLIENT_CA_FILE = "../../certs/server-ca.pem";
    private static final String CLIENT_CERT_FILE = "../../certs/client.pem";
    private static final String CLIENT_KEY_FILE = "../../certs/client-key.pem";

    private static final String SERVER_CA_FILE = "../../certs/client-ca.pem";
    private static final String SERVER_CERT_FILE = "../../certs/server.pem";
    private static final String SERVER_KEY_FILE = "../../certs/server-key.pem";

    public static void client()
            throws NoSuchAlgorithmException, KeyManagementException, IOException {
        log.info("Starting in client mode");

        KeyManagerFactory keyManagerFactory = PemManagerFactory.createKeyManagerFactory(Path.of(CLIENT_KEY_FILE),
                Path.of(CLIENT_CERT_FILE));
        TrustManagerFactory trustManagerFactory = PemManagerFactory.createTrustManagerFactory(Path.of(CLIENT_CA_FILE));

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

        SSLSocket sock = (SSLSocket) context.getSocketFactory().createSocket(address, port);
        log.info("Connected to server local={} remote={}", sock.getLocalSocketAddress(),
                sock.getRemoteSocketAddress());

        int counter = 1;
        while (true) {
            try {
                String message = "Hello World " + counter++;
                log.info("Sending: {}", message);

                OutputStream outputStream = sock.getOutputStream();
                outputStream.write(message.getBytes());
                outputStream.flush();

                InputStream inputStream = sock.getInputStream();
                byte[] receivedBytes = new byte[message.length()];
                int bytesRead = inputStream.read(receivedBytes);

                if (bytesRead <= 0) {
                    break;
                }

                String receivedMessage = new String(receivedBytes, 0, bytesRead);
                log.info("Received: {}", receivedMessage);

                Thread.sleep(1000);
            } catch (InterruptedException e) {
                log.error("Error:", e);
                Thread.currentThread().interrupt();
            }
        }

    }

    private static void server() throws IOException, NoSuchAlgorithmException, KeyManagementException {
        log.info("Starting in server mode");

        KeyManagerFactory keyManagerFactory = PemManagerFactory.createKeyManagerFactory(Path.of(SERVER_KEY_FILE),
                Path.of(SERVER_CERT_FILE));
        TrustManagerFactory trustManagerFactory = PemManagerFactory.createTrustManagerFactory(Path.of(SERVER_CA_FILE));

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

        SSLServerSocketFactory sslServerSocketFactory = context.getServerSocketFactory();
        try (SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port)) {

            // Force TLSv1.2 for better visibility of the TLS handshake.
            // sslServerSocket.setEnabledProtocols(new String[] { "TLSv1.2" });
            sslServerSocket.setNeedClientAuth(true);

            log.info("Server started on port {}", sslServerSocket.getLocalPort());
            while (true) {
                try {
                    SSLSocket sock = (SSLSocket) sslServerSocket.accept();
                    log.info("Client connected local={} remote={}", sock.getLocalSocketAddress(),
                            sock.getRemoteSocketAddress());

                    log.debug("Negotiated protocol: {} cipher: {}", sock.getSession().getProtocol(),
                            sock.getSession().getCipherSuite());

                    OutputStream outputStream = sock.getOutputStream();
                    InputStream inputStream = sock.getInputStream();

                    while (true) {
                        byte[] receivedBytes = new byte[1024];
                        int bytesRead = inputStream.read(receivedBytes);

                        if (bytesRead <= 0) {
                            break;
                        }

                        String receivedMessage = new String(receivedBytes, 0, bytesRead);
                        log.info("Received: {}", receivedMessage);

                        outputStream.write(receivedBytes, 0, bytesRead);
                        outputStream.flush();
                        log.info("Sent: {}", receivedMessage);
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
                client();
            } else if (args[0].equals("server")) {
                server();
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
