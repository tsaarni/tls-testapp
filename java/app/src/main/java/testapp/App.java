package testapp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App {

    private static final Logger log = LoggerFactory.getLogger(App.class);

    private static String address = "server.127-0-0-1.nip.io";
    private static int port = 9090;


    public static void client() throws IOException {
        log.info("Starting in client mode");

        SSLSocket sock = (SSLSocket) SSLSocketFactory.getDefault().createSocket(address, port);
        log.info("Connected to server local={} remote={}", sock.getLocalSocketAddress(),
                sock.getRemoteSocketAddress());

        log.debug("Negotiated protocol: {} cipher: {}",
                sock.getSession().getProtocol(), sock.getSession().getCipherSuite());

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


    private static void server() throws IOException {
        log.info("Starting in server mode");

        SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        try (SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port)) {

            // Force TLSv1.2 for better visibility of the TLS handshake.
            // sslServerSocket.setEnabledProtocols(new String[] { "TLSv1.2" });
            sslServerSocket.setNeedClientAuth(true);

            log.info("Server started on port {}", sslServerSocket.getLocalPort());
            while (true) {
                try {
                    SSLSocket sock = (SSLSocket) sslServerSocket.accept();
                    log.info("Client connected local={} remote={}", sock.getLocalSocketAddress(), sock.getRemoteSocketAddress());

                    log.debug("Negotiated protocol: {} cipher: {}",
                            sock.getSession().getProtocol(), sock.getSession().getCipherSuite());

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
