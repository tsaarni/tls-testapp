package testapp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import fi.protonode.certy.Credential;

public class GenerateCerts {

    public static void main(String[] args) {

        try {

            Credential serverCa = new Credential().subject("CN=server-ca");
            Credential clientCa = new Credential().subject("CN=client-ca");
            Credential server = new Credential().subject("CN=server").issuer(serverCa)
                    .subjectAltName("DNS:server.127-0-0-1.nip.io");
            Credential client = new Credential().subject("CN=client").issuer(clientCa);

            // Generate trust and keystore files for the server
            KeyStore serverTruststore = KeyStore.getInstance("PKCS12");
            serverTruststore.load(null, null);
            serverTruststore.setCertificateEntry("ca", clientCa.getCertificate());
            serverTruststore.store(Files.newOutputStream(Paths.get("server-truststore.p12")), "secret".toCharArray());

            KeyStore serverKeystore = KeyStore.getInstance("PKCS12");
            serverKeystore.load(null, null);
            serverKeystore.setKeyEntry("server", server.getPrivateKey(), "secret".toCharArray(), server.getCertificates());
            serverKeystore.store(Files.newOutputStream(Paths.get("server-keystore.p12")), "secret".toCharArray());


            // Generate trust and keystore files for the client
            KeyStore clientTruststore = KeyStore.getInstance("PKCS12");
            clientTruststore.load(null, null);
            clientTruststore.setCertificateEntry("ca", serverCa.getCertificate());
            clientTruststore.store(Files.newOutputStream(Paths.get("client-truststore.p12")), "secret".toCharArray());

            KeyStore clientKeystore = KeyStore.getInstance("PKCS12");
            clientKeystore.load(null, null);
            clientKeystore.setKeyEntry("client", client.getPrivateKey(), "secret".toCharArray(), client.getCertificates());
            clientKeystore.store(Files.newOutputStream(Paths.get("client-keystore.p12")), "secret".toCharArray());

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
        }
    }

}
