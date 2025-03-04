package io.github.tsaarni.tlstestapp.tls;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

public class PemManagerFactory {

    private PemManagerFactory() {
        // Empty.
    }

    public static KeyManagerFactory createKeyManagerFactory(Path keyPath, Path certPath) {
        try {
            KeyStore keyStore = createKeyStore(keyPath, certPath);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory
                    .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, null);
            return keyManagerFactory;
        } catch (NoSuchAlgorithmException | KeyStoreException | IOException
                | UnrecoverableKeyException | CertificateException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to create KeyManagerFactory", e);
        }
    }

    public static TrustManagerFactory createTrustManagerFactory(Path certPath) {
        try {
            KeyStore trustStore = createTrustStore(certPath);
            TrustManagerFactory trustManagerFactory = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            return trustManagerFactory;
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException e) {
            throw new RuntimeException("Failed to create TrustManagerFactory", e);
        }
    }

    public static KeyStore createKeyStore(Path keyPath, Path certPath) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException, InvalidKeySpecException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);

        Certificate[] certificates = PemCredentialFactory.generateCertificates(certPath);
        PrivateKey privateKey = PemCredentialFactory.generatePrivateKey(keyPath);

        keyStore.setKeyEntry("credential", privateKey, null, certificates);

        return keyStore;
    }

    public static KeyStore createTrustStore(Path certPath)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);

        Certificate[] certificates = PemCredentialFactory.generateCertificates(certPath);

        for (int i = 0; i < certificates.length; i++) {
            trustStore.setCertificateEntry("cert-" + i, certificates[i]);
        }

        return trustStore;
    }
}
