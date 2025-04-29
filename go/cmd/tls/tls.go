package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"
)

const (
	addr            = "server.127-0-0-1.nip.io:14443"
	serverCaFile    = "../certs/client-ca.pem"
	serverCertFile  = "../certs/server.pem"
	serverKeyFile   = "../certs/server-key.pem"
	serverCaCrlFile = "../certs/client-ca-crl.pem" // CRL file that client CA has issued (contains revoked client cert serials)
	clientCaFile    = "../certs/server-ca.pem"
	clientCertFile  = "../certs/client.pem"
	clientKeyFile   = "../certs/client-key.pem"
	// clientCertFile = "../certs/revoked-client.pem"
	// clientKeyFile  = "../certs/revoked-client-key.pem"
)

func server() {
	cert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		slog.Error("Error loading server certificate", "error", err)
		return
	}

	caCert, err := os.ReadFile(serverCaFile)
	if err != nil {
		slog.Error("Error loading client CA certificate", "error", err)
		return
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		// Force TLSv1.2 for better visibility of the TLS handshake.
		// MaxVersion: tls.VersionTLS12,
		VerifyPeerCertificate: rejectRevokedCerts,
	}

	keyLogFile := os.Getenv("SSLKEYLOGFILE")
	if keyLogFile != "" {
		slog.Info("Keylog enabled", "file", keyLogFile)
		f, _ := os.OpenFile(keyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		config.KeyLogWriter = f
	}

	listener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		slog.Error("Error creating TLS listener", "error", err)
		return
	}

	slog.Info("Server started", "address", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Error("Error accepting connection", "error", err)
			return
		}

		slog.Info("Server accepted connection", "remote", conn.RemoteAddr())

		handleClient(conn)
		conn.Close()
	}
}

func handleClient(conn net.Conn) {
	for {
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			if err.Error() == "EOF" {
				slog.Info("Client closed connection", "remote", conn.RemoteAddr())
			} else {
				slog.Error("Error reading from connection", "error", err)
			}
			return
		}

		slog.Info("Received", "message", string(buffer[:n]))

		_, err = conn.Write(buffer[:n])
		if err != nil {
			if err.Error() == "EOF" {
				slog.Info("Client closed connection", "remote", conn.RemoteAddr())
			} else {
				slog.Error("Error writing to connection", "error", err)
			}
			return
		}
		slog.Info("Sent", "message", string(buffer[:n]))
	}
}

func client() {
	// Read the CA certificate and create cert pool for server authentication.
	caCert, err := os.ReadFile(clientCaFile)
	if err != nil {
		slog.Error("Error loading server CA certificate", "error", err)
		return
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Read the client certificate and private key.
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		slog.Error("Error loading client certificate", "error", err)
		return
	}

	config := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS12,
		// CipherSuites: []uint16{
		// 	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		// },
	}

	keyLogFile := os.Getenv("SSLKEYLOGFILE")
	if keyLogFile != "" {
		slog.Info("Keylog enabled", "file", keyLogFile)
		f, _ := os.OpenFile(keyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		config.KeyLogWriter = f
	}

	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		slog.Error("Error dialing server", "error", err)
		return
	}

	defer conn.Close()

	slog.Info("Connected", "remote", conn.RemoteAddr())

	i := 1
	for {
		// Send message to server
		msg := fmt.Sprintf("Hello world %d", i)
		slog.Info("Sending", "message", msg)

		_, err = conn.Write([]byte(msg))
		if err != nil {
			slog.Error("Error writing to connection", "error", err)
			return
		}

		// Read message from server
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			slog.Error("Error reading from connection", "error", err)
			return
		}

		slog.Info("Received", "message", string(buffer[:n]))

		time.Sleep(1 * time.Second)
		i++
	}
}

func rejectRevokedCerts(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	crl, err := loadCRL(serverCaCrlFile, serverCaFile)
	if err != nil {
		return fmt.Errorf("failed to verify: failed to load CRL: %w", err)
	}

	for _, chain := range verifiedChains {
		for _, cert := range chain {
			return verifyCert(cert, crl)
		}
	}
	return nil
}

func verifyCert(cert *x509.Certificate, crl *x509.RevocationList) error {
	// Check that the certificate is issued by the same issuer as the CRL.
	if cert.Issuer.String() != crl.Issuer.String() {
		return fmt.Errorf("certificate issuer %s does not match CRL issuer %s", cert.Issuer, crl.Issuer)
	}

	for _, revoked := range crl.RevokedCertificateEntries {
		// Note: this example code ignores the CRL extensions.

		// Check if the certificate serial number is in the CRL.
		if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			return fmt.Errorf("certificate %s is revoked (serial: %s)", cert.Subject, cert.SerialNumber)
		}
	}
	return nil
}

func loadCRL(crlFile string, issuerCertFile string) (*x509.RevocationList, error) {
	crlPEM, err := os.ReadFile(crlFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL file: %w", err)
	}

	// Decode the PEM file into DER format.
	block, _ := pem.Decode(crlPEM)
	if block.Type != "X509 CRL" {
		return nil, fmt.Errorf("invalid CRL PEM block type: %s", block.Type)
	}

	// Parse the CRL.
	crl, error := x509.ParseRevocationList(block.Bytes)
	if error != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", error)
	}

	// Optional 1: Check if the CRL is expired.
	//
	//expired := !time.Now().Before(crl.NextUpdate)
	//if expired {
	//	return nil, fmt.Errorf("CRL is expired: %s", crl.NextUpdate)
	//}

	// Optional 2: Verify that the CRL is signed by the issuer CA certificate.
	//
	//// Load the issuer certificate.
	//issuerCertPEM, err := os.ReadFile(issuerCertFile)
	//if err != nil {
	//	return nil, fmt.Errorf("failed to read issuer certificate file: %w", err)
	//}
	//
	//issuerCertBlock, _ := pem.Decode(issuerCertPEM)
	//if issuerCertBlock == nil || issuerCertBlock.Type != "CERTIFICATE" {
	//	return nil, fmt.Errorf("invalid issuer certificate PEM block type: %s", issuerCertBlock.Type)
	//}
	//issuerCert, err := x509.ParseCertificate(issuerCertBlock.Bytes)
	//if err != nil {
	//	return nil, fmt.Errorf("failed to parse issuer certificate: %w", err)
	//}
	//if err := crl.CheckSignatureFrom(issuerCert); err != nil {
	//	return nil, fmt.Errorf("failed to verify CRL signature: %w", err)
	//}

	return crl, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: tls server|client")
		return
	}

	switch os.Args[1] {
	case "server":
		server()
	case "client":
		client()
	default:
		fmt.Println("Usage: tls server|client")
	}
}
