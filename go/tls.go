package main

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"os"
	"time"
)

func tlsServer() {
	cert, err := tls.LoadX509KeyPair("certs/server.pem", "certs/server-key.pem")
	if err != nil {
		slog.Error("Error loading server certificate", "error", err)
		return
	}

	caCert, err := os.ReadFile("certs/client-ca.pem")
	if err != nil {
		slog.Error("Error loading client CA certificate", "error", err)
		return
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	f, _ := os.OpenFile("/tmp/wireshark-keys.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		KeyLogWriter: f,
		// Force TLSv1.2 for better visibility of the TLS handshake.
		//MaxVersion: tls.VersionTLS12,
	}

	// create TLS listener
	listener, err := tls.Listen("tcp", "127.0.0.1:8443", config)
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

		defer conn.Close()
		slog.Info("Server accepted connection", "remote", conn.RemoteAddr())

		// handle connection
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			slog.Error("Error reading from connection", "error", err)
			return
		}

		slog.Info("Server received", "message", string(buffer[:n]))

		_, err = conn.Write(buffer[:n])
		if err != nil {
			slog.Error("Error writing to connection", "error", err)
			return
		}
	}
}

func tlsClient() {
	// Read the CA certificate and create cert pool for server authentication.
	caCert, err := os.ReadFile("certs/server-ca.pem")
	if err != nil {
		slog.Error("Error loading server CA certificate", "error", err)
		return
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Read the client certificate and private key.
	clientCert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client-key.pem")
	if err != nil {
		slog.Error("Error loading client certificate", "error", err)
		return
	}

	for {
		// Make TLS connection
		conn, err := tls.Dial("tcp", "server.127-0-0-1.nip.io:8443", &tls.Config{
			RootCAs:      caCertPool,
			Certificates: []tls.Certificate{clientCert},
		})
		if err != nil {
			slog.Error("Error dialing server", "error", err)
			return
		}

		defer conn.Close()

		slog.Info("Client connected", "remote", conn.RemoteAddr())

		// Send message to server
		slog.Info("Client sending", "message", "Hello, TLS!")

		_, err = conn.Write([]byte("Hello, TLS!"))
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

		slog.Info("Client received", "message", string(buffer[:n]))

		slog.Info("Client sleeping for 5 seconds")
		time.Sleep(5 * time.Second)
	}
}
