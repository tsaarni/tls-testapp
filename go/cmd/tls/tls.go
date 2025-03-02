package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"
)

const (
	addr           = "server.127-0-0-1.nip.io:14443"
	serverCaFile   = "../certs/client-ca.pem"
	serverCertFile = "../certs/server.pem"
	serverKeyFile  = "../certs/server-key.pem"
	clientCaFile   = "../certs/server-ca.pem"
	clientCertFile = "../certs/client.pem"
	clientKeyFile  = "../certs/client-key.pem"
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
		//MaxVersion: tls.VersionTLS12,
	}

	keyLogFile := os.Getenv("SSLKEYLOGFILE")
	if keyLogFile != "" {
		slog.Info("Keylog enabled", "file", keyLogFile)
		f, _ := os.OpenFile(keyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
	}

	keyLogFile := os.Getenv("SSLKEYLOGFILE")
	if keyLogFile != "" {
		slog.Info("Keylog enabled", "file", keyLogFile)
		f, _ := os.OpenFile(keyLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
