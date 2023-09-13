package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func server() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Server received", "method", r.Method, "url", r.URL, "proto", r.Proto, "remote", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, TLS!"))
	})

	// Read server certificate and private key.
	cert, err := tls.LoadX509KeyPair("certs/server.pem", "certs/server-key.pem")
	if err != nil {
		slog.Error("Error loading server certificate", "error", err)
		return
	}

	// Read CA certificate and create cert pool for client authentication.
	caCert, err := os.ReadFile("certs/client-ca.pem")
	if err != nil {
		slog.Error("Error loading client CA certificate", "error", err)
		return
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create a key log file for wireshark.
	f, _ := os.OpenFile("/tmp/wireshark-keys.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		KeyLogWriter: f,
		// Force TLSv1.2 for better visibility of the TLS handshake.
		MaxVersion: tls.VersionTLS12,
	}

	address := "0.0.0.0:8443"

	server := &http.Server{
		Addr:      address,
		TLSConfig: config,
	}

	slog.Info("Server started", "address", address)
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		slog.Error("Error starting server", "error", err)
		return
	}
}

func client() {
	// If environment variable SERVER_URL is set, use it as the server address.
	// Otherwise, use the default address.
	url := os.Getenv("SERVER_URL")
	if url == "" {
		url = "https://server.127-0-0-1.nip.io:8443/test"
	}

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

	// Make https request
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caCertPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}

	client := &http.Client{Transport: tr}

	for {
		makeRequest(client, url)
		slog.Info("Client sleeping for 5 seconds")
		time.Sleep(5 * time.Second)
	}
}

func makeRequest(client *http.Client, url string) {
	resp, err := client.Get(url)
	if err != nil {
		slog.Error("Error making request", "error", err)
		return
	}
	defer resp.Body.Close()

	slog.Info("Client received", "status", resp.Status)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("Error reading response body", "error", err)
		return
	}

	slog.Info("Client received", "body", string(body), "url", resp.Request.URL)
}

func main() {

	if len(os.Args) > 1 {
		if os.Args[1] == "server" {
			server()
		} else if os.Args[1] == "client" {
			client()
		}
	} else {
		slog.Info("Usage: go run main.go <server|client>")
		os.Exit(1)
	}
}
