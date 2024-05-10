package main

import (
	"log/slog"
	"os"
)

func printUsage() {
	slog.Info("Usage: go run main.go <https-server|https-client|tls-server|tls-client>")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
	}

	switch os.Args[1] {
	case "https-server":
		httpsServer()
	case "https-client":
		httpsClient()
	case "tls-server":
		tlsServer()
	case "tls-client":
		tlsClient()
	default:
		printUsage()
	}
}
