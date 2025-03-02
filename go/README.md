
# TLS client server example in Go

This is a simple client server example in Go:

* A TLS server that listens on port 14443 for TLS client connections and echoes back the received message. This is implemented in [`cmd/tls/tls.go`](cmd/tls/tls.go)
* A HTTPS server that listens on port 14443 for HTTP client connections and echoes back the received message. This is implemented in [`cmd/http/http.go`](cmd/http/http.go)

The examples use mutual TLS authentication, i.e. both the client and the server authenticate each other using X509 certificates.


## Pre-requisites

Run the following commands to generate the certificates using [certyaml](https://github.com/tsaarni/certyaml), see [`certs.yaml`](certs.yaml) for the configuration.

```console
$ rm -rf certs  # remove old certs
$ mkdir certs
$ certyaml --destination certs certs.yaml  # generate certs
```

## Running the TLS test application locally

```console
$ go build ./cmd/tls
$ ./tls server  # run TLS server in one terminal
$ ./tls client  # run TLS client in another terminal

or

```console
$ go build ./cmd/http
$ ./http server  # run HTTPS server in one terminal
$ ./http client  # run HTTPS client in another terminal
```

Capture traffic with Wireshark and observe the TLS handshake.

```console
$ wireshark -i lo -f 'port 8443' -k -o tls.keylog_file:/tmp/wireshark-keys.log
```


## Build testapp container and run it on Kind cluster

> ⚠️ TODO: Unfinished, does not work currently.

Build the testapp container.

```console
$ docker build -t localhost/testapp:latest -f docker/testapp/Dockerfile .
```

Create a Kind cluster and load the testapp image to the cluster

```console
$ kind create cluster
$ kind load docker-image localhost/testapp:latest
```

Deploy the testapp to the cluster

```console
$ kubectl apply -f manifests/testapp.yaml
```

Check the logs to see that the client and server are communicating

```console
$ kubectl logs deployment/server -f
$ kubectl logs deployment/client -f
```


## TLS decryption

Go [`TLSConfig`](https://pkg.go.dev/crypto/tls#Config) has support for writing TLS master secrets to a file by setting [`KeyLogWriter`](https://pkg.go.dev/crypto/tls#example-Config-KeyLogWriter) field.
This file can then be used by Wireshark to decrypt the TLS traffic.

To enable writing the keylog file set `SSLKEYLOGFILE` environment variable to the path of the keylog file.

```console
$ SSLKEYLOGFILE=wireshark-keys.log ./tls server
```

Then run Wireshark with the keylog file.

```console
$ wireshark -i lo -k -f "port 8443" -o tls.keylog_file:wireshark-keys.log
```

The example intercepts the TLS master secrets from the server, but the same can be done for the client.

If running the testapp in Kind, use `nsenter` to enter the network namespace of the container and run Wireshark there.
First, find the PID of the testapp server process and then run `nsenter` with the PID.

```console
$ server_pid=$(pgrep -f "tls server")
$ sudo nsenter -t $server_pid --net wireshark -f "port 8443" -k -o tls.keylog_file:/proc/$server_pid/root/tmp/wireshark-keys.log
```

Note that Wireshark must capture the traffic beginning from the handshake, otherwise, it cannot decrypt the traffic.
