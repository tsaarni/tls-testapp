
# TLS client server example in Go

This is a simple TLS client server example in Go, using HTTP as the application protocol.
The example uses mutual TLS authentication, i.e. both the client and the server authenticate each other using X509 certificates.
The client and server are implemented in the same file, see [`main.go`](main.go) for the code.


## Pre-requisites

Run the following commands to generate the certificates using [certyaml](https://github.com/tsaarni/certyaml), see [`certs.yaml`](certs.yaml) for the configuration.

```console
$ rm -rf certs  # remove old certs
$ mkdir certs
$ certyaml --destination certs certs.yaml  # generate certs
```

## Running the test application locally

```console
$ go run main.go server  # run in one terminal
$ go run main.go client  # run in another terminal
```

Capture traffic with Wireshark and observe the TLS handshake.

```console
$ wireshark -k -i lo -f 'port 8443'
```


## Build testapp container and run it on Kind cluster

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
See [`main.go`](main.go) how this is used to write the secrets to `/tmp/wireshark-keys.log`.
This file can then be used by Wireshark to decrypt the TLS traffic.

```console
$ wireshark -i lo -k -f "port 8443" -o tls.keylog_file:/tmp/wireshark-keys.log
```

The example intercepts the TLS master secrets from the server, but the same can be done for the client.

If running the testapp in Kind, use `nsenter` to enter the network namespace of the container and run Wireshark there.
First, find the PID of the testapp server process and then run `nsenter` with the PID.

```console
$ server_pid=$(pgrep -f "testapp server")
$ sudo nsenter -t $server_pid --net wireshark -f "port 8443" -k -o tls.keylog_file:/proc/$server_pid/root/tmp/wireshark-keys.log
```

Note that Wireshark must capture the traffic beginning from the handshake, otherwise, it cannot decrypt the traffic.
