
# TLS key logging example for Go

## Pre-requisites

Run the following commands to generate the certificates using [certyaml](https://github.com/tsaarni/certyaml).

```console
$ rm -rf certs
$ mkdir certs
$ certyaml --destination certs certs.yaml
```

## Running the testapp locally

```console
$ go run main.go server  # run in one terminal
$ go run main.go client  # run in another terminal
```

Check from the logs that the client and server are communicating.

Use Wireshark to decrypt TLS traffic:

```console
$ server_pid=$(pgrep -f "bin/go run main.go server")
$ sudo wireshark -i lo -k -f "port 8443" -o tls.keylog_file:/tmp/wireshark-keys.log
```


## Build testapp container and run it on Kind cluster

```console
$ docker build -t localhost/testapp:latest -f docker/testapp/Dockerfile .
$ kind create cluster
$ kind load docker-image localhost/testapp:latest
$ kubectl apply -f manifests/testapp.yaml
```

Check the logs to see that the client and server are communicating

```console
$ kubectl logs deployment/server -f
$ kubectl logs deployment/client -f
```

Use Wireshark to decrypt TLS traffic

```console
$ server_pid=$(pgrep -f "testapp server")
$ sudo nsenter -t $server_pid --net wireshark -f "port 8443" -k -o tls.keylog_file:/proc/$server_pid/root/tmp/wireshark-keys.log
```
