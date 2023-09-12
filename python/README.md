
# TLS key logging example for Python (or ANY OpenSSL based application)

## Pre-requisites

Run the following commands to generate the certificates using [certyaml](https://github.com/tsaarni/certyaml).

```console
$ rm -rf certs
$ mkdir certs
$ certyaml --destination certs certs.yaml
```

## Running the example


```console
$ openssl s_server -key certs/server.key -cert certs/server.crt -accept 8443 -tls1_3 -debug -msg -state -tlsextdebug -keylogfile keylog.txt
```

```console
