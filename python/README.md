# TLS client server example in Python

This is a simple TLS client server example in Python, using HTTP as the application protocol.
The example uses mutual TLS authentication, i.e. both the client and the server authenticate each other using X509 certificates.
The client and server are implemented in the same file, see [`testapp.py`](testapp.py) for the code.

## Pre-requisites

Run the following commands to generate the certificates using [certyaml](https://github.com/tsaarni/certyaml), see [`certs.yaml`](certs.yaml) for the configuration.

```console
$ rm -rf certs  # remove old certs
$ mkdir certs
$ certyaml --destination certs certs.yaml  # generate certs
```

## Running the test application

```console
$ python3 testapp.py server  # run in one terminal
$ python3 testapp.py client  # run in another terminal
```

Capture traffic with Wireshark and observe the TLS handshake.

```console
$ wireshark -k -i lo -f 'port 8443'
```


## TLS decryption

### LD_PRELOAD approach (works for ANY OpenSSL-based application)

The following steps work for any OpenSSL-based application, not just Python.

The TLS master secrets can be intercepted from OpenSSL using a wrapper library and written to a file.
This file can then be used by Wireshark to decrypt the TLS traffic.
The wrapper can be loaded by using `LD_PRELOAD`, without modifying the application itself.

In this example, we use the library https://github.com/Lekensteyn/wireshark-notes/tree/master/src, courtesy of Peter Wu.
You can download `sslkeylog.c` or compile the included copy:

```console
$ gcc sslkeylog.c -shared -o libsslkeylog.so -fPIC -ldl -lssl
```

Run the application with `LD_PRELOAD` set to the path of the `libsslkeylog.so` file and SSLKEYLOGFILE set to the path of the key log file.

```console
LD_PRELOAD=./libsslkeylog.so SSLKEYLOGFILE=/tmp/wireshark-keys.log python3 testapp.py server
```

The TLS keys are now logged to `/tmp/wireshark-keys.log` when the server is terminating the TLS connection.
The example intercepts the TLS master secrets from the server, but the same can be done for the client.
Wireshark can decrypt the TLS traffic when provided with the key log file.

```console
$ wireshark -k -i lo -f 'port 8443' -o tls.keylog_file:/tmp/wireshark-keys.log
```

Note that Wireshark must capture the traffic beginning from the handshake, otherwise, it cannot decrypt the traffic.


### SSLKEYLOGFILE approach

To be more precise, the `LD_PRELOAD` approach is not necessary for Python.
When using [`create_default_context()`](https://docs.python.org/3/library/ssl.html#ssl.create_default_context) there is direct support for keylogging by setting the environment variable `SSLKEYLOGFILE` to the path of the key log file, so it is not necessary to use the `LD_PRELOAD` approach.

```console
$ SSLKEYLOGFILE=/tmp/wireshark-keys.log python3 testapp.py server
```

Just as a side note, the same `SSLKEYLOGFILE` environment variable works also for Chrome and Firefox.

```console
$ SSLKEYLOGFILE=/tmp/wireshark-keys.log google-chrome https://localhost:8443
```
