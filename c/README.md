# TLS client server example using OpenSSL in C

This is a simple example of using OpenSSL in C language.
The client connects to server, sends a message and then closes the connection and exits.
The server accepts connections in port 9876.
It receives the message, closes the connection and then waits for new connections in a loop.
The example uses mutual TLS authentication: the server and client authenticate each other using X509 certificates.

Client and server are implemented in the same file.
See [`testapp.c`](testapp.c) for the source code.

## Prerequisites

First generate certificates and compile the code:

```console
$ make certs
$ make
```

The `make certs` command generates certificates using [`certyaml`](https://github.com/tsaarni/certyaml).

## Running the example

Run the testapp in two separate terminals.
In one terminal, run the server:

```console
$ ./testapp -v server
```

In another terminal, run the client:

```console
$ ./testapp -v client
```

The verbose flag `-v` enables debug level logs.

## TLS decryption

The example writes the TLS master secrets to a file, which can be used to decrypt the TLS traffic in Wireshark.
Run the following command:

```console
$ wireshark -i lo -k -f "port 9876" -o tls.keylog_file:wireshark-keys.log
```
