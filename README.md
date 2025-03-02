# TLS client and server examples

This repository contains examples of TLS client and server applications written in Go, Java, Python, Node.js and C with OpenSSL and Rust with rustls.
Each example also shows how to use Wireshark to capture and decrypt TLS traffic by intercepting TLS master secrets in language-specific ways.

## Pre-requisites

Before running the examples, you need to create certificates and keys for the server and client.
Use Makefile to generate them:

```console
make certs
```

The Makefile uses [`certyaml`](https://github.com/tsaarni/certyaml) to generate certificates and keys.
