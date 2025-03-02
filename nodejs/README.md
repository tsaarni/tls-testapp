# TLS client and server example for TypeScript and Node.js

This is a simple TLS client server example in Node.JS and TypeScript.
The example uses mutual TLS authentication, i.e. both the client and the server authenticate each other using X509 certificates.
The client and server are implemented in the same file, see [`src/tls.ts`](src/tls.ts) for the code.

## Prerequisites

## Running the test application

```console
$ npm run start:server  # run in one terminal
$ npm run start:client  # run in another terminal
```

## TLS decryption

Set the `SSLKEYLOGFILE` environment variable to a file where the TLS master secrets are written.
For example:

```console
$ SSLKEYLOGFILE=wireshark-keys.log npm run start:server
```

Then run Wireshark and set the `tls.keylog_file` preference to the file you set `SSLKEYLOGFILE` to:

```console
$ wireshark -i lo -k -f "port 9876" -o tls.keylog_file:wireshark-keys.log
```
