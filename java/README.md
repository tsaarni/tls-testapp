# TLS client server example in Java

This is a simple TLS client server example in Java.
The client transmits the string `Hello world` periodically to the server and the server echoes the message back.
The example uses mutual TLS authentication, i.e. both the client and the server authenticate each other using X509 certificates.
The client and server are implemented in the same file, see [`App.java`](app/src/main/java/testapp/App.java) for the code.


## Pre-requisites

First run `make certs` in git repository root to generate the necessary certificates.


## Running the test application

Run the testapp server and client

```console
$ gradle server  # run in one terminal
$ gradle client  # run in another terminal
```

Capture traffic with Wireshark and observe the TLS handshake.

```console
$ wireshark  -k -i lo -f "port 14443"
```


## TLS decryption

The TLS master secrets can be intercepted by a Java agent and logged into a file.
This file can then be used by Wireshark to decrypt the TLS traffic.

The example uses [extract-tls-secrets](https://github.com/neykov/extract-tls-secrets), courtesy of [@neykov](https://github.com/neykov).

To run the client or server with the agent attached, use the `useAgent` property.

```console
$ gradle <client|server> -PuseAgent
```

The agent will log the TLS master secrets into a file `wireshark-keys.log` in the project root directory.

To decrypt the TLS traffic in Wireshark, run

```console
$ wireshark -i lo -k -f "port 14443" -o tls.keylog_file:wireshark-keys.log
```

Alternatively, the agent can also be attached to a running JVM process

```console
java -jar app/build/extract-tls-secrets-4.0.0.jar <PID> wireshark-keys.log
```

Note that Wireshark must capture the traffic beginning from the handshake, otherwise, it cannot decrypt the traffic.


## List protocols and ciphers

To check what JDK lists as available protocols and ciphers, run

```console
$ gradle ciphers
```

To see what is impact when disabling specific protocols for the default `SSLContext`:

```console
$ java -Djdk.tls.server.protocols=TLSv1.3 -Djdk.tls.client.protocols=TLSv1.3 app/src/main/java/testapp/Ciphers.java
```
