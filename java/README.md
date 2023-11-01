# TLS client server example in Java

This is a simple TLS client server example in Java.
The client transmits the string `Hello world` periodically to the server and the server echoes the message back.
The example uses mutual TLS authentication, i.e. both the client and the server authenticate each other using X509 certificates.
The client and server are implemented in the same file, see [`App.java`](app/src/main/java/testapp/App.java) for the code.


## Pre-requisites

First run [GenerateCerts.java](app/src/main/java/testapp/GenerateCerts.java), which uses [java-certy](https://github.com/tsaarni/java-certy) library for generating certificates.

```console
$ gradle generateCerts
```


## Running the test application

Run the testapp server and client

```console
$ gradle server  # run in one terminal
$ gradle client  # run in another terminal
```

Capture traffic with Wireshark and observe the TLS handshake.

```console
$ wireshark  -k -i lo -f "port 9090"
```


## TLS decryption

The TLS master secrets can be intercepted by a Java agent and logged into a file.
This file can then be used by Wireshark to decrypt the TLS traffic.

In this example, we use the agent [extract-tls-secrets](https://github.com/neykov/extract-tls-secrets), courtesy of [@neykov](https://github.com/neykov).
You can compile the agent from source code or download the pre-compiled JAR by running

```console
$ gradle downloadAgent
```

To run the server with the agent attached, use the following command

```console
$ gradle serverWithAgent
```

See [build.gradle](app/build.gradle) for the details.
The example intercepts the TLS master secrets from the server, but the same can be done for the client.

Decrypt the TLS traffic in Wireshark by providing the path to the log file

```console
$ wireshark -i lo -k -f "port 9090" -o tls.keylog_file:/tmp/wireshark-keys.log
```

Alternatively, the agent can also be attached to a running JVM process

```console
java -jar app/build/extract-tls-secrets-4.0.0.jar <PID> /tmp/wireshark-keys.log
```

Note that Wireshark must capture the traffic beginning from the handshake, otherwise, it cannot decrypt the traffic.
