# TLS key logging example for Java

## Pre-requisites

Generate certificates for the testapp using [java-certy](https://github.com/tsaarni/java-certy)

```console
gradle generateCerts
```

Compile Java agent that will extract the TLS secrets

```console
$ git clone https://github.com/neykov/extract-tls-secrets.git
$ cd extract-tls-secrets
$ mvn package
```

The compiled JAR will be in `target/extract-tls-secrets-4.1.0-SNAPSHOT.jar`



## Running the testapp

Run the testapp server and client

```console
$ gradle server  # in one terminal
$ gradle client  # in another terminal
```

The server app will be automatically started with the agent.

Decrypt the TLS traffic in Wireshark by providing the path to the log file

```console
$ sudo wireshark -i lo -k -f "port 9090" -o tls.keylog_file:/tmp/wireshark-keys.log
```

Alternatively, the agent can also be attached to a running JVM process

```console
java -jar ./target/extract-tls-secrets-4.1.0-SNAPSHOT.jar <PID> /tmp/wireshark-keys.log
```
