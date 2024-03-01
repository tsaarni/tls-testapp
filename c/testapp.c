#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "logger.h"

#define SERVER_ADDR "localhost"
#define SERVER_PORT 9876

#define KEYLOG_FILE "wireshark-keylog.txt"

// Allocate a thread-local variable for the thread name.
_Thread_local char *thread_name = "main";

int create_socket(char *hostname, int port, struct sockaddr_in *addr) {
    DEBUG("Creating socket");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        PERROR("socket");
        exit(EXIT_FAILURE);
    }

    struct hostent *host = gethostbyname(hostname);
    if (host == NULL) {
        close(sock);
        return -1;
    }

    memset(addr, 0, sizeof(*addr));
    addr->sin_family = host->h_addrtype;
    addr->sin_port = htons(port);
    memcpy(&addr->sin_addr.s_addr, host->h_addr, host->h_length);

    return sock;
}

int load_credentials(SSL_CTX *ctx, char *cert_file, char *key_file) {
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        PERROR("SSL_CTX_use_certificate_file");
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        PERROR("SSL_CTX_use_PrivateKey_file");
        return -1;
    }

    return 0;
}

int set_min_max_proto_versions(SSL_CTX *ctx, int min_version, int max_version) {
    if (SSL_CTX_set_min_proto_version(ctx, min_version) != 1) {
        PERROR("SSL_CTX_set_min_proto_version");
        return -1;
    }

    if (SSL_CTX_set_max_proto_version(ctx, max_version) != 1) {
        PERROR("SSL_CTX_set_max_proto_version");
        return -1;
    }

    return 0;
}

void keylog_callback(const SSL *ssl, const char *line) {
    (void)ssl;

    FILE *file = fopen(KEYLOG_FILE, "a");
    if (!file) {
        PERROR("fopen");
        return;
    }

    fprintf(file, "%s\n", line);
    fclose(file);
}

void print_peer_cert_info(SSL *ssl) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    X509_NAME *name = X509_get_subject_name(cert);

    BIO *bio = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);

    char *subject = NULL;
    BIO_get_mem_data(bio, &subject);
    DEBUG("Subject: %s", subject);

    // Print the certificate subject alt name
    GENERAL_NAMES *names =
        X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (names) {
        for (int i = 0; i < sk_GENERAL_NAME_num(names); i++) {
            GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
            if (name->type == GEN_DNS) {
                char *dns_name = (char *)ASN1_STRING_get0_data(name->d.dNSName);
                DEBUG("Subject alt name: %s", dns_name);
            }
        }
        GENERAL_NAMES_free(names);
    }

    BIO_free_all(bio);
    X509_free(cert);
}

void *run_client(void *arg) {
    (void)arg;

    DEBUG_SET_THREAD_NAME("client");

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        PERROR("SSL_CTX_new");
        goto clenup;
    }

    SSL_CTX_set_keylog_callback(ctx, keylog_callback);

    if (load_credentials(ctx, "client.pem", "client-key.pem") != 0) {
        goto clenup;
    }

    if (!SSL_CTX_load_verify_locations(ctx, "server-ca.pem", NULL)) {
        PERROR("SSL_CTX_load_verify_locations");
        goto clenup;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    DEBUG("Connecting to %s:%d", SERVER_ADDR, SERVER_PORT);

    struct sockaddr_in addr;
    int sock = create_socket(SERVER_ADDR, SERVER_PORT, &addr);

    // Retry connection until success.
    while (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        PERROR("Attempting reconnect...");
        usleep(100000);
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        PERROR("SSL_new");
        goto clenup;
    }
    SSL_set_fd(ssl, sock);

    // Set the SNI extension.
    if (SSL_set_tlsext_host_name(ssl, SERVER_ADDR) != 1) {
        PERROR("SSL_set_tlsext_host_name");
        goto clenup;
    }

    // Check the server's certificate against the hostname.
    if (SSL_set1_host(ssl, SERVER_ADDR) != 1) {
        PERROR("SSL_set1_host");
        goto clenup;
    }

    DEBUG("SSL_connect");
    if (SSL_connect(ssl) <= 0) {
        PERROR("SSL_connect");
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            ERROR("Certificate verification failed: %s",
                  X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        }
        goto clenup;
    }

    DEBUG("Connected with TLS version %s, cipher %s", SSL_get_version(ssl),
          SSL_get_cipher(ssl));

    print_peer_cert_info(ssl);

    DEBUG("Sending: Hello, world!");
    char *msg = "Hello, world!";
    size_t written;
    if (SSL_write_ex(ssl, msg, strlen(msg), &written) != 1) {
        PERROR("SSL_write_ex");
        goto clenup;
    }

    // TLSv1.3: we need to read (at least) 0 bytes to complete the handshake.
    SSL_read_ex(ssl, NULL, 0, NULL);

    if (SSL_shutdown(ssl) < 0) {
        PERROR("SSL_shutdown");
        goto clenup;
    }

clenup:
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return NULL;
}

void *run_server(void *arg) {
    (void)arg;

    DEBUG_SET_THREAD_NAME("server");

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        PERROR("SSL_CTX_new");
        goto cleanup;
    }

    SSL_CTX_set_keylog_callback(ctx, keylog_callback);

    if (set_min_max_proto_versions(ctx, TLS1_2_VERSION, TLS1_3_VERSION) != 0) {
        goto cleanup;
    }

    if (load_credentials(ctx, "server.pem", "server-key.pem") != 0) {
        goto cleanup;
    }

    if (!SSL_CTX_load_verify_locations(ctx, "client-ca.pem", NULL)) {
        PERROR("SSL_CTX_load_verify_locations");
        goto cleanup;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);

    struct sockaddr_in server_addr;
    int sock = create_socket(SERVER_ADDR, SERVER_PORT, &server_addr);
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        PERROR("bind");
        goto cleanup;
    }

    DEBUG("Listening on %s:%d", SERVER_ADDR, SERVER_PORT);
    if (listen(sock, 1) != 0) {
        PERROR("listen");
        goto cleanup;
    }

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_sock =
        accept(sock, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_sock < 0) {
        PERROR("accept");
        goto cleanup;
    }

    DEBUG("Client connected from %s:%d", inet_ntoa(client_addr.sin_addr),
          ntohs(client_addr.sin_port));

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        PERROR("SSL_new");
        goto cleanup;
    }
    SSL_set_fd(ssl, client_sock);

    DEBUG("SSL_accept");
    if (SSL_accept(ssl) <= 0) {
        PERROR("SSL_accept");
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            ERROR("Certificate verification failed: %s",
                  X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        }
        goto cleanup;
    }

    print_peer_cert_info(ssl);

    DEBUG("Connected with TLS version %s, cipher %s", SSL_get_version(ssl),
          SSL_get_cipher(ssl));

    char buf[1024];
    size_t len;
    if (SSL_read_ex(ssl, buf, sizeof(buf), &len) != 1) {
        PERROR("SSL_read_ex");
        goto cleanup;
    }

    buf[len] = '\0';
    DEBUG("Received: %s", buf);

    if (SSL_shutdown(ssl) < 0) {
        PERROR("SSL_shutdown");
        goto cleanup;
    }

cleanup:
    SSL_free(ssl);
    close(client_sock);
    close(sock);
    SSL_CTX_free(ctx);
    return NULL;
}

int main() {
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, run_server, NULL);

    pthread_t client_thread;
    pthread_create(&client_thread, NULL, run_client, NULL);

    pthread_join(client_thread, NULL);
    pthread_join(server_thread, NULL);

    DEBUG("Server and client threads have finished. Exiting.");

    return 0;
}
