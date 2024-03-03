// Reference for OpenSSL API
// https://www.openssl.org/docs/man3.2/man7/ossl-guide-introduction.html

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logger.h"

#define SERVER_ADDR "localhost"
#define SERVER_PORT 9876

#define CLIENT_CA_FILE "server-sub-ca.pem"
#define CLIENT_CERT_FILE "client.pem"
#define CLIENT_KEY_FILE "client-key.pem"

#define SERVER_CA_FILE "client-ca.pem"
#define SERVER_CERT_FILE "server.pem"
#define SERVER_KEY_FILE "server-key.pem"

#define KEYLOG_FILE "wireshark-keys.log"

// Debug level logs are disabled by default.
static bool log_level_verbose = false;

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

int load_credentials(SSL_CTX *ctx, const char *cert_file, const char *key_file) {
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        PERROR("SSL_CTX_use_certificate_file failed to load %s", cert_file);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        PERROR("SSL_CTX_use_PrivateKey_file failed to load %s", key_file);
        return -1;
    }

    return 0;
}

int set_min_max_proto_versions(SSL_CTX *ctx, int min_version, int max_version) {
    if (SSL_CTX_set_min_proto_version(ctx, min_version) != 1) {
        PERROR("SSL_CTX_set_min_proto_version failed to set %d", min_version);
        return -1;
    }

    if (SSL_CTX_set_max_proto_version(ctx, max_version) != 1) {
        PERROR("SSL_CTX_set_max_proto_version failed to set %d", max_version);
        return -1;
    }

    return 0;
}

void keylog_callback(const SSL *ssl, const char *line) {
    (void)ssl;

    FILE *file = fopen(KEYLOG_FILE, "a");
    if (!file) {
        PERROR("fopen failed to open %s", KEYLOG_FILE);
        return;
    }

    fprintf(file, "%s\n", line);
    fclose(file);

    return;
}

void print_peer_cert_info(SSL *ssl) {
    BIO *bio = NULL;
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        INFO("No peer certificate provided");
        goto cleanup;
    }

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        PERROR("BIO_new failed");
        goto cleanup;
    }

    if (X509_print_ex(bio, cert, XN_FLAG_RFC2253, X509_FLAG_COMPAT) <= 0) {
        PERROR("X509_print_ex failed");
        goto cleanup;
    }

    char buf[1024];
    while (BIO_gets(bio, buf, sizeof(buf)) > 0) {
        buf[strlen(buf) - 1] = '\0'; // Remove the linefeed at the end.
        DEBUG("%s", buf);
    }

cleanup:
    if (bio)
        BIO_free_all(bio);
    if (cert)
        X509_free(cert);

    return;
}

// Enable partial chain validation to allow configuring sub-CA certificates as trust anchors,
// instead of only root CAs.
void enable_partial_chain_validation(SSL_CTX *ctx) {
    X509_VERIFY_PARAM *param = SSL_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN);
    SSL_CTX_set1_param(ctx, param);
}

void run_client() {
    SSL *ssl = NULL;
    int sock = -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        PERROR("SSL_CTX_new failed");
        goto cleanup;
    }

    // Enable key logging for Wireshark.
    SSL_CTX_set_keylog_callback(ctx, keylog_callback);

    if (load_credentials(ctx, CLIENT_CERT_FILE, CLIENT_KEY_FILE) != 0) {
        goto cleanup;
    }

    // Load the server's CA certificate.
    const char *ca_file = "server-sub-ca.pem";
    if (!SSL_CTX_load_verify_locations(ctx, CLIENT_CA_FILE, NULL)) {
        PERROR("SSL_CTX_load_verify_locations failed to load %s", ca_file);
        goto cleanup;
    }

    enable_partial_chain_validation(ctx);

    // Require the server to present a certificate.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    INFO("Connecting to %s:%d", SERVER_ADDR, SERVER_PORT);

    // Retry connection until success.
    do {
        struct sockaddr_in addr;
        sock = create_socket(SERVER_ADDR, SERVER_PORT, &addr);

        int res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        if (res == 0) {
            // Connection succeeded.
            break;
        }

        PERROR("connect failed");
        close(sock);
        sock = -1;

        // Retry only on connection refused.
        if (errno != ECONNREFUSED) {
            goto cleanup;
        }

        DEBUG("Retrying in 2 second");
        sleep(2);
    } while (true);

    ssl = SSL_new(ctx);
    if (!ssl) {
        PERROR("SSL_new failed");
        goto cleanup;
    }
    SSL_set_fd(ssl, sock);

    // Set the hostname to the SNI extension.
    if (SSL_set_tlsext_host_name(ssl, SERVER_ADDR) != 1) {
        PERROR("SSL_set_tlsext_host_name failed to set %s", SERVER_ADDR);
        goto cleanup;
    }

    // Check the server's certificate against the hostname.
    if (SSL_set1_host(ssl, SERVER_ADDR) != 1) {
        PERROR("SSL_set1_host failed to set %s", SERVER_ADDR);
        goto cleanup;
    }

    DEBUG("SSL_connect");
    if (SSL_connect(ssl) <= 0) {
        PERROR("SSL_connect failed");
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            ERROR("Certificate verification result: %s", X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        }
        goto cleanup;
    }

    DEBUG("Connected with TLS version %s, cipher %s", SSL_get_version(ssl), SSL_get_cipher(ssl));

    print_peer_cert_info(ssl);

    char *msg = "Hello, world!";
    INFO("Sending: %s", msg);
    size_t written;
    if (SSL_write_ex(ssl, msg, strlen(msg), &written) != 1) {
        PERROR("SSL_write_ex failed");
        goto cleanup;
    }

    // TLSv1.3: we need to read (at least) 0 bytes to complete the handshake.
    SSL_read_ex(ssl, NULL, 0, NULL);

    INFO("Closing connection");

    if (SSL_shutdown(ssl) < 0) {
        PERROR("SSL_shutdown failed");
        goto cleanup;
    }

cleanup:
    if (ssl)
        SSL_free(ssl);
    if (sock >= 0)
        close(sock);
    if (ctx)
        SSL_CTX_free(ctx);

    return;
}

void handle_client_connection(SSL_CTX *ctx, int client_sock) {
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        PERROR("SSL_new failed");
        goto cleanup;
    }
    SSL_set_fd(ssl, client_sock);

    DEBUG("SSL_accept");
    if (SSL_accept(ssl) <= 0) {
        PERROR("SSL_accept failed");
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            ERROR("Certificate verification result: %s", X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        }
        goto cleanup;
    }

    print_peer_cert_info(ssl);

    DEBUG("Connected with TLS version %s, cipher %s", SSL_get_version(ssl), SSL_get_cipher(ssl));

    char buf[1024];
    size_t len;
    if (SSL_read_ex(ssl, buf, sizeof(buf), &len) != 1) {
        PERROR("SSL_read_ex failed");
        goto cleanup;
    }

    buf[len] = '\0';
    INFO("Received: %s", buf);

    INFO("Closing client connection");

    if (SSL_shutdown(ssl) < 0) {
        PERROR("SSL_shutdown failed");
        goto cleanup;
    }

cleanup:
    if (ssl)
        SSL_free(ssl);

    return;
}

void run_server() {
    int sock = -1;
    int client_sock = -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        PERROR("SSL_CTX_new failed");
        goto cleanup;
    }

    // Enable key logging for Wireshark.
    SSL_CTX_set_keylog_callback(ctx, keylog_callback);

    if (set_min_max_proto_versions(ctx, TLS1_2_VERSION, TLS1_3_VERSION) != 0) {
        goto cleanup;
    }

    if (load_credentials(ctx, SERVER_CERT_FILE, SERVER_KEY_FILE) != 0) {
        goto cleanup;
    }

    // Load the client's CA certificate.
    const char *ca_file = "client-ca.pem";
    if (!SSL_CTX_load_verify_locations(ctx, SERVER_CA_FILE, NULL)) {
        PERROR("SSL_CTX_load_verify_locations failed to load %s", ca_file);
        goto cleanup;
    }

    // Require the client to present a certificate.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    struct sockaddr_in server_addr;
    sock = create_socket(SERVER_ADDR, SERVER_PORT, &server_addr);
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        PERROR("bind failed on %s:%d", SERVER_ADDR, SERVER_PORT);
        goto cleanup;
    }

    INFO("Listening on %s:%d", SERVER_ADDR, SERVER_PORT);
    if (listen(sock, 1) != 0) {
        PERROR("listen failed");
        goto cleanup;
    }

    // Server loop handling client connections.
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        client_sock = accept(sock, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_sock < 0) {
            PERROR("accept failed");
            continue;
        }

        INFO("Client connected from %s:%d", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        handle_client_connection(ctx, client_sock);

        close(client_sock);
    }

cleanup:
    if (sock >= 0)
        close(sock);
    if (ctx)
        SSL_CTX_free(ctx);

    return;
}

int main(int argc, char *argv[]) {
    const char *usage = "Usage: %s [-v] client|server\n";

    int opt;
    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
        case 'v':
            LOGGER_VERBOSE(true);
            break;
        default:
            fprintf(stderr, usage, argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // No positional argument.
    if (optind == argc) {
        fprintf(stderr, usage, argv[0]);
        exit(EXIT_FAILURE);
    }

    // Parse the positional argument.
    if (strcmp(argv[optind], "client") == 0) {
        run_client();
    } else if (strcmp(argv[optind], "server") == 0) {
        run_server();
    } else {
        fprintf(stderr, usage, argv[0]);
        exit(EXIT_FAILURE);
    }

    return 0;
}
