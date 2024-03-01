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

#include "debug.h"

#define SERVER_ADDR "localhost"
#define SERVER_PORT 9876

#define KEYLOG_FILE "wireshark-keylog.txt"

int create_socket(char *hostname, int port, struct addrinfo **res) {
	DEBUG("Creating socket");

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		PERROR("socket");
		exit(EXIT_FAILURE);
	}

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	char port_str[6];
	snprintf(port_str, sizeof(port_str), "%d", port);

	if (getaddrinfo(hostname, port_str, &hints, res) != 0) {
		PERROR("getaddrinfo");
		exit(EXIT_FAILURE);
	}

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

	BIO_free(bio);
	X509_free(cert);
}

void *run_client(void *arg) {
	(void)arg;

	DEBUG_SET_THREAD_NAME("client");

	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {
		perror("SSL_CTX_new");
		return NULL;
	}

	SSL_CTX_set_keylog_callback(ctx, keylog_callback);

	if (load_credentials(ctx, "client.pem", "client-key.pem") != 0) {
		return NULL;
	}

	if (!SSL_CTX_load_verify_locations(ctx, "server-ca.pem", NULL)) {
		PERROR("SSL_CTX_load_verify_locations");
		return NULL;
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	DEBUG("Connecting to %s:%d", SERVER_ADDR, SERVER_PORT);

	struct addrinfo *res;
	int sock = create_socket(SERVER_ADDR, SERVER_PORT, &res);

	// Retry connection until success
	while (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
		PERROR("Attempting reconnect...");
		usleep(100000);
	}

	SSL *ssl = SSL_new(ctx);
	if (!ssl) {
		PERROR("SSL_new");
		return NULL;
	}
	SSL_set_fd(ssl, sock);

	DEBUG("SSL_connect");
	if (SSL_connect(ssl) <= 0) {
		PERROR("SSL_connect");
		return NULL;
	}

	DEBUG("Connected with TLS version %s, cipher %s", SSL_get_version(ssl),
		  SSL_get_cipher(ssl));

	print_peer_cert_info(ssl);

	if (SSL_get_verify_result(ssl) != X509_V_OK) {
		PERROR("SSL_get_verify_result");
		return NULL;
	}

	X509 *cert = SSL_get_peer_certificate(ssl);
	if (!cert) {
		PERROR("SSL_get_peer_certificate");
		return NULL;
	}

	if (X509_check_host(cert, SERVER_ADDR, 0, 0, NULL) != 1) {
		DEBUG("Certificate does not match the server hostname");
		return NULL;
	}

	DEBUG("Sending: Hello, world!");
	int len = SSL_write(ssl, "Hello, world!", 13);
	if (len < 0) {
		PERROR("SSL_write");
		return NULL;
	}

	// TLSv1.3: we need to read (at least) 0 bytes to complete the handshake.
	len = SSL_read(ssl, NULL, 0);

	SSL_free(ssl);
	close(sock);
	SSL_CTX_free(ctx);

	return 0;
}

void *run_server(void *arg) {
	(void)arg;

	DEBUG_SET_THREAD_NAME("server");

	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		PERROR("SSL_CTX_new");
		return NULL;
	}

	SSL_CTX_set_keylog_callback(ctx, keylog_callback);

	if (set_min_max_proto_versions(ctx, TLS1_2_VERSION, TLS1_3_VERSION) != 0) {
		return NULL;
	}

	if (load_credentials(ctx, "server.pem", "server-key.pem") != 0) {
		return NULL;
	}

	if (!SSL_CTX_load_verify_locations(ctx, "client-ca.pem", NULL)) {
		PERROR("SSL_CTX_load_verify_locations");
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
					   NULL);

	struct addrinfo *res;
	int sock = create_socket(SERVER_ADDR, SERVER_PORT, &res);
	if (bind(sock, res->ai_addr, res->ai_addrlen) != 0) {
		PERROR("bind");
		return NULL;
	}

	DEBUG("Listening on %s:%d", SERVER_ADDR, SERVER_PORT);
	if (listen(sock, 1) != 0) {
		PERROR("listen");
		return NULL;
	}

	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	int client_sock = accept(sock, (struct sockaddr *)&addr, &addr_len);
	if (client_sock < 0) {
		perror("accept");
		return NULL;
	}

	DEBUG("Client connected from %s:%d", inet_ntoa(addr.sin_addr),
		  ntohs(addr.sin_port));

	SSL *ssl = SSL_new(ctx);
	if (!ssl) {
		PERROR("SSL_new");
		return NULL;
	}
	SSL_set_fd(ssl, client_sock);

	DEBUG("SSL_accept");
	if (SSL_accept(ssl) <= 0) {
		PERROR("SSL_accept");
		return NULL;
	}

	print_peer_cert_info(ssl);

	if (SSL_get_verify_result(ssl) != X509_V_OK) {
		PERROR("SSL_get_verify_result");
		return NULL;
	}

	DEBUG("Connected with TLS version %s, cipher %s", SSL_get_version(ssl),
		  SSL_get_cipher(ssl));

	char buf[1024];
	int len = SSL_read(ssl, buf, sizeof(buf) - 1);
	if (len < 0) {
		PERROR("SSL_read");
		return NULL;
	}
	buf[len] = '\0';
	DEBUG("Received: %s", buf);

	SSL_free(ssl);
	close(client_sock);
	close(sock);
	SSL_CTX_free(ctx);

	return 0;
}

int main() {
	pthread_t server_thread;
	pthread_create(&server_thread, NULL, run_server, NULL);

	pthread_t client_thread;
	pthread_create(&client_thread, NULL, run_client, NULL);

	pthread_join(client_thread, NULL);
	pthread_join(server_thread, NULL);

	return 0;
}
