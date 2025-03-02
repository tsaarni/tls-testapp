import socket
import ssl
import argparse
import logging
import time
import sys
from datetime import datetime

SERVER_HOST = "server.127-0-0-1.nip.io"
SERVER_PORT = 14443

CLIENT_CA_FILE = "../certs/client-ca.pem"
CLIENT_CERT_FILE = "../certs/client.pem"
CLIENT_KEY_FILE = "../certs/client-key.pem"

SERVER_CA_FILE = "../certs/server-ca.pem"
SERVER_CERT_FILE = "../certs/server.pem"
SERVER_KEY_FILE = "../certs/server-key.pem"


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)


class Tls:

    def __init__(self):
        self.logger = logging.getLogger("tls")

    def server(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile=SERVER_CERT_FILE, keyfile=SERVER_KEY_FILE)
        context.load_verify_locations(cafile=CLIENT_CA_FILE)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((SERVER_HOST, SERVER_PORT))
            server_sock.listen()
            self.logger.info(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

            while True:
                client_sock, addr = server_sock.accept()
                self.logger.info(f"Connection from {addr}")
                try:
                    self.handle_client(client_sock, context)
                except Exception as e:
                    self.logger.error(f"Error while handling client: {e}")
                client_sock.close()

    def handle_client(self, client_sock, context):
        secure_sock = context.wrap_socket(client_sock, server_side=True)
        self.log_certificate_details(secure_sock)
        while True:
            data = secure_sock.recv(1024)
            if not data:
                break

            message = data.decode("utf-8")
            self.logger.info(f"Received: {message}")

            secure_sock.send(data)
            self.logger.info(f"Sent: {message}")

        secure_sock.close()
        self.logger.info("Closing connection")

    def client(self):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile=CLIENT_CERT_FILE, keyfile=CLIENT_KEY_FILE)
        context.load_verify_locations(cafile=SERVER_CA_FILE)

        self.logger.info(f"Connecting to server {SERVER_HOST}:{SERVER_PORT}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            secure_sock = context.wrap_socket(sock, server_hostname=SERVER_HOST)
            secure_sock.connect((SERVER_HOST, SERVER_PORT))
            self.log_certificate_details(secure_sock)

            count = 1
            while True:
                message = f"Hello world {count}"
                secure_sock.send(message.encode("utf-8"))
                self.logger.info(f"Sent: {message}")

                data = secure_sock.recv(1024)
                if not data:
                    self.logger.info("Server closed connection")
                    break

                self.logger.info("Received: %s", data.decode("utf-8"))
                count += 1

                time.sleep(1)

            secure_sock.close()

        self.logger.info("Closing connection")

    def log_certificate_details(self, secure_sock):
        cert = secure_sock.getpeercert()

        def format_dn(dn):
            return ", ".join(f"{name}={value}" for rdn in dn for name, value in rdn)

        subject = format_dn(cert["subject"])
        issuer = format_dn(cert["issuer"])

        self.logger.debug(f"Subject: {subject}")
        self.logger.debug(f"Issuer: {issuer}")

        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")

        self.logger.debug(f"Valid from: {not_before}")
        self.logger.debug(f"Valid until: {not_after}")

        sans = cert.get("subjectAltName", [])
        if sans:
            san_list = [f"{name}: {value}" for name, value in sans]
            self.logger.debug(f"Subject Alternative Names: {', '.join(san_list)}")


def main():
    parser = argparse.ArgumentParser(description="TLS example")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "mode", choices=["client", "server"], help="Run as client or server"
    )
    args = parser.parse_args()

    try:
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        tls = Tls()
        if args.mode == "client":
            tls.client()
        elif args.mode == "server":
            tls.server()
        else:
            parser.print_help()
            sys.exit(1)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.error(f"Error: {e}")


if __name__ == "__main__":
    main()
