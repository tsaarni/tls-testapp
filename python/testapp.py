#!/bin/env python3

import http.client
import http.server
import logging
import ssl
import sys
import time


class TestApp:

    def __init__(self):
        pass

    def server(self):
        address = 'localhost'
        port = 8443

        class MyHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                logging.info(f"{self.client_address[0]} - - [{self.log_date_time_string()}] {format % args}")

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Hello, world!')

        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile='certs/server.pem', keyfile='certs/server-key.pem')
        ssl_context.load_verify_locations(cafile='certs/client-ca.pem')
        # Force TLSv1.2 for better visibility of the TLS handshake.
        # ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2

        logging.info(f'Starting server on {address}:{port}')
        server = http.server.HTTPServer((address, port), MyHandler)
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        server.serve_forever()

    def client(self):
        address = 'server.127-0-0-1.nip.io'
        port = 8443

        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.load_cert_chain(certfile='certs/client.pem', keyfile='certs/client-key.pem')
        ssl_context.load_verify_locations(cafile='certs/server-ca.pem')

        while True:
            conn = http.client.HTTPSConnection(address, port, context=ssl_context)
            conn.request('GET', '/')
            response = conn.getresponse()
            logging.info(f'Received response: {response.read().decode()}')
            conn.close()
            time.sleep(5)


def main():
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) != 2:
        logging.error('Required argument: server|client')
        sys.exit(1)

    if sys.argv[1] == 'server':
        TestApp().server()
    elif sys.argv[1] == 'client':
        TestApp().client()
    else:
        logging.error(f'Invalid argument: {sys.argv[1]}')


if __name__ == '__main__':
    main()
