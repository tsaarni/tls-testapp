import * as tls from 'tls';
import * as fs from 'fs';

const config = {
  addr: 'server.127-0-0-1.nip.io',
  port: 14443,

  serverKey: '../certs/server-key.pem',
  serverCert: '../certs/server.pem',
  serverCaCert: '../certs/client-ca.pem',
  clientKey: '../certs/client-key.pem',
  clientCert: '../certs/client.pem',
  clientCaCert: '../certs/server-ca.pem',
};

export class Tls {
  static async server() {
    const options = {
      key: fs.readFileSync(config.serverKey),
      cert: fs.readFileSync(config.serverCert),
      ca: fs.readFileSync(config.serverCaCert),

      requestCert: true,
      rejectUnauthorized: true,
    };
    const server = tls.createServer(options, (socket) => {
      console.log('Server: client connected', socket.remoteAddress, socket.remotePort);
      socket.setEncoding('utf8');
      socket.on('data', (data) => {
        console.log('Received:', data);
        socket.write(data);
        console.log('Sent:', data);
      });
      socket.on('end', () => {
        console.log('Client disconnected');
      });
      socket.on('error', (err) => {
        console.error('Error', err);
      });
    });

    server.listen(config.port, config.addr, () => {
      console.log(`Server listening on ${config.addr}:${config.port}`);
    });

    server.on('tlsClientError', (err, socket) => {
      console.error('Client error', err);
      socket.destroy();
    });

    server.on('error', (err) => {
      console.error('Server error', err);
    });

    if (process.env.SSLKEYLOGFILE) {
      console.log(`Keylog enabled: ${process.env.SSLKEYLOGFILE}`);
      server.on('keylog', (line) => {
        fs.appendFileSync(process.env.SSLKEYLOGFILE!, line.toString());
      });
    }

  }

  static async client() {
    const options = {
      host: config.addr,
      port: config.port,
      key: fs.readFileSync(config.clientKey),
      cert: fs.readFileSync(config.clientCert),
      ca: fs.readFileSync(config.clientCaCert),
      rejectUnauthorized: true,
    };

    const socket = tls.connect(options, () => {
      console.log(`Connected to ${options.host}:${options.port}`);
    });

    socket.setEncoding('utf8');

    let counter = 1;
    setInterval(() => {
      const message = `Hello world ${counter++}`;
      console.log('Sent:', message);
      socket.write(message);
    }, 1000);

    socket.on('data', (data) => {
      console.log('Received:', data);
    });

    socket.on('error', (err) => {
      console.error('TLS handshake error:', err);
      process.exit(1);
    });

    socket.on('end', () => {
      console.log('Disconnected');
      process.exit(0);
    });

    if (process.env.SSLKEYLOGFILE) {
      console.log(`Keylog enabled: ${process.env.SSLKEYLOGFILE}`);
      socket.on('keylog', (line) => {
        fs.appendFileSync(process.env.SSLKEYLOGFILE!, line.toString());
      });
    }

  }
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('server')) {
    Tls.server();
  }

  if (args.includes('client')) {
    Tls.client();
  }

  if (!args.includes('server') && !args.includes('client')) {
    console.log('Usage: server|client.');
  }
}

main();
