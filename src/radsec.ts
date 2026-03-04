/**
 * radsec.ts — RadSec (RADIUS over TLS) — RFC 6614
 *
 * Provides RADIUS-over-TLS transport using node:tls.
 * Shares packet encode/decode with the UDP path.
 */

import * as tls from 'node:tls';
import * as net from 'node:net';
import { EventEmitter } from 'node:events';
import {
  Packet, AuthPacket, AcctPacket, CoAPacket,
  AccessRequest, AccountingRequest, CoARequest, DisconnectRequest,
  PacketError, type PacketOptions,
} from './packet.js';
import { Dictionary } from './dictionary.js';
import { type Logger, NullLogger } from './logger.js';

// RadSec uses standard RADIUS packet framing over TCP/TLS.
// Each packet is self-delimiting via the 2-byte length field at offset 2.
// The shared secret is typically "radsec" for certificate-based auth.

const RADSEC_DEFAULT_PORT = 2083;
const RADSEC_DEFAULT_SECRET = Buffer.from('radsec');

export interface RadSecClientOptions {
  host: string;
  port?: number;
  /** TLS client certificate (PEM) */
  cert?: string | Buffer;
  /** TLS client private key (PEM) */
  key?: string | Buffer;
  /** CA certificate(s) for server verification */
  ca?: string | Buffer | Array<string | Buffer>;
  /** Reject unauthorized certificates (default true) */
  rejectUnauthorized?: boolean;
  /** Shared secret (default "radsec") */
  secret?: Buffer;
  /** RADIUS dictionary */
  dict?: Dictionary;
  /** Timeout in ms for connect and response (default 5000) */
  timeout?: number;
  /** Logger */
  logger?: Logger;
}

export interface RadSecServerOptions {
  /** TLS server certificate (PEM) */
  cert: string | Buffer;
  /** TLS server private key (PEM) */
  key: string | Buffer;
  /** CA certificate(s) for client verification (mutual TLS) */
  ca?: string | Buffer | Array<string | Buffer>;
  /** Require client certificate (default true) */
  requestCert?: boolean;
  /** Reject unauthorized clients (default true) */
  rejectUnauthorized?: boolean;
  /** Port to listen on (default 2083) */
  port?: number;
  /** Address to listen on (default '0.0.0.0') */
  address?: string;
  /** Shared secret (default "radsec") */
  secret?: Buffer;
  /** RADIUS dictionary */
  dict?: Dictionary;
  /** Logger */
  logger?: Logger;
}

/**
 * RadSec client — sends RADIUS packets over TLS.
 */
export class RadSecClient {
  private host: string;
  private port: number;
  private tlsOptions: tls.ConnectionOptions;
  private secret: Buffer;
  private dict: Dictionary;
  private timeout: number;
  private socket: tls.TLSSocket | null = null;
  private buffer: Buffer = Buffer.alloc(0);
  private pendingResolve: ((pkt: Packet) => void) | null = null;
  private pendingReject: ((err: Error) => void) | null = null;
  private pendingOriginal: Packet | null = null;
  private logger: Logger;

  constructor(opts: RadSecClientOptions) {
    this.host = opts.host;
    this.port = opts.port ?? RADSEC_DEFAULT_PORT;
    this.secret = opts.secret ?? RADSEC_DEFAULT_SECRET;
    this.dict = opts.dict ?? new Dictionary();
    this.timeout = opts.timeout ?? 5000;
    this.logger = opts.logger ?? new NullLogger();

    this.tlsOptions = {
      host: this.host,
      port: this.port,
      cert: opts.cert,
      key: opts.key,
      ca: opts.ca,
      rejectUnauthorized: opts.rejectUnauthorized ?? true,
    };
  }

  /** Connect to the RadSec server. */
  async connect(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error('RadSec connect timeout'));
      }, this.timeout);

      this.socket = tls.connect(this.tlsOptions, () => {
        clearTimeout(timer);
        this.logger.info('RadSec connected', { nasAddress: this.host });
        resolve();
      });

      this.socket.on('data', (data: Buffer) => this.onData(data));
      this.socket.on('error', (err) => {
        clearTimeout(timer);
        if (this.pendingReject) {
          this.pendingReject(err);
          this.pendingResolve = null;
          this.pendingReject = null;
          this.pendingOriginal = null;
        }
        reject(err);
      });
      this.socket.on('close', () => {
        if (this.pendingReject) {
          this.pendingReject(new Error('Connection closed'));
          this.pendingResolve = null;
          this.pendingReject = null;
          this.pendingOriginal = null;
        }
      });
    });
  }

  /** Send a RADIUS packet and wait for a reply over TLS. */
  async sendPacket(pkt: Packet): Promise<Packet> {
    if (!this.socket || this.socket.destroyed) {
      throw new Error('Not connected — call connect() first');
    }

    pkt.secret = this.secret;
    const raw = (pkt as any).requestPacket
      ? (pkt as AuthPacket | AcctPacket | CoAPacket).requestPacket()
      : pkt.replyPacket();

    return new Promise<Packet>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingResolve = null;
        this.pendingReject = null;
        this.pendingOriginal = null;
        reject(new Error('RadSec response timeout'));
      }, this.timeout);

      this.pendingResolve = (reply) => {
        clearTimeout(timer);
        resolve(reply);
      };
      this.pendingReject = (err) => {
        clearTimeout(timer);
        reject(err);
      };
      this.pendingOriginal = pkt;

      this.socket!.write(raw);
    });
  }

  private onData(data: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, data]);

    // Try to parse complete RADIUS packets from the buffer
    while (this.buffer.length >= 4) {
      const length = this.buffer.readUInt16BE(2);
      if (this.buffer.length < length) break; // need more data

      const pktBuf = this.buffer.subarray(0, length);
      this.buffer = Buffer.from(this.buffer.subarray(length));

      if (this.pendingResolve && this.pendingOriginal) {
        try {
          const reply = this.pendingOriginal.createReply({
            packet: Buffer.from(pktBuf),
          });
          if (this.pendingOriginal.authenticator) {
            reply.requestAuthenticator = this.pendingOriginal.authenticator;
          }
          const cb = this.pendingResolve;
          this.pendingResolve = null;
          this.pendingReject = null;
          this.pendingOriginal = null;
          cb(reply);
        } catch (err) {
          // Bad packet
          this.logger.error('Failed to decode RadSec reply');
        }
      }
    }
  }

  /** Close the TLS connection. */
  close(): void {
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
    this.buffer = Buffer.alloc(0);
  }
}

/**
 * RadSec server — accepts RADIUS-over-TLS connections.
 */
export class RadSecServer {
  private server: tls.Server | null = null;
  private port: number;
  private address: string;
  private secret: Buffer;
  private dict: Dictionary;
  private emitter = new EventEmitter();
  private logger: Logger;

  constructor(opts: RadSecServerOptions) {
    this.port = opts.port ?? RADSEC_DEFAULT_PORT;
    this.address = opts.address ?? '0.0.0.0';
    this.secret = opts.secret ?? RADSEC_DEFAULT_SECRET;
    this.dict = opts.dict ?? new Dictionary();
    this.logger = opts.logger ?? new NullLogger();

    this.server = tls.createServer({
      cert: opts.cert,
      key: opts.key,
      ca: opts.ca,
      requestCert: opts.requestCert ?? true,
      rejectUnauthorized: opts.rejectUnauthorized ?? true,
    }, (socket) => this.handleConnection(socket));

    this.server.on('error', (err) => this.emitter.emit('error', err));
  }

  /** Start listening. */
  listen(): Promise<void> {
    return new Promise<void>((resolve) => {
      this.server!.listen(this.port, this.address, () => {
        this.logger.info('RadSec server listening', { nasAddress: `${this.address}:${this.port}` });
        this.emitter.emit('ready');
        resolve();
      });
    });
  }

  /** Stop the server. */
  close(): Promise<void> {
    return new Promise<void>((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  on(event: 'ready' | 'error' | 'packet', listener: (...args: any[]) => void): this {
    this.emitter.on(event, listener);
    return this;
  }

  /** Called when a RADIUS packet is received. Override or listen for 'packet' event. */
  handlePacket(pkt: Packet, socket: tls.TLSSocket): void {
    this.emitter.emit('packet', pkt, socket);
  }

  /** Send a reply over the TLS connection. */
  sendReply(pkt: Packet, socket: tls.TLSSocket): void {
    const data = pkt.replyPacket();
    socket.write(data);
  }

  private handleConnection(socket: tls.TLSSocket): void {
    let buffer = Buffer.alloc(0);

    socket.on('data', (data: Buffer) => {
      buffer = Buffer.concat([buffer, data]);

      while (buffer.length >= 4) {
        const length = buffer.readUInt16BE(2);
        if (buffer.length < length) break;

        const pktBuf = Buffer.from(buffer.subarray(0, length));
        buffer = Buffer.from(buffer.subarray(length));

        try {
          const pkt = new Packet({
            packet: pktBuf,
            secret: this.secret,
            dict: this.dict,
          });
          this.handlePacket(pkt, socket);
        } catch (err) {
          this.logger.error('Failed to decode RadSec packet');
          this.emitter.emit('error', err);
        }
      }
    });

    socket.on('error', (err) => {
      this.logger.error('RadSec client error');
      this.emitter.emit('error', err);
    });
  }
}
