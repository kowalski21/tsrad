/**
 * client.ts — RADIUS client
 *
 * Port of pyrad/client.py
 *
 * Sends RADIUS requests (Auth, Acct, CoA, Disconnect) via UDP
 * and waits for replies with configurable timeout and retries.
 *
 * Extended: connection pooling (multiplexed packet IDs),
 * server failover, Status-Server support.
 */

import * as dgram from 'node:dgram';
import { Host } from './host.js';
import {
  Packet, AuthPacket, AcctPacket, CoAPacket,
  PacketError, AccountingRequest, StatusServer,
  type PacketOptions,
} from './packet.js';
import { Dictionary } from './dictionary.js';
import { type Logger, NullLogger } from './logger.js';

export class Timeout extends Error {
  constructor(msg = 'RADIUS server did not reply') {
    super(msg);
    this.name = 'Timeout';
  }
}

export interface ClientOptions {
  /** Hostname or IP address of the RADIUS server */
  server: string;
  /** Port for authentication packets (default 1812) */
  authport?: number;
  /** Port for accounting packets (default 1813) */
  acctport?: number;
  /** Port for CoA/Disconnect packets (default 3799) */
  coaport?: number;
  /** Shared secret */
  secret: Buffer;
  /** RADIUS dictionary */
  dict?: Dictionary;
  /** Total number of send attempts, matching pyrad (default 3). */
  retries?: number;
  /** Timeout in seconds (default 5) */
  timeout?: number;
  /** Enforce Message-Authenticator (default false) */
  enforceMA?: boolean;
  /** Logger instance */
  logger?: Logger;
  /** UDP socket family. If omitted, inferred from the server address. */
  family?: 'udp4' | 'udp6';
  /** Optional local address and port to bind before sending. */
  localAddress?: string;
  localPort?: number;
}

interface PendingRequest {
  resolve: (pkt: Packet) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
  originalPkt: Packet;
  retriesLeft: number;
  port: number;
  raw: Buffer;
}

export class Client extends Host {
  server: string;
  secret: Buffer;
  retries: number;
  timeout: number;
  enforceMA: boolean;
  family: 'udp4' | 'udp6';
  private localAddress?: string;
  private localPort?: number;

  private socket: dgram.Socket | null = null;
  private pending = new Map<number, PendingRequest>();
  private clientLogger: Logger;

  constructor(opts: ClientOptions) {
    super({
      authport: opts.authport,
      acctport: opts.acctport,
      coaport: opts.coaport,
      dict: opts.dict,
      logger: opts.logger,
    });
    this.server = opts.server;
    this.secret = opts.secret;
    this.retries = opts.retries ?? 3;
    this.timeout = opts.timeout ?? 5;
    this.enforceMA = opts.enforceMA ?? false;
    this.family = opts.family ?? (opts.server.includes(':') ? 'udp6' : 'udp4');
    this.localAddress = opts.localAddress;
    this.localPort = opts.localPort;
    this.clientLogger = opts.logger ?? new NullLogger();
  }

  createAuthPacket(opts?: PacketOptions): AuthPacket {
    const pktOpts: PacketOptions = { secret: this.secret, ...opts };
    if (this.enforceMA) pktOpts.messageAuthenticator = true;
    return super.createAuthPacket(pktOpts);
  }

  createAcctPacket(opts?: PacketOptions): AcctPacket {
    return super.createAcctPacket({ secret: this.secret, ...opts });
  }

  createCoAPacket(opts?: PacketOptions): CoAPacket {
    return super.createCoAPacket({ secret: this.secret, ...opts });
  }

  /**
   * Send a Status-Server request and wait for a reply.
   * Used for NAS health checking.
   */
  async sendStatusServer(port?: number): Promise<Packet> {
    const pkt = this.createAuthPacket({ code: StatusServer });
    pkt.addMessageAuthenticator();
    const targetPort = port ?? this.authport;
    return this.sendToPort(pkt, targetPort);
  }

  /**
   * Send a packet and wait for a reply.
   * Automatically determines the correct port based on packet type.
   * Supports concurrent requests via packet ID multiplexing.
   */
  async sendPacket(pkt: Packet): Promise<Packet> {
    if (pkt instanceof AuthPacket) {
      return this.sendToPort(pkt, this.authport);
    } else if (pkt instanceof CoAPacket) {
      return this.sendToPort(pkt, this.coaport);
    } else {
      return this.sendToPort(pkt, this.acctport);
    }
  }

  // Compatibility aliases for pyrad's public naming.
  CreateAuthPacket(opts?: PacketOptions): AuthPacket { return this.createAuthPacket(opts); }
  CreateAcctPacket(opts?: PacketOptions): AcctPacket { return this.createAcctPacket(opts); }
  CreateCoAPacket(opts?: PacketOptions): CoAPacket { return this.createCoAPacket(opts); }
  SendPacket(pkt: Packet): Promise<Packet> { return this.sendPacket(pkt); }

  /** Close the underlying UDP socket */
  close(): void {
    // Cancel all pending requests
    for (const [id, req] of this.pending) {
      clearTimeout(req.timer);
      req.reject(new Error('Client closed'));
    }
    this.pending.clear();

    if (this.socket) {
      this.socket.removeAllListeners();
      this.socket.close();
      this.socket = null;
    }
  }

  /** Bind the client socket to a local address, matching pyrad.Client.bind(). */
  bind(address: string, port = 0): void {
    this.close();
    this.family = address.includes(':') ? 'udp6' : 'udp4';
    this.localAddress = address;
    this.localPort = port;
    this.getSocket();
  }

  private getSocket(): dgram.Socket {
    if (!this.socket) {
      this.socket = dgram.createSocket(this.family);
      this.socket.on('message', (msg) => this.handleResponse(msg));
      if (this.localAddress !== undefined || this.localPort !== undefined) {
        this.socket.bind(this.localPort ?? 0, this.localAddress);
      }
    }
    return this.socket;
  }

  /** Global response handler — dispatches by packet ID. */
  private handleResponse(msg: Buffer): void {
    if (msg.length < 4) return;
    const id = msg.readUInt8(1);
    const req = this.pending.get(id);
    if (!req) return; // unknown/expired

    try {
      const reply = req.originalPkt.createReply({ packet: msg });
      if (req.originalPkt.authenticator) {
        reply.requestAuthenticator = req.originalPkt.authenticator;
      }
      if (req.originalPkt.verifyReply(reply, msg, this.enforceMA)) {
        clearTimeout(req.timer);
        this.pending.delete(id);
        req.resolve(reply);
      }
      // Invalid reply — ignore, timer will expire
    } catch {
      // Bad packet, ignore
    }
  }

  /** Find an unused packet ID (0-255). */
  private allocateId(): number {
    for (let i = 0; i < 256; i++) {
      if (!this.pending.has(i)) return i;
    }
    throw new Error('All 256 packet IDs are in use');
  }

  private async sendToPort(pkt: Packet, port: number): Promise<Packet> {
    if (this.retries <= 0) return Promise.reject(new Timeout());
    const sock = this.getSocket();

    // Assign an available packet ID
    const id = this.allocateId();
    pkt.id = id;

    const raw = (pkt as any).requestPacket
      ? (pkt as AuthPacket | AcctPacket | CoAPacket).requestPacket()
      : pkt.replyPacket();

    return new Promise<Packet>((resolve, reject) => {
      const attempt = (retriesLeft: number, currentRaw: Buffer) => {
        const timeoutMs = this.timeout * 1000;

        const timer = setTimeout(() => {
          if (retriesLeft > 0) {
            // Retry
            let retryRaw = currentRaw;
            if (pkt.code === AccountingRequest && pkt.has('Acct-Delay-Time')) {
              try {
                const current = pkt.getAttribute('Acct-Delay-Time')[0] as number;
                const buf = Buffer.alloc(4);
                buf.writeUInt32BE(current + this.timeout);
                pkt.set(41, [buf]);
                retryRaw = (pkt as AcctPacket).requestPacket();
              } catch { /* use original */ }
            }
            this.clientLogger.debug('Retrying request', { packetId: id });
            attempt(retriesLeft - 1, retryRaw);
          } else {
            this.pending.delete(id);
            reject(new Timeout());
          }
        }, timeoutMs);

        this.pending.set(id, {
          resolve,
          reject,
          timer,
          originalPkt: pkt,
          retriesLeft,
          port,
          raw: currentRaw,
        });

        sock.send(currentRaw, port, this.server, (err) => {
          if (err) {
            clearTimeout(timer);
            this.pending.delete(id);
            reject(err);
          }
        });
      };

      // Match pyrad: retries is the total number of send attempts.
      attempt(Math.max(0, this.retries - 1), raw);
    });
  }
}

// ---- Server Failover ----

export interface ServerEndpoint {
  server: string;
  authport?: number;
  acctport?: number;
  coaport?: number;
  secret: Buffer;
  weight?: number;
}

export type FailoverStrategy = 'failover' | 'round-robin';

export interface FailoverClientOptions {
  servers: ServerEndpoint[];
  strategy?: FailoverStrategy;
  dict?: Dictionary;
  retries?: number;
  timeout?: number;
  enforceMA?: boolean;
  logger?: Logger;
}

/**
 * Client that supports multiple RADIUS servers with failover.
 * - 'failover': try servers in order, move to next on timeout
 * - 'round-robin': rotate starting server, fall back on timeout
 */
export class FailoverClient extends Host {
  private clients: Client[];
  private strategy: FailoverStrategy;
  private roundRobinIndex = 0;
  private failoverLogger: Logger;

  constructor(opts: FailoverClientOptions) {
    super({ dict: opts.dict, logger: opts.logger });
    if (opts.servers.length === 0) throw new Error('FailoverClient requires at least one server');
    this.strategy = opts.strategy ?? 'failover';
    this.failoverLogger = opts.logger ?? new NullLogger();

    this.clients = opts.servers.map(s => new Client({
      server: s.server,
      authport: s.authport,
      acctport: s.acctport,
      coaport: s.coaport,
      secret: s.secret,
      dict: opts.dict,
      retries: opts.retries ?? 1, // single retry per server in failover
      timeout: opts.timeout ?? 5,
      enforceMA: opts.enforceMA,
      logger: opts.logger,
    }));
  }

  createAuthPacket(opts?: PacketOptions): AuthPacket {
    return this.clients[0].createAuthPacket(opts);
  }

  createAcctPacket(opts?: PacketOptions): AcctPacket {
    return this.clients[0].createAcctPacket(opts);
  }

  createCoAPacket(opts?: PacketOptions): CoAPacket {
    return this.clients[0].createCoAPacket(opts);
  }

  /** Send a packet with failover across configured servers. */
  async sendPacket(pkt: Packet): Promise<Packet> {
    const servers = this.getServerOrder();

    for (let i = 0; i < servers.length; i++) {
      const client = servers[i];
      this.applyServerSecret(pkt, client.secret);

      try {
        const reply = await client.sendPacket(pkt);
        return reply;
      } catch (err) {
        if (err instanceof Timeout && i < servers.length - 1) {
          this.failoverLogger.warn('Server timeout, failing over', {
            nasAddress: client.server,
          });
          continue;
        }
        throw err;
      }
    }

    throw new Timeout('All servers exhausted');
  }

  /** Re-encrypt secret-bound attributes before trying another server. */
  private applyServerSecret(pkt: Packet, secret: Buffer): void {
    if (pkt.secret.equals(secret)) return;

    let password: string | undefined;
    if (pkt instanceof AuthPacket && pkt.has('User-Password')) {
      const encrypted = pkt.get('User-Password');
      if (Array.isArray(encrypted) && Buffer.isBuffer(encrypted[0])) {
        password = pkt.pwDecrypt(encrypted[0]);
      }
    }

    const protectedAttributes: Array<[string, any[]]> = [];
    for (const key of pkt.keys()) {
      if (typeof key !== 'string' || key === 'User-Password') continue;
      if (pkt.dict.get(key)?.encrypt === 2) {
        protectedAttributes.push([key, pkt.getAttribute(key)]);
      }
    }

    pkt.secret = secret;
    if (password !== undefined) pkt.setPassword(password);
    for (const [key, values] of protectedAttributes) pkt.set(key, values);
  }

  private getServerOrder(): Client[] {
    if (this.strategy === 'round-robin') {
      const idx = this.roundRobinIndex % this.clients.length;
      this.roundRobinIndex++;
      return [...this.clients.slice(idx), ...this.clients.slice(0, idx)];
    }
    return this.clients;
  }

  close(): void {
    for (const client of this.clients) {
      client.close();
    }
  }
}
