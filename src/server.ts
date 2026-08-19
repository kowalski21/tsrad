/**
 * server.ts — RADIUS server
 *
 * Port of pyrad/server.py
 *
 * Listens for incoming RADIUS packets on auth/acct/coa ports
 * and dispatches them to handler methods.
 *
 * Extended: async handlers, middleware pipeline, dedup, rate limiting,
 * Status-Server, graceful shutdown, server-side CoA/Disconnect sender.
 */

import * as dgram from 'node:dgram';
import { EventEmitter } from 'node:events';
import { Host } from './host.js';
import {
  Packet, AuthPacket, AcctPacket, CoAPacket,
  AccessRequest, AccessAccept, AccountingRequest, AccountingResponse,
  CoARequest, CoAACK, DisconnectRequest, DisconnectACK,
  StatusServer,
  PacketError, type PacketOptions,
} from './packet.js';
import { Dictionary } from './dictionary.js';
import { type Logger, NullLogger } from './logger.js';
import {
  type Middleware, type RequestContext,
  composeMiddleware, createRequestId,
} from './middleware.js';
import { DedupCache } from './dedup.js';
import { RateLimiter, type RateLimitConfig } from './ratelimit.js';
import { type Metrics, NullMetrics } from './metrics.js';
import { Client, type ClientOptions } from './client.js';

export class RemoteHost {
  address: string;
  secret: Buffer;
  name: string;
  authport: number;
  acctport: number;
  coaport: number;

  constructor(
    address: string,
    secret: Buffer,
    name: string,
    opts?: { authport?: number; acctport?: number; coaport?: number },
  ) {
    this.address = address;
    this.secret = secret;
    this.name = name;
    this.authport = opts?.authport ?? 1812;
    this.acctport = opts?.acctport ?? 1813;
    this.coaport = opts?.coaport ?? 3799;
  }
}

export class ServerPacketError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'ServerPacketError';
  }
}

export interface ServerOptions {
  /** IP addresses to listen on (default ['0.0.0.0']) */
  addresses?: string[];
  authport?: number;
  acctport?: number;
  coaport?: number;
  /** Map of IP address → RemoteHost (allowed NAS clients) */
  hosts?: Map<string, RemoteHost>;
  dict?: Dictionary;
  /** Enable auth server (default true) */
  authEnabled?: boolean;
  /** Enable accounting server (default true) */
  acctEnabled?: boolean;
  /** Enable CoA server (default false) */
  coaEnabled?: boolean;
  /** Logger instance */
  logger?: Logger;
  /** Dedup cache TTL in ms, or false to disable (default 30000) */
  dedupTtl?: number | false;
  /** Rate limit config, or false to disable (default: enabled, 100/s burst 200) */
  rateLimit?: RateLimitConfig | false;
  /** Metrics collector */
  metrics?: Metrics;
  /** UDP socket family. If omitted, inferred from each listen address. */
  family?: 'udp4' | 'udp6';
  /** Verify accounting/CoA authenticators and present Message-Authenticators. */
  verifyPackets?: boolean;
}

export interface RadiusPacket extends Packet {
  source: { address: string; port: number };
  fd: dgram.Socket;
}

/**
 * RADIUS server. Subclass and override the handle* methods,
 * or use middleware via `use()`, `useAuth()`, `useAcct()`, `useCoa()`.
 */
export class Server extends Host {
  hosts: Map<string, RemoteHost>;
  authEnabled: boolean;
  acctEnabled: boolean;
  coaEnabled: boolean;

  private authSockets: dgram.Socket[] = [];
  private acctSockets: dgram.Socket[] = [];
  private coaSockets: dgram.Socket[] = [];
  private running = false;
  private emitter = new EventEmitter();
  private inflightCount = 0;
  private inflightResolve: (() => void) | null = null;
  private bound = false;
  private startupPromises: Promise<void>[] = [];
  private readonly addresses: string[];
  private readonly family?: 'udp4' | 'udp6';
  private readonly verifyPackets: boolean;

  private dedupCache: DedupCache | null = null;
  private rateLimiter: RateLimiter | null = null;
  private serverMetrics: Metrics;
  private serverLogger: Logger;

  // Middleware chains
  private globalMiddleware: Middleware[] = [];
  private authMiddleware: Middleware[] = [];
  private acctMiddleware: Middleware[] = [];
  private coaMiddleware: Middleware[] = [];

  // NAS client cache for server-initiated CoA/Disconnect
  private nasClients = new Map<string, Client>();

  static readonly MaxPacketSize = 8192;

  constructor(opts?: ServerOptions) {
    super({
      authport: opts?.authport,
      acctport: opts?.acctport,
      coaport: opts?.coaport,
      dict: opts?.dict,
      logger: opts?.logger,
    });

    this.hosts = opts?.hosts ?? new Map();
    this.authEnabled = opts?.authEnabled ?? true;
    this.acctEnabled = opts?.acctEnabled ?? true;
    this.coaEnabled = opts?.coaEnabled ?? false;
    this.serverLogger = opts?.logger ?? new NullLogger();
    this.serverMetrics = opts?.metrics ?? new NullMetrics();
    this.addresses = opts?.addresses ?? ['0.0.0.0'];
    this.family = opts?.family;
    this.verifyPackets = opts?.verifyPackets ?? true;

    // Dedup
    if (opts?.dedupTtl !== false) {
      this.dedupCache = new DedupCache(
        typeof opts?.dedupTtl === 'number' ? opts.dedupTtl : 30000,
      );
    }

    // Rate limiting
    if (opts?.rateLimit !== false) {
      const rlConfig = typeof opts?.rateLimit === 'object' ? opts.rateLimit : undefined;
      this.rateLimiter = new RateLimiter(rlConfig);
    }

    if (opts?.addresses) {
      for (const addr of this.addresses) this.bindToAddress(addr);
    }
  }

  // ---- Middleware ----

  /** Add global middleware (runs for all request types). */
  use(mw: Middleware): this {
    this.globalMiddleware.push(mw);
    return this;
  }

  /** Add middleware for auth requests only. */
  useAuth(mw: Middleware): this {
    this.authMiddleware.push(mw);
    return this;
  }

  /** Add middleware for accounting requests only. */
  useAcct(mw: Middleware): this {
    this.acctMiddleware.push(mw);
    return this;
  }

  /** Add middleware for CoA/Disconnect requests. */
  useCoa(mw: Middleware): this {
    this.coaMiddleware.push(mw);
    return this;
  }

  /** Bind to an IP address. Call before run(). */
  bindToAddress(addr: string): void {
    this.bound = true;
    if (this.authEnabled) {
      const sock = dgram.createSocket(this.family ?? (addr.includes(':') ? 'udp6' : 'udp4'));
      sock.on('message', (msg, rinfo) => this.processAuth(msg, rinfo, sock));
      sock.on('error', (err) => this.emitError(err));
      this.trackStartup(sock);
      this.authSockets.push(sock);
      sock.bind(this.authport, addr);
    }

    if (this.acctEnabled) {
      const sock = dgram.createSocket(this.family ?? (addr.includes(':') ? 'udp6' : 'udp4'));
      sock.on('message', (msg, rinfo) => this.processAcct(msg, rinfo, sock));
      sock.on('error', (err) => this.emitError(err));
      this.trackStartup(sock);
      this.acctSockets.push(sock);
      sock.bind(this.acctport, addr);
    }

    if (this.coaEnabled) {
      const sock = dgram.createSocket(this.family ?? (addr.includes(':') ? 'udp6' : 'udp4'));
      sock.on('message', (msg, rinfo) => this.processCoa(msg, rinfo, sock));
      sock.on('error', (err) => this.emitError(err));
      this.trackStartup(sock);
      this.coaSockets.push(sock);
      sock.bind(this.coaport, addr);
    }
  }

  /** Start the server (non-blocking — sockets are already listening after bind). */
  run(): void {
    if (this.running) return;
    if (!this.bound) {
      for (const addr of this.addresses) this.bindToAddress(addr);
    }
    this.running = true;
    void Promise.all(this.startupPromises).then(() => {
      if (this.running) this.emitter.emit('ready');
    }).catch(() => {
      // Socket errors are emitted by the socket-level handler. `listen()` also
      // receives the rejected startup promise directly.
    });
  }

  /** Promise-based startup for applications that prefer async initialization. */
  async listen(): Promise<void> {
    this.run();
    await Promise.all(this.startupPromises);
  }

  /** Stop the server immediately and close all sockets. */
  stop(): void {
    this.running = false;
    this.closeSockets();
    this.cleanupResources();
  }

  /**
   * Gracefully stop the server: stop accepting new requests,
   * wait for in-flight requests to complete, then close.
   */
  async gracefulStop(timeoutMs = 5000): Promise<void> {
    this.running = false;

    // Stop accepting new packets by removing message listeners
    for (const sock of [...this.authSockets, ...this.acctSockets, ...this.coaSockets]) {
      sock.removeAllListeners('message');
    }

    // Wait for in-flight requests
    if (this.inflightCount > 0) {
      await Promise.race([
        new Promise<void>(resolve => {
          this.inflightResolve = resolve;
        }),
        new Promise<void>(resolve => setTimeout(resolve, timeoutMs)),
      ]);
    }

    this.closeSockets();
    this.cleanupResources();
  }

  private closeSockets(): void {
    for (const sock of [...this.authSockets, ...this.acctSockets, ...this.coaSockets]) {
      try { sock.close(); } catch { /* ignore */ }
    }
    this.authSockets = [];
    this.acctSockets = [];
    this.coaSockets = [];
    this.startupPromises = [];
    this.bound = false;
  }

  private trackStartup(sock: dgram.Socket): void {
    const startup = new Promise<void>((resolve, reject) => {
      sock.once('listening', resolve);
      sock.once('error', reject);
    });
    // `run()`/`listen()` observe the original promise; this prevents a bind
    // failure from becoming an unhandled rejection before either is called.
    void startup.catch(() => {});
    this.startupPromises.push(startup);
  }

  private emitError(err: Error): void {
    if (this.emitter.listenerCount('error') > 0) {
      this.emitter.emit('error', err);
    } else {
      this.serverLogger.error(err.message, { error: err });
    }
  }

  private cleanupResources(): void {
    this.dedupCache?.destroy();
    this.rateLimiter?.destroy();
    for (const client of this.nasClients.values()) {
      client.close();
    }
    this.nasClients.clear();
  }

  on(event: 'ready' | 'error' | 'rateLimit', listener: (...args: any[]) => void): this {
    this.emitter.on(event, listener);
    return this;
  }

  /** Get current in-flight request count. */
  get inflight(): number {
    return this.inflightCount;
  }

  // ---- Handlers (override in subclass) ----

  /** Called when an Access-Request is received. Override this. */
  handleAuthPacket(pkt: RadiusPacket): void | Promise<void> {}

  /** Called when an Accounting-Request is received. Override this. */
  handleAcctPacket(pkt: RadiusPacket): void | Promise<void> {}

  /** Called when a CoA-Request is received. Override this. */
  handleCoaPacket(pkt: RadiusPacket): void | Promise<void> {}

  /** Called when a Disconnect-Request is received. Override this. */
  handleDisconnectPacket(pkt: RadiusPacket): void | Promise<void> {}

  /** Called when a Status-Server request is received. Override to customize. */
  handleStatusServer(pkt: RadiusPacket): void | Promise<void> {
    // Default: reply with Access-Accept (auth port) or Accounting-Response (acct port)
    const reply = this.createReplyPacket(pkt, { code: AccessAccept });
    this.sendReply(reply);
  }

  // ---- Reply helpers ----

  createReplyPacket(pkt: RadiusPacket, opts?: PacketOptions): RadiusPacket {
    const reply = pkt.createReply(opts) as unknown as RadiusPacket;
    reply.source = pkt.source;
    reply.fd = pkt.fd;
    return reply;
  }

  /** Send a reply packet back to the requesting NAS. */
  sendReply(pkt: RadiusPacket): void {
    const data = pkt.replyPacket();

    // Store in dedup cache
    if (this.dedupCache) {
      const key = DedupCache.key(pkt.source.address, pkt.source.port, pkt.id);
      this.dedupCache.storeReply(key, data);
    }

    pkt.fd.send(data, pkt.source.port, pkt.source.address);
  }

  // Compatibility aliases for pyrad's public naming.
  BindToAddress(address: string): void { this.bindToAddress(address); }
  Run(): void { this.run(); }
  CreateReplyPacket(pkt: RadiusPacket, opts?: PacketOptions): RadiusPacket {
    return this.createReplyPacket(pkt, opts);
  }
  SendReply(pkt: RadiusPacket): void { this.sendReply(pkt); }

  // ---- Server-side CoA/Disconnect sender ----

  /** Send a CoA-Request to a NAS and wait for reply. */
  async sendCoA(
    nasAddr: string,
    nasPort: number,
    secret: Buffer,
    attrs: Record<string, any>,
    opts?: { timeout?: number; retries?: number },
  ): Promise<Packet> {
    const client = this.getNasClient(nasAddr, nasPort, secret, opts);
    const pkt = client.createCoAPacket({ code: CoARequest });
    for (const [k, v] of Object.entries(attrs)) {
      pkt.addAttribute(k, v);
    }
    return client.sendPacket(pkt);
  }

  /** Send a Disconnect-Request to a NAS and wait for reply. */
  async sendDisconnect(
    nasAddr: string,
    nasPort: number,
    secret: Buffer,
    attrs: Record<string, any>,
    opts?: { timeout?: number; retries?: number },
  ): Promise<Packet> {
    const client = this.getNasClient(nasAddr, nasPort, secret, opts);
    const pkt = client.createCoAPacket({ code: DisconnectRequest });
    for (const [k, v] of Object.entries(attrs)) {
      pkt.addAttribute(k, v);
    }
    return client.sendPacket(pkt);
  }

  private getNasClient(
    nasAddr: string,
    nasPort: number,
    secret: Buffer,
    opts?: { timeout?: number; retries?: number },
  ): Client {
    const cacheKey = `${nasAddr}:${nasPort}`;
    let client = this.nasClients.get(cacheKey);
    if (!client) {
      client = new Client({
        server: nasAddr,
        coaport: nasPort,
        secret,
        dict: this.dict,
        timeout: opts?.timeout ?? 5,
        retries: opts?.retries ?? 3,
      });
      this.nasClients.set(cacheKey, client);
    }
    return client;
  }

  // ---- Internal processing ----

  private addSecret(pkt: RadiusPacket): void {
    const host = this.hosts.get(pkt.source.address)
      ?? this.hosts.get(pkt.source.address.includes(':') ? '::' : '0.0.0.0');
    if (!host) throw new ServerPacketError('Received packet from unknown host');
    pkt.secret = host.secret;
  }

  /** Validate request authenticity after the NAS secret has been assigned. */
  private verifyRequest(pkt: RadiusPacket): void {
    if (!this.verifyPackets) return;
    try {
      if (pkt instanceof AcctPacket && !pkt.verifyAcctRequest()) {
        throw new ServerPacketError('Accounting request authenticator is invalid');
      }
      if (pkt instanceof CoAPacket && !pkt.verifyCoARequest()) {
        throw new ServerPacketError('CoA request authenticator is invalid');
      }
      // Access-Request and Status-Server authenticators are random by design.
      if (pkt.messageAuthenticator && !pkt.verifyMessageAuthenticator()) {
        throw new ServerPacketError('Message-Authenticator is invalid');
      }
    } catch (err) {
      if (err instanceof ServerPacketError) throw err;
      throw new ServerPacketError(`Request authentication failed: ${String(err)}`);
    }
  }

  private async runWithMiddleware(
    pkt: RadiusPacket,
    typeMiddleware: Middleware[],
    handler: (pkt: RadiusPacket) => void | Promise<void>,
  ): Promise<void> {
    const hasMiddleware = this.globalMiddleware.length > 0 || typeMiddleware.length > 0;

    if (!hasMiddleware) {
      // No middleware — direct handler call (no overhead)
      const result = handler.call(this, pkt);
      if (result && typeof (result as any).then === 'function') {
        await result;
      }
      return;
    }

    const ctx: RequestContext = {
      packet: pkt,
      state: new Map(),
      requestId: createRequestId(),
      receivedAt: Date.now(),
      source: pkt.source,
    };

    const allMiddleware = [...this.globalMiddleware, ...typeMiddleware];
    const composed = composeMiddleware(allMiddleware, async (c) => {
      const result = handler.call(this, c.packet as RadiusPacket);
      if (result && typeof (result as any).then === 'function') {
        await result;
      }
    });

    await composed(ctx);
  }

  private async processWithTracking(
    fn: () => void | Promise<void>,
  ): Promise<void> {
    this.inflightCount++;
    this.serverMetrics.gauge('radius_inflight_requests', this.inflightCount);
    try {
      const result = fn();
      if (result && typeof (result as any).then === 'function') {
        await result;
      }
    } finally {
      this.inflightCount--;
      this.serverMetrics.gauge('radius_inflight_requests', this.inflightCount);
      if (this.inflightCount === 0 && this.inflightResolve) {
        this.inflightResolve();
        this.inflightResolve = null;
      }
    }
  }

  private checkRateLimit(address: string): boolean {
    if (!this.rateLimiter) return true;
    if (this.rateLimiter.allow(address)) return true;
    this.serverMetrics.increment('radius_ratelimit_drops');
    this.emitter.emit('rateLimit', address);
    this.serverLogger.warn('Rate limit exceeded', { nasAddress: address });
    return false;
  }

  private checkDedup(
    address: string,
    port: number,
    packetId: number,
    sock: dgram.Socket,
  ): boolean {
    if (!this.dedupCache) return true; // no dedup, proceed
    const key = DedupCache.key(address, port, packetId);
    const cached = this.dedupCache.check(key);
    if (cached === undefined) {
      // New request
      this.dedupCache.markPending(key);
      return true;
    }
    if (cached !== null) {
      // Cached reply — retransmit
      this.serverMetrics.increment('radius_dedup_hits');
      sock.send(cached, port, address);
    }
    // else: pending, silently drop
    return false;
  }

  private processAuth(msg: Buffer, rinfo: dgram.RemoteInfo, sock: dgram.Socket): void {
    const startTime = Date.now();

    // Rate limit first (before any parsing)
    if (!this.checkRateLimit(rinfo.address)) return;

    try {
      const pkt = this.createAuthPacket({ packet: msg }) as unknown as RadiusPacket;
      pkt.source = { address: rinfo.address, port: rinfo.port };
      pkt.fd = sock;
      this.addSecret(pkt);
      this.verifyRequest(pkt);

      // Dedup check
      if (!this.checkDedup(rinfo.address, rinfo.port, pkt.id, sock)) return;

      // Status-Server on auth port
      if (pkt.code === StatusServer) {
        this.serverMetrics.increment('radius_auth_total', { type: 'status-server' });
        this.processWithTracking(() =>
          this.runWithMiddleware(pkt, this.authMiddleware, this.handleStatusServer),
        ).catch(err => this.emitError(err));
        return;
      }

      if (pkt.code !== AccessRequest) {
        throw new ServerPacketError('Received non-authentication packet on authentication port');
      }

      this.serverMetrics.increment('radius_auth_total');
      this.processWithTracking(() =>
        this.runWithMiddleware(pkt, this.authMiddleware, this.handleAuthPacket),
      ).then(() => {
        this.serverMetrics.histogram('radius_request_duration_ms', Date.now() - startTime, { type: 'auth' });
      }).catch(err => this.emitError(err));
    } catch (err) {
      if (err instanceof ServerPacketError || err instanceof PacketError) {
        this.emitError(err);
      } else {
        throw err;
      }
    }
  }

  private processAcct(msg: Buffer, rinfo: dgram.RemoteInfo, sock: dgram.Socket): void {
    const startTime = Date.now();

    if (!this.checkRateLimit(rinfo.address)) return;

    try {
      const pkt = this.createAcctPacket({ packet: msg }) as unknown as RadiusPacket;
      pkt.source = { address: rinfo.address, port: rinfo.port };
      pkt.fd = sock;
      this.addSecret(pkt);
      this.verifyRequest(pkt);

      if (!this.checkDedup(rinfo.address, rinfo.port, pkt.id, sock)) return;

      // Status-Server on acct port
      if (pkt.code === StatusServer) {
        this.serverMetrics.increment('radius_acct_total', { type: 'status-server' });
        this.processWithTracking(() =>
          this.runWithMiddleware(pkt, this.acctMiddleware, (p) => {
            const reply = this.createReplyPacket(p, { code: AccountingResponse });
            this.sendReply(reply);
          }),
        ).catch(err => this.emitError(err));
        return;
      }

      if (pkt.code !== AccountingRequest) {
        throw new ServerPacketError('Received non-accounting packet on accounting port');
      }

      this.serverMetrics.increment('radius_acct_total');
      this.processWithTracking(() =>
        this.runWithMiddleware(pkt, this.acctMiddleware, this.handleAcctPacket),
      ).then(() => {
        this.serverMetrics.histogram('radius_request_duration_ms', Date.now() - startTime, { type: 'acct' });
      }).catch(err => this.emitError(err));
    } catch (err) {
      if (err instanceof ServerPacketError || err instanceof PacketError) {
        this.emitError(err);
      } else {
        throw err;
      }
    }
  }

  private processCoa(msg: Buffer, rinfo: dgram.RemoteInfo, sock: dgram.Socket): void {
    const startTime = Date.now();

    if (!this.checkRateLimit(rinfo.address)) return;

    try {
      const pkt = this.createCoAPacket({ packet: msg }) as unknown as RadiusPacket;
      pkt.source = { address: rinfo.address, port: rinfo.port };
      pkt.fd = sock;
      this.addSecret(pkt);
      this.verifyRequest(pkt);

      if (!this.checkDedup(rinfo.address, rinfo.port, pkt.id, sock)) return;

      if (pkt.code === CoARequest) {
        this.serverMetrics.increment('radius_coa_total');
        this.processWithTracking(() =>
          this.runWithMiddleware(pkt, this.coaMiddleware, this.handleCoaPacket),
        ).then(() => {
          this.serverMetrics.histogram('radius_request_duration_ms', Date.now() - startTime, { type: 'coa' });
        }).catch(err => this.emitError(err));
      } else if (pkt.code === DisconnectRequest) {
        this.serverMetrics.increment('radius_disconnect_total');
        this.processWithTracking(() =>
          this.runWithMiddleware(pkt, this.coaMiddleware, this.handleDisconnectPacket),
        ).then(() => {
          this.serverMetrics.histogram('radius_request_duration_ms', Date.now() - startTime, { type: 'disconnect' });
        }).catch(err => this.emitError(err));
      } else {
        throw new ServerPacketError('Received non-coa packet on coa port');
      }
    } catch (err) {
      if (err instanceof ServerPacketError || err instanceof PacketError) {
        this.emitError(err);
      } else {
        throw err;
      }
    }
  }
}
