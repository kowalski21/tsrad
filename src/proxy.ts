/**
 * proxy.ts — RADIUS proxy server
 *
 * Forwards RADIUS requests to upstream servers based on realm routing.
 * Supports realm extraction, attribute rewriting, and failover.
 */

import {
  Packet, AccessRequest, AccessAccept, AccessReject, AccessChallenge,
  AccountingRequest, AccountingResponse,
  type PacketOptions,
} from './packet.js';
import { Server, RemoteHost, type ServerOptions, type RadiusPacket } from './server.js';
import {
  FailoverClient, type ServerEndpoint, type FailoverStrategy,
} from './client.js';
import { type Logger, NullLogger } from './logger.js';

export interface RealmRoute {
  servers: ServerEndpoint[];
  strategy?: FailoverStrategy;
  /** Strip realm from User-Name before forwarding (default false) */
  stripRealm?: boolean;
}

export interface ProxyOptions extends ServerOptions {
  /** Map of realm → routing config */
  routes: Map<string, RealmRoute> | Record<string, RealmRoute>;
  /** Default route for unknown realms (optional) */
  defaultRoute?: RealmRoute;
  /** Realm separator character (default '@') */
  realmSeparator?: string;
}

/**
 * RADIUS proxy server. Routes requests to upstream servers
 * based on the realm portion of User-Name.
 */
export class ProxyServer extends Server {
  private routes: Map<string, RealmRoute>;
  private defaultRoute: RealmRoute | undefined;
  private realmSeparator: string;
  private realmClients = new Map<string, FailoverClient>();
  private proxyLogger: Logger;

  constructor(opts: ProxyOptions) {
    super(opts);
    this.routes = opts.routes instanceof Map
      ? opts.routes
      : new Map(Object.entries(opts.routes));
    this.defaultRoute = opts.defaultRoute;
    this.realmSeparator = opts.realmSeparator ?? '@';
    this.proxyLogger = opts.logger ?? new NullLogger();
  }

  /** Extract realm from User-Name (e.g., "user@example.com" → "example.com"). */
  extractRealm(username: string): { user: string; realm: string } {
    const idx = username.indexOf(this.realmSeparator);
    if (idx < 0) return { user: username, realm: '' };
    return {
      user: username.substring(0, idx),
      realm: username.substring(idx + 1),
    };
  }

  handleAuthPacket(pkt: RadiusPacket): void | Promise<void> {
    return this.proxyRequest(pkt, 'auth');
  }

  handleAcctPacket(pkt: RadiusPacket): void | Promise<void> {
    return this.proxyRequest(pkt, 'acct');
  }

  private async proxyRequest(pkt: RadiusPacket, type: 'auth' | 'acct'): Promise<void> {
    let username = '';
    try {
      const vals = pkt.getAttribute('User-Name');
      if (vals.length > 0) username = vals[0] as string;
    } catch { /* no User-Name */ }

    const { user, realm } = this.extractRealm(username);
    const route = this.routes.get(realm) ?? this.defaultRoute;

    if (!route) {
      this.proxyLogger.warn('No route for realm', { username, nasAddress: pkt.source.address });
      if (type === 'auth') {
        const reply = this.createReplyPacket(pkt, { code: AccessReject });
        this.sendReply(reply);
      }
      return;
    }

    // Build forwarding packet
    const client = this.getRealmClient(realm || '__default__', route);
    const fwdOpts: PacketOptions = {
      code: pkt.code,
      secret: route.servers[0].secret,
    };

    let fwdPkt: Packet;
    if (type === 'auth') {
      fwdPkt = client.createAuthPacket(fwdOpts);
    } else {
      fwdPkt = client.createAcctPacket(fwdOpts);
    }

    // Copy attributes, optionally strip realm
    for (const key of pkt.keys()) {
      if (typeof key !== 'string') continue;
      if (key === 'User-Name' && route.stripRealm && realm) {
        fwdPkt.addAttribute('User-Name', user);
        continue;
      }
      try {
        this.copyAttribute(pkt, fwdPkt, key);
      } catch { /* skip unknown */ }
    }

    // Preserve an existing Proxy-State. If none exists, add an opaque state
    // value so the upstream can return it according to RFC 2865.
    if (!pkt.has('Proxy-State')) {
      try {
        const proxyState = Buffer.from(JSON.stringify({
          src: pkt.source.address,
          port: pkt.source.port,
          id: pkt.id,
        }));
        fwdPkt.addAttribute('Proxy-State', proxyState);
      } catch { /* Proxy-State may not be in dict */ }
    }

    try {
      const reply = await client.sendPacket(fwdPkt);

      // Relay reply back to original NAS
      const replyCode = reply.code;
      const relayReply = this.createReplyPacket(pkt, { code: replyCode });

      // Copy reply attributes
      for (const key of reply.keys()) {
        if (typeof key !== 'string') continue;
        try {
          this.copyAttribute(reply, relayReply, key);
        } catch { /* skip */ }
      }

      this.sendReply(relayReply);
    } catch (err) {
      this.proxyLogger.error('Upstream server error', {
        username, nasAddress: pkt.source.address,
      });
      if (type === 'auth') {
        const reply = this.createReplyPacket(pkt, { code: AccessReject });
        this.sendReply(reply);
      }
    }
  }

  private getRealmClient(realm: string, route: RealmRoute): FailoverClient {
    let client = this.realmClients.get(realm);
    if (!client) {
      client = new FailoverClient({
        servers: route.servers,
        strategy: route.strategy,
        dict: this.dict,
        logger: this.proxyLogger,
      });
      this.realmClients.set(realm, client);
    }
    return client;
  }

  /** Copy an attribute across a shared-secret boundary. */
  private copyAttribute(source: Packet, target: Packet, key: string): void {
    if (key === 'User-Password') {
      const encrypted = source.get(key);
      if (Array.isArray(encrypted) && Buffer.isBuffer(encrypted[0])) {
        target.setPassword(source.pwDecrypt(encrypted[0]));
      }
      return;
    }

    if (key === 'Message-Authenticator') {
      target.addMessageAuthenticator();
      return;
    }

    if (source.dict.get(key)?.encrypt === 2) {
      target.set(key, source.getAttribute(key));
      return;
    }

    const values = source.get(key);
    if (values) target.set(key, values);
  }

  private closeRealmClients(): void {
    for (const client of this.realmClients.values()) client.close();
    this.realmClients.clear();
  }

  stop(): void {
    this.closeRealmClients();
    super.stop();
  }

  async gracefulStop(timeoutMs = 5000): Promise<void> {
    await super.gracefulStop(timeoutMs);
    this.closeRealmClients();
  }
}
