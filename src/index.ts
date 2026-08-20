/**
 * tsrad — TypeScript RADIUS client/server library
 *
 * A complete port of pyrad (https://github.com/pyradius/pyrad) to TypeScript.
 * Implements RFC 2865 (RADIUS Authentication), RFC 2866 (RADIUS Accounting),
 * RFC 3576 (Dynamic Authorization / CoA), RFC 6929 (Extended Attributes),
 * RFC 5080 (Duplicate Detection), RFC 5997 (Status-Server),
 * and RFC 6614 (RadSec / RADIUS over TLS).
 *
 * @example Client usage
 * ```ts
 * import { Client, Dictionary, AccessAccept } from 'tsrad';
 *
 * const dict = new Dictionary('/path/to/dictionary');
 * const client = new Client({
 *   server: '127.0.0.1',
 *   secret: Buffer.from('shared_secret'),
 *   dict,
 * });
 *
 * const req = client.createAuthPacket();
 * req.addAttribute('User-Name', 'testuser');
 * req.set('User-Password', [req.pwCrypt('testpass')]);
 *
 * const reply = await client.sendPacket(req);
 * if (reply.code === AccessAccept) {
 *   console.log('Access accepted!');
 * }
 * client.close();
 * ```
 *
 * @example Server usage
 * ```ts
 * import { Server, RemoteHost, AccessAccept, type RadiusPacket } from 'tsrad';
 *
 * class MyServer extends Server {
 *   handleAuthPacket(pkt: RadiusPacket) {
 *     const username = pkt.getAttribute('User-Name')[0];
 *     const reply = this.createReplyPacket(pkt, { code: AccessAccept });
 *     this.sendReply(reply);
 *   }
 * }
 *
 * const dict = new Dictionary('/path/to/dictionary');
 * const server = new MyServer({
 *   addresses: ['0.0.0.0'],
 *   dict,
 *   hosts: new Map([
 *     ['0.0.0.0', new RemoteHost('0.0.0.0', Buffer.from('secret'), 'any')],
 *   ]),
 * });
 * server.run();
 * ```
 */

// Core types and utilities
export { BiDict } from './bidict.js';

export {
  encodeString, encodeOctets, encodeAddress, encodeIPv6Address,
  encodeIPv6Prefix, encodeAscendBinary, encodeInteger, encodeInteger64,
  encodeDate, decodeString, decodeOctets, decodeAddress, decodeIPv6Address,
  decodeIPv6Prefix, decodeAscendBinary, decodeInteger, decodeInteger64,
  decodeDate, encodeAttr, decodeAttr,
  type RadiusDataType,
} from './tools.js';

// Dictionary
export { DictFile } from './dictfile.js';
export {
  Dictionary, Attribute, ParseError,
  DATATYPES, type AttrKey, type VendorFormat,
} from './dictionary.js';

// Packet
export {
  Packet, AuthPacket, AcctPacket, CoAPacket,
  PacketError, createID,
  // Packet codes
  AccessRequest, AccessAccept, AccessReject,
  AccountingRequest, AccountingResponse,
  AccessChallenge, StatusServer, StatusClient,
  DisconnectRequest, DisconnectACK, DisconnectNAK,
  CoARequest, CoAACK, CoANAK,
  type PacketOptions, type AttrValue, type TlvValue,
} from './packet.js';

// Host
export { Host } from './host.js';

// Client
export {
  Client, Timeout, FailoverClient,
  type ClientOptions, type ServerEndpoint, type FailoverStrategy, type FailoverClientOptions,
} from './client.js';
export { ClientAsync } from './client_async.js';

// Server
export {
  Server, RemoteHost, ServerPacketError,
  type ServerOptions, type RadiusPacket,
} from './server.js';
export { ServerAsync } from './server_async.js';
export {
  secretFromEnv, clientOptionsFromEnv, serverOptionsFromEnv,
  createClientFromEnv, createServerFromEnv,
  type RadiusEnv,
} from './config.js';

// Logger
export {
  ConsoleLogger, NullLogger,
  type Logger, type LogContext, type LogLevel,
} from './logger.js';

// Middleware
export {
  composeMiddleware, createRequestId,
  type Middleware, type NextFunction, type RequestContext,
} from './middleware.js';

// Dedup
export { DedupCache } from './dedup.js';

// Rate Limiting
export { RateLimiter, type RateLimitConfig } from './ratelimit.js';

// Metrics
export {
  DefaultMetrics, NullMetrics,
  type Metrics, type MetricLabels, type MetricsSnapshot, type HistogramData,
} from './metrics.js';

// Proxy
export { ProxyServer, type ProxyOptions, type RealmRoute } from './proxy.js';

// RadSec
export {
  RadSecClient, RadSecServer,
  type RadSecClientOptions, type RadSecServerOptions,
} from './radsec.js';
