/**
 * host.ts — Generic RADIUS capable host
 *
 * Port of pyrad/host.py
 */

import { Dictionary } from './dictionary.js';
import { Packet, AuthPacket, AcctPacket, CoAPacket, type PacketOptions } from './packet.js';
import type * as dgram from 'node:dgram';
import { type Logger, NullLogger } from './logger.js';

export class Host {
  dict: Dictionary;
  authport: number;
  acctport: number;
  coaport: number;
  logger: Logger;

  constructor(opts?: {
    authport?: number;
    acctport?: number;
    coaport?: number;
    dict?: Dictionary;
    logger?: Logger;
  }) {
    this.authport = opts?.authport ?? 1812;
    this.acctport = opts?.acctport ?? 1813;
    this.coaport = opts?.coaport ?? 3799;
    this.dict = opts?.dict ?? new Dictionary();
    this.logger = opts?.logger ?? new NullLogger();
  }

  createPacket(opts?: PacketOptions): Packet {
    return new Packet({ dict: this.dict, ...opts });
  }

  createAuthPacket(opts?: PacketOptions): AuthPacket {
    return new AuthPacket({ dict: this.dict, ...opts });
  }

  createAcctPacket(opts?: PacketOptions): AcctPacket {
    return new AcctPacket({ dict: this.dict, ...opts });
  }

  createCoAPacket(opts?: PacketOptions): CoAPacket {
    return new CoAPacket({ dict: this.dict, ...opts });
  }

  // Compatibility aliases for pyrad's Host API.
  CreatePacket(opts?: PacketOptions): Packet { return this.createPacket(opts); }
  CreateAuthPacket(opts?: PacketOptions): AuthPacket { return this.createAuthPacket(opts); }
  CreateAcctPacket(opts?: PacketOptions): AcctPacket { return this.createAcctPacket(opts); }
  CreateCoAPacket(opts?: PacketOptions): CoAPacket { return this.createCoAPacket(opts); }

  sendPacketVia(socket: dgram.Socket, pkt: Packet, address: string, port: number): void {
    const data = pkt.replyPacket();
    socket.send(data, port, address);
  }

  sendReplyVia(socket: dgram.Socket, pkt: Packet, address: string, port: number): void {
    const data = pkt.replyPacket();
    socket.send(data, port, address);
  }

  SendPacket(...args: any[]): any {
    if (args.length === 1) throw new Error('Host.SendPacket requires socket, packet, address, and port');
    this.sendPacketVia(args[0], args[1], args[2], args[3]);
  }

  SendReplyPacket(...args: any[]): any {
    this.sendReplyVia(args[0], args[1], args[2], args[3]);
  }
}
