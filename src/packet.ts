/**
 * packet.ts — RADIUS packet implementation
 *
 * Port of pyrad/packet.py
 *
 * Implements RADIUS packet encoding/decoding as defined in RFC 2865/2866,
 * including Auth, Acct, CoA, and Disconnect packet types.
 * Extended with RFC 6929 extended attributes, vendor format support,
 * and attribute validation.
 */

import * as crypto from 'node:crypto';
import { Dictionary, type Attribute, type AttrKey } from './dictionary.js';
import { encodeAttr, decodeAttr } from './tools.js';

// -------------------------
// Packet codes (RFC 2865/2866/3576)
// -------------------------

export const AccessRequest = 1;
export const AccessAccept = 2;
export const AccessReject = 3;
export const AccountingRequest = 4;
export const AccountingResponse = 5;
export const AccessChallenge = 11;
export const StatusServer = 12;
export const StatusClient = 13;
export const DisconnectRequest = 40;
export const DisconnectACK = 41;
export const DisconnectNAK = 42;
export const CoARequest = 43;
export const CoAACK = 44;
export const CoANAK = 45;

let currentID = crypto.randomInt(1, 255);

export function createID(): number {
  currentID = (currentID + 1) % 256;
  return currentID;
}

// -------------------------
// Errors
// -------------------------

export class PacketError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'PacketError';
  }
}

// -------------------------
// Types
// -------------------------

export type AttrValue = Buffer[];
export type TlvValue = Map<number, Buffer[]>;
export type AttrMapValue = AttrValue | TlvValue;

export interface PacketOptions {
  code?: number;
  id?: number;
  secret?: Buffer;
  authenticator?: Buffer | null;
  dict?: Dictionary;
  packet?: Buffer;
  messageAuthenticator?: boolean;
  [key: string]: any;
}

// Type validation helpers
const STRING_TYPES = new Set(['string', 'octets', 'ipaddr', 'ipv6addr', 'ipv6prefix', 'ifid', 'ether', 'abinary']);
const INTEGER_TYPES = new Set(['integer', 'signed', 'short', 'byte', 'date']);

// -------------------------
// Packet
// -------------------------

export class Packet {
  code: number;
  id: number;
  secret: Buffer;
  authenticator: Buffer | null;
  requestAuthenticator: Buffer | null = null;
  messageAuthenticator: boolean | null = null;
  rawPacket: Buffer | null = null;
  dict!: Dictionary;

  protected data = new Map<number | string, AttrMapValue>();

  constructor(opts: PacketOptions = {}) {
    this.code = opts.code ?? 0;
    this.id = opts.id ?? createID();

    if (opts.secret !== undefined && !Buffer.isBuffer(opts.secret)) {
      throw new TypeError('secret must be a Buffer');
    }
    this.secret = opts.secret ?? Buffer.alloc(0);

    if (opts.authenticator !== undefined && opts.authenticator !== null && !Buffer.isBuffer(opts.authenticator)) {
      throw new TypeError('authenticator must be a Buffer');
    }
    this.authenticator = opts.authenticator ?? null;

    if (opts.dict) this.dict = opts.dict;
    if (opts.messageAuthenticator) this.messageAuthenticator = true;

    if (opts.packet) {
      this.rawPacket = opts.packet;
      this.decodePacket(opts.packet);
    }

    // Process named attributes (e.g., User_Name: "foo")
    for (const [key, value] of Object.entries(opts)) {
      if (['code', 'id', 'secret', 'authenticator', 'dict', 'packet', 'messageAuthenticator', 'fd'].includes(key)) continue;
      const attrName = key.replace(/_/g, '-');
      if (this.dict && this.dict.has(attrName)) {
        this.addAttribute(attrName, value);
      }
    }
  }

  // ---- Map-like interface ----

  get(key: string | number | AttrKey): AttrMapValue | undefined {
    if (typeof key === 'string') {
      const encKey = this.encodeKey(key);
      return this.data.get(typeof encKey === 'number' ? encKey : JSON.stringify(encKey));
    }
    return this.data.get(typeof key === 'number' ? key : JSON.stringify(key));
  }

  set(key: string | number | AttrKey, value: AttrMapValue): void {
    if (typeof key === 'string') {
      const [encKey, encVal] = this.encodeKeyValues(key, value as any);
      this.data.set(
        typeof encKey === 'number' ? encKey : JSON.stringify(encKey),
        encVal,
      );
    } else {
      this.data.set(typeof key === 'number' ? key : JSON.stringify(key), value);
    }
  }

  has(key: string | number): boolean {
    if (typeof key === 'string') {
      try {
        const encKey = this.encodeKey(key);
        return this.data.has(typeof encKey === 'number' ? encKey : JSON.stringify(encKey));
      } catch {
        return false;
      }
    }
    return this.data.has(key);
  }

  delete(key: string | number): void {
    if (typeof key === 'string') {
      const encKey = this.encodeKey(key);
      this.data.delete(typeof encKey === 'number' ? encKey : JSON.stringify(encKey));
    } else {
      this.data.delete(key);
    }
  }

  /** Get decoded attribute values by name */
  getAttribute(key: string): any[] {
    const encKey = this.encodeKey(key);
    const storeKey = typeof encKey === 'number' ? encKey : JSON.stringify(encKey);
    const values = this.data.get(storeKey);
    if (!values) throw new Error(`Attribute not found: ${key}`);

    const attr = this.dict.attributes.get(key.split(':')[0])!;
    if (attr.type === 'tlv') {
      const res: Record<string, any[]> = {};
      const tlvMap = values as TlvValue;
      for (const [subCode, subVals] of tlvMap) {
        const subAttrName = attr.subAttributes.get(subCode);
        if (subAttrName) {
          const subAttr = this.dict.attributes.get(subAttrName)!;
          res[subAttrName] = subVals.map(v => this.decodeValue(subAttr, v));
        }
      }
      return [res];
    }

    const vals = values as AttrValue;
    return vals.map(v => this.decodeValue(attr, v));
  }

  /** Get all attribute names present in the packet */
  keys(): (string | number)[] {
    const result: (string | number)[] = [];
    for (const key of this.data.keys()) {
      if (typeof key === 'number') {
        if (this.dict.attrindex.hasBackward(key)) {
          result.push(this.dict.attrindex.getBackward(key));
        } else {
          result.push(key);
        }
      } else {
        // JSON-stringified tuple key
        try {
          const parsed = JSON.parse(key);
          if (this.dict.attrindex.hasBackward(parsed)) {
            result.push(this.dict.attrindex.getBackward(parsed));
          } else {
            result.push(key);
          }
        } catch {
          result.push(key);
        }
      }
    }
    return result;
  }

  // ---- Attribute encoding/decoding ----

  addAttribute(key: string, value: any): void {
    const attrName = key.split(':')[0];
    const attr = this.dict.attributes.get(attrName);
    if (!attr) throw new Error(`Unknown attribute: ${attrName}`);

    // Validate attribute value types
    this.validateAttributeValue(attr, value);

    const [encKey, encValues] = this.encodeKeyValues(key, value);
    const storeKey = typeof encKey === 'number' ? encKey : JSON.stringify(encKey);

    if (attr.isSubAttribute && attr.parent) {
      const parentKey = this.encodeKey(attr.parent.name);
      const parentStoreKey = typeof parentKey === 'number' ? parentKey : JSON.stringify(parentKey);
      let tlv = this.data.get(parentStoreKey) as TlvValue | undefined;
      if (!tlv) {
        tlv = new Map();
        this.data.set(parentStoreKey, tlv);
      }
      const existing = tlv.get(encKey as number) ?? [];
      existing.push(...(encValues as Buffer[]));
      tlv.set(encKey as number, existing);
    } else {
      const existing = (this.data.get(storeKey) as AttrValue) ?? [];
      existing.push(...(encValues as Buffer[]));
      this.data.set(storeKey, existing);
    }
  }

  /** Validate that the value type matches the attribute definition. */
  private validateAttributeValue(attr: Attribute, value: any): void {
    const values = Array.isArray(value) ? value : [value];
    for (const v of values) {
      if (v === null || v === undefined) continue;
      if (Buffer.isBuffer(v)) continue; // Buffers are always accepted (pre-encoded)

      if (INTEGER_TYPES.has(attr.type)) {
        if (typeof v === 'number' || typeof v === 'bigint') continue;
        // Allow string if it's a named value
        if (typeof v === 'string' && attr.values.hasForward(v)) continue;
        // Allow numeric strings
        if (typeof v === 'string' && !isNaN(Number(v))) continue;
        const namedValues = attr.values.forwardKeys();
        const hint = namedValues.length > 0
          ? ` (named values: ${namedValues.slice(0, 5).join(', ')}${namedValues.length > 5 ? ', ...' : ''})`
          : '';
        throw new TypeError(
          `Attribute '${attr.name}' expects number, got ${typeof v}${hint}`,
        );
      }

      if (attr.type === 'ipaddr' || attr.type === 'ipv6addr' || attr.type === 'ipv6prefix') {
        if (typeof v !== 'string') {
          throw new TypeError(
            `Attribute '${attr.name}' expects IP address string, got ${typeof v}`,
          );
        }
      }

      if (attr.type === 'integer64') {
        if (typeof v !== 'number' && typeof v !== 'bigint' && typeof v !== 'string') {
          throw new TypeError(
            `Attribute '${attr.name}' expects number/bigint, got ${typeof v}`,
          );
        }
      }
    }
  }

  protected decodeValue(attr: Attribute, value: Buffer): any {
    if (attr.encrypt === 2) {
      value = this.saltDecrypt(value);
    }
    if (attr.values.hasBackward(value)) {
      return attr.values.getBackward(value);
    }
    return decodeAttr(attr.type, value);
  }

  protected encodeValue(attr: Attribute, value: any): Buffer {
    let result: Buffer;
    if (typeof value === 'string' && attr.values.hasForward(value)) {
      result = attr.values.getForward(value);
    } else {
      result = encodeAttr(attr.type, value);
    }
    if (attr.encrypt === 2) {
      result = this.saltCrypt(result);
    }
    return result;
  }

  protected encodeKeyValues(key: string, values: any): [AttrKey, Buffer[]] {
    if (typeof key !== 'string') return [key as any, values];

    if (!Array.isArray(values)) values = [values];

    const colonIdx = key.indexOf(':');
    const attrName = colonIdx >= 0 ? key.substring(0, colonIdx) : key;
    const tagStr = colonIdx >= 0 ? key.substring(colonIdx + 1) : undefined;

    const attr = this.dict.attributes.get(attrName)!;
    const encKey = this.encodeKey(attrName);

    if (tagStr) {
      const tag = Buffer.from([parseInt(tagStr, 10)]);
      if (attr.type === 'integer') {
        return [encKey, (values as any[]).map(v => {
          const encoded = this.encodeValue(attr, v);
          return Buffer.concat([tag, encoded.subarray(1)]);
        })];
      }
      return [encKey, (values as any[]).map(v =>
        Buffer.concat([tag, this.encodeValue(attr, v)]),
      )];
    }

    return [encKey, (values as any[]).map(v => this.encodeValue(attr, v))];
  }

  protected encodeKey(key: string): AttrKey {
    const attr = this.dict.attributes.get(key);
    if (!attr) throw new Error(`Unknown attribute: ${key}`);
    if (attr.extended) {
      return [attr.extendedType, attr.extendedCode];
    }
    if (attr.vendor && !attr.isSubAttribute) {
      return [this.dict.vendors.getForward(attr.vendor), attr.code];
    }
    return attr.code;
  }

  protected decodeKey(key: number | AttrKey): string | number | AttrKey {
    try {
      return this.dict.attrindex.getBackward(key);
    } catch {
      return key;
    }
  }

  // ---- Authenticator ----

  static createAuthenticator(): Buffer {
    return crypto.randomBytes(16);
  }

  createID(): number {
    return crypto.randomInt(0, 256);
  }

  // ---- Packet encoding ----

  protected pktEncodeAttribute(key: number | [number, number], value: Buffer): Buffer {
    if (Array.isArray(key)) {
      // Check if this is an extended attribute (241-244)
      const attrName = this.decodeKey(key);
      if (typeof attrName === 'string') {
        const attr = this.dict.attributes.get(attrName);
        if (attr && attr.extended) {
          return this.pktEncodeExtendedAttribute(attr, value);
        }
      }

      // Vendor-specific attribute — use vendor format if available
      const vendorId = key[0];
      const fmt = this.dict.getVendorFormat(vendorId);
      const inner = this.pktEncodeVendorInner(key[1], value, fmt);
      const vendorBuf = Buffer.alloc(4);
      vendorBuf.writeUInt32BE(vendorId);
      const vsaPayload = Buffer.concat([vendorBuf, inner]);
      const header = Buffer.alloc(2);
      header[0] = 26;
      header[1] = vsaPayload.length + 2;
      return Buffer.concat([header, vsaPayload]);
    }

    const header = Buffer.alloc(2);
    header[0] = key;
    header[1] = value.length + 2;
    return Buffer.concat([header, value]);
  }

  /** Encode the inner VSA type+length+value using the vendor's format. */
  private pktEncodeVendorInner(code: number, value: Buffer, fmt: { typeSize: number; lengthSize: number }): Buffer {
    const typeBuf = Buffer.alloc(fmt.typeSize);
    if (fmt.typeSize === 1) typeBuf.writeUInt8(code);
    else if (fmt.typeSize === 2) typeBuf.writeUInt16BE(code);
    else typeBuf.writeUInt32BE(code);

    if (fmt.lengthSize === 0) {
      return Buffer.concat([typeBuf, value]);
    }
    const lenBuf = Buffer.alloc(fmt.lengthSize);
    const totalLen = value.length + fmt.typeSize + fmt.lengthSize;
    if (fmt.lengthSize === 1) lenBuf.writeUInt8(totalLen);
    else lenBuf.writeUInt16BE(totalLen);

    return Buffer.concat([typeBuf, lenBuf, value]);
  }

  // ---- Extended Attributes (RFC 6929) ----

  /** Encode an extended attribute (types 241-244). */
  protected pktEncodeExtendedAttribute(attr: Attribute, value: Buffer): Buffer {
    const isLong = attr.extendedType === 243 || attr.extendedType === 244;

    if (!isLong || value.length <= 251) {
      // Short extended: type(1) + length(1) + extCode(1) + value
      const header = Buffer.alloc(3);
      header[0] = attr.extendedType;
      header[1] = value.length + 3;
      header[2] = attr.extendedCode;
      return Buffer.concat([header, value]);
    }

    // Long extended with fragmentation: type(1) + length(1) + extCode(1) + flags(1) + value
    const fragments: Buffer[] = [];
    let remaining = value;
    let first = true;

    while (remaining.length > 0) {
      const maxChunk = first ? 250 : 251; // first fragment has extCode byte
      const isLast = remaining.length <= maxChunk;
      const chunk = remaining.subarray(0, maxChunk);
      remaining = remaining.subarray(maxChunk);

      if (first) {
        const header = Buffer.alloc(4);
        header[0] = attr.extendedType;
        header[1] = chunk.length + 4;
        header[2] = attr.extendedCode;
        header[3] = isLast ? 0x00 : 0x80; // More flag
        fragments.push(Buffer.concat([header, chunk]));
        first = false;
      } else {
        const header = Buffer.alloc(4);
        header[0] = attr.extendedType;
        header[1] = chunk.length + 4;
        header[2] = attr.extendedCode;
        header[3] = isLast ? 0x00 : 0x80;
        fragments.push(Buffer.concat([header, chunk]));
      }
    }

    return Buffer.concat(fragments);
  }

  /** Decode an extended attribute from a packet. */
  protected pktDecodeExtendedAttribute(typeCode: number, data: Buffer): void {
    if (data.length < 1) return;
    const extCode = data[0];
    const key: AttrKey = [typeCode, extCode];
    const storeKey = JSON.stringify(key);

    const isLong = typeCode === 243 || typeCode === 244;

    if (!isLong) {
      // Short extended: just extCode + value
      const value = Buffer.from(data.subarray(1));
      const existing = (this.data.get(storeKey) as AttrValue) ?? [];
      existing.push(value);
      this.data.set(storeKey, existing);
    } else {
      // Long extended: extCode + flags + value
      if (data.length < 2) return;
      const flags = data[1];
      const value = Buffer.from(data.subarray(2));

      // Check for pending fragment assembly
      const pendingKey = `__ext_pending_${typeCode}_${extCode}`;
      let pending = (this as any)[pendingKey] as Buffer | undefined;

      if (pending) {
        pending = Buffer.concat([pending, value]);
      } else {
        pending = value;
      }

      if ((flags & 0x80) === 0) {
        // Last fragment
        const existing = (this.data.get(storeKey) as AttrValue) ?? [];
        existing.push(pending);
        this.data.set(storeKey, existing);
        delete (this as any)[pendingKey];
      } else {
        // More fragments coming
        (this as any)[pendingKey] = pending;
      }
    }
  }

  protected pktIsTlvAttribute(code: number | AttrKey): boolean {
    const name = this.decodeKey(code);
    if (typeof name !== 'string') return false;
    const attr = this.dict.attributes.get(name);
    return attr !== undefined && attr.type === 'tlv';
  }

  /** Check if a top-level attribute code is an extended attribute type. */
  private isExtendedAttrCode(code: number): boolean {
    if (code < 241 || code > 244) return false;
    // Only treat as extended if we have extended attributes defined in this range
    return true;
  }

  protected pktEncodeTlv(tlvKey: number | string, tlvValue: TlvValue): Buffer {
    const keyStr = typeof tlvKey === 'string' ? tlvKey :
      typeof tlvKey === 'number' ? this.decodeKey(tlvKey) : this.decodeKey(JSON.parse(tlvKey as string));
    const tlvAttr = this.dict.attributes.get(keyStr as string)!;

    const maxLen = Math.max(...Array.from(tlvValue.values()).map(v => v.length), 0);
    let currAvp = Buffer.alloc(0);
    const avps: Buffer[] = [];

    for (let i = 0; i < maxLen; i++) {
      let subAttrEncoding = Buffer.alloc(0);
      for (const [code, datalst] of tlvValue) {
        if (i < datalst.length) {
          subAttrEncoding = Buffer.concat([subAttrEncoding, this.pktEncodeAttribute(code, datalst[i])]);
        }
      }
      if (subAttrEncoding.length + currAvp.length < 245) {
        currAvp = Buffer.concat([currAvp, subAttrEncoding]);
      } else {
        avps.push(currAvp);
        currAvp = subAttrEncoding;
      }
    }
    avps.push(currAvp);

    const tlvAvps: Buffer[] = [];
    for (const avp of avps) {
      const header = Buffer.alloc(2);
      header[0] = tlvAttr.code;
      header[1] = avp.length + 2;
      tlvAvps.push(Buffer.concat([header, avp]));
    }

    if (tlvAttr.vendor) {
      let vendorAvps = Buffer.alloc(0);
      for (const avp of tlvAvps) {
        const header = Buffer.alloc(6);
        header[0] = 26;
        header[1] = avp.length + 6;
        header.writeUInt32BE(this.dict.vendors.getForward(tlvAttr.vendor), 2);
        vendorAvps = Buffer.concat([vendorAvps, header, avp]);
      }
      return vendorAvps;
    }

    return Buffer.concat(tlvAvps);
  }

  protected pktEncodeAttributes(): Buffer {
    let result = Buffer.alloc(0);
    for (const [codeKey, datalst] of this.data) {
      const numKey = typeof codeKey === 'number' ? codeKey : undefined;
      if (numKey !== undefined && this.pktIsTlvAttribute(numKey)) {
        result = Buffer.concat([result, this.pktEncodeTlv(numKey, datalst as TlvValue)]);
      } else if (typeof codeKey === 'string' && codeKey.startsWith('[')) {
        // Vendor attribute stored as JSON key
        const parsed = JSON.parse(codeKey) as [number, number];

        // Check if this is an extended attribute
        const attrName = this.decodeKey(parsed);
        if (typeof attrName === 'string') {
          const attr = this.dict.attributes.get(attrName);
          if (attr && attr.extended) {
            for (const data of datalst as Buffer[]) {
              result = Buffer.concat([result, this.pktEncodeExtendedAttribute(attr, data)]);
            }
            continue;
          }
        }

        if (this.pktIsTlvAttribute(parsed)) {
          result = Buffer.concat([result, this.pktEncodeTlv(codeKey, datalst as TlvValue)]);
        } else {
          for (const data of datalst as Buffer[]) {
            result = Buffer.concat([result, this.pktEncodeAttribute(parsed, data)]);
          }
        }
      } else {
        for (const data of datalst as Buffer[]) {
          result = Buffer.concat([result, this.pktEncodeAttribute(numKey!, data)]);
        }
      }
    }
    return result;
  }

  // ---- Packet decoding ----

  decodePacket(packet: Buffer): void {
    if (packet.length < 20) throw new PacketError('Packet header is corrupt');

    this.code = packet.readUInt8(0);
    this.id = packet.readUInt8(1);
    const length = packet.readUInt16BE(2);
    this.authenticator = Buffer.from(packet.subarray(4, 20));

    if (packet.length !== length) throw new PacketError('Packet has invalid length');
    if (length > 8192) throw new PacketError(`Packet length is too long (${length})`);

    this.data.clear();

    let rest = packet.subarray(20);
    while (rest.length > 0) {
      if (rest.length < 2) throw new PacketError('Attribute header is corrupt');
      const key = rest.readUInt8(0);
      const attrlen = rest.readUInt8(1);
      if (attrlen < 2) throw new PacketError(`Attribute length is too small (${attrlen})`);

      const value = Buffer.from(rest.subarray(2, attrlen));

      if (key === 26) {
        // Vendor-specific
        for (const [vk, vv] of this.pktDecodeVendorAttribute(value)) {
          const sk = typeof vk === 'number' ? vk : JSON.stringify(vk);
          const existing = (this.data.get(sk) as AttrValue) ?? [];
          existing.push(vv);
          this.data.set(sk, existing);
        }
      } else if (key === 80) {
        // Message-Authenticator
        this.messageAuthenticator = true;
        const existing = (this.data.get(key) as AttrValue) ?? [];
        existing.push(value);
        this.data.set(key, existing);
      } else if (this.isExtendedAttrCode(key)) {
        // RFC 6929 extended attributes
        this.pktDecodeExtendedAttribute(key, value);
      } else if (this.pktIsTlvAttribute(key)) {
        this.pktDecodeTlvAttribute(key, value);
      } else {
        const existing = (this.data.get(key) as AttrValue) ?? [];
        existing.push(value);
        this.data.set(key, existing);
      }

      rest = rest.subarray(attrlen);
    }
  }

  private pktDecodeVendorAttribute(data: Buffer): Array<[number | [number, number], Buffer]> {
    if (data.length < 6) return [[26, data]];

    const vendor = data.readUInt32BE(0);
    const fmt = this.dict.getVendorFormat(vendor);

    // Read type using vendor format
    if (data.length < 4 + fmt.typeSize) return [[26, data]];
    let atype: number;
    if (fmt.typeSize === 1) atype = data.readUInt8(4);
    else if (fmt.typeSize === 2) atype = data.readUInt16BE(4);
    else atype = data.readUInt32BE(4);

    let length: number;
    let headerSize = 4 + fmt.typeSize;

    if (fmt.lengthSize === 0) {
      // No length field — rest of data is the value
      length = data.length - headerSize;
    } else {
      if (data.length < headerSize + fmt.lengthSize) return [[26, data]];
      if (fmt.lengthSize === 1) length = data.readUInt8(headerSize);
      else length = data.readUInt16BE(headerSize);
      // length includes type+length fields
      length = length - fmt.typeSize - fmt.lengthSize;
      headerSize += fmt.lengthSize;
    }

    const tlvs: Array<[number | [number, number], Buffer]> = [];

    try {
      if (this.pktIsTlvAttribute([vendor, atype])) {
        this.pktDecodeTlvAttribute([vendor, atype] as any, data.subarray(headerSize, headerSize + length));
      } else {
        tlvs.push([[vendor, atype], data.subarray(headerSize, headerSize + length)]);
      }
    } catch {
      return [[26, data]];
    }

    let sumLength = headerSize + length;
    while (data.length > sumLength) {
      try {
        let at: number;
        if (fmt.typeSize === 1) at = data.readUInt8(sumLength);
        else if (fmt.typeSize === 2) at = data.readUInt16BE(sumLength);
        else at = data.readUInt32BE(sumLength);

        let len: number;
        let innerHeader = fmt.typeSize;
        if (fmt.lengthSize === 0) {
          len = data.length - sumLength - fmt.typeSize;
        } else {
          if (fmt.lengthSize === 1) len = data.readUInt8(sumLength + fmt.typeSize);
          else len = data.readUInt16BE(sumLength + fmt.typeSize);
          innerHeader += fmt.lengthSize;
          // total len includes header
          const valueLen = len - fmt.typeSize - fmt.lengthSize;
          tlvs.push([[vendor, at], data.subarray(sumLength + innerHeader, sumLength + innerHeader + valueLen)]);
          sumLength += len;
          continue;
        }
        tlvs.push([[vendor, at], data.subarray(sumLength + innerHeader, sumLength + innerHeader + len)]);
        sumLength += innerHeader + len;
      } catch {
        return [[26, data]];
      }
    }
    return tlvs;
  }

  private pktDecodeTlvAttribute(code: number, data: Buffer): void {
    const storeKey = typeof code === 'number' ? code : JSON.stringify(code);
    let subAttrs = this.data.get(storeKey) as TlvValue | undefined;
    if (!subAttrs) {
      subAttrs = new Map();
      this.data.set(storeKey, subAttrs);
    }

    let loc = 0;
    while (loc < data.length) {
      const atype = data.readUInt8(loc);
      const length = data.readUInt8(loc + 1);
      const existing = subAttrs.get(atype) ?? [];
      existing.push(Buffer.from(data.subarray(loc + 2, loc + length)));
      subAttrs.set(atype, existing);
      loc += length;
    }
  }

  // ---- Reply packet ----

  createReply(opts?: PacketOptions): Packet {
    return new Packet({
      id: this.id,
      secret: this.secret,
      authenticator: this.authenticator,
      dict: this.dict,
      ...opts,
    });
  }

  replyPacket(): Buffer {
    if (!this.authenticator) throw new Error('No authenticator set');
    if (!this.secret) throw new Error('No secret set');

    if (this.messageAuthenticator) {
      this.refreshMessageAuthenticator();
    }

    const attr = this.pktEncodeAttributes();
    const header = Buffer.alloc(4);
    header.writeUInt8(this.code, 0);
    header.writeUInt8(this.id, 1);
    header.writeUInt16BE(20 + attr.length, 2);

    const hash = crypto.createHash('md5');
    hash.update(header);
    hash.update(this.authenticator);
    hash.update(attr);
    hash.update(this.secret);
    const authenticator = hash.digest();

    return Buffer.concat([header, authenticator, attr]);
  }

  // ---- Verify ----

  verifyReply(reply: Packet, rawReply?: Buffer): boolean {
    if (reply.id !== this.id) return false;

    if (!rawReply) rawReply = reply.replyPacket();

    const hash = crypto.createHash('md5');
    hash.update(rawReply.subarray(0, 4));
    hash.update(this.authenticator!);
    hash.update(rawReply.subarray(20));
    hash.update(this.secret);
    const expected = hash.digest();

    return expected.equals(rawReply.subarray(4, 20));
  }

  // ---- Message Authenticator ----

  addMessageAuthenticator(): void {
    this.messageAuthenticator = true;
    this.set(80, [Buffer.alloc(16)]);

    if (this.authenticator === null && this.code === AccessRequest) {
      this.authenticator = Packet.createAuthenticator();
      this.refreshMessageAuthenticator();
    }
  }

  protected refreshMessageAuthenticator(): void {
    // Zero out Message-Authenticator for calculation
    this.set(80, [Buffer.alloc(16)]);
    const attr = this.pktEncodeAttributes();

    const header = Buffer.alloc(4);
    header.writeUInt8(this.code, 0);
    header.writeUInt8(this.id, 1);
    header.writeUInt16BE(20 + attr.length, 2);

    const hmac = crypto.createHmac('md5', this.secret);
    hmac.update(header);

    if ([AccountingRequest, DisconnectRequest, CoARequest, AccountingResponse].includes(this.code)) {
      hmac.update(Buffer.alloc(16));
    } else {
      if (!this.authenticator) throw new Error('No authenticator found');
      hmac.update(this.authenticator);
    }

    hmac.update(attr);
    this.set(80, [hmac.digest()]);
  }

  verifyMessageAuthenticator(secret?: Buffer, originalAuthenticator?: Buffer): boolean {
    if (!this.messageAuthenticator) throw new Error('No Message-Authenticator AVP present');

    const prevMa = this.data.get(80) as AttrValue;
    const key = secret ?? this.secret;
    if (!key) throw new Error('Missing secret for HMAC/MD5 verification');

    let attr: Buffer;
    if (this.rawPacket) {
      attr = Buffer.from(this.rawPacket.subarray(20));
      // Replace MA with zeros in the raw attribute data
      const maOffset = findAttributeOffset(attr, 80);
      if (maOffset >= 0) {
        Buffer.alloc(16).copy(attr, maOffset + 2);
      }
    } else {
      this.set(80, [Buffer.alloc(16)]);
      attr = this.pktEncodeAttributes();
    }

    const header = Buffer.alloc(4);
    header.writeUInt8(this.code, 0);
    header.writeUInt8(this.id, 1);
    header.writeUInt16BE(20 + attr.length, 2);

    const hmac = crypto.createHmac('md5', key);
    hmac.update(header);

    if ([AccountingRequest, DisconnectRequest, CoARequest, AccountingResponse].includes(this.code)) {
      hmac.update(Buffer.alloc(16));
    } else if ([AccessAccept, AccessChallenge, AccessReject].includes(this.code)) {
      const authToUse = originalAuthenticator ?? this.authenticator;
      if (!authToUse) throw new Error('Missing original authenticator');
      hmac.update(authToUse);
    } else {
      hmac.update(this.authenticator!);
    }

    hmac.update(attr);
    this.set(80, prevMa);
    return prevMa[0].equals(hmac.digest());
  }

  // ---- Password encryption (RFC 2865 section 5.2) ----

  pwCrypt(password: string): Buffer {
    if (this.authenticator === null) {
      this.authenticator = Packet.createAuthenticator();
    }

    let buf = Buffer.from(password, 'utf-8');
    if (buf.length % 16 !== 0) {
      buf = Buffer.concat([buf, Buffer.alloc(16 - (buf.length % 16))]);
    }

    let result = Buffer.alloc(0);
    let last: Buffer = this.authenticator;

    while (buf.length > 0) {
      const hash = crypto.createHash('md5').update(this.secret).update(last).digest();
      const chunk = Buffer.alloc(16);
      for (let i = 0; i < 16; i++) {
        chunk[i] = hash[i] ^ buf[i];
      }
      result = Buffer.concat([result, chunk]);
      last = chunk;
      buf = buf.subarray(16);
    }

    return result;
  }

  pwDecrypt(password: Buffer): string {
    let buf = password;
    let pw = Buffer.alloc(0);
    let last: Buffer = this.authenticator!;

    while (buf.length > 0) {
      const hash = crypto.createHash('md5').update(this.secret).update(last).digest();
      const chunk = Buffer.alloc(16);
      for (let i = 0; i < 16; i++) {
        chunk[i] = hash[i] ^ buf[i];
      }
      pw = Buffer.concat([pw, chunk]);
      last = buf.subarray(0, 16);
      buf = buf.subarray(16);
    }

    // Strip trailing NULLs
    let end = pw.length;
    while (end > 0 && pw[end - 1] === 0) end--;
    return pw.subarray(0, end).toString('utf-8');
  }

  // ---- Salt encryption (RFC 2868) ----

  saltCrypt(value: Buffer | string): Buffer {
    let buf = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf-8');

    if (!this.authenticator) {
      this.authenticator = Buffer.alloc(16);
    }

    const randomValue = 32768 + crypto.randomInt(0, 32767);
    const salt = Buffer.alloc(2);
    salt.writeUInt16BE(randomValue);

    // Length prefix
    const lengthBuf = Buffer.from([buf.length]);
    buf = Buffer.concat([lengthBuf, buf]);

    // Zero padding
    if (buf.length % 16 !== 0) {
      buf = Buffer.concat([buf, Buffer.alloc(16 - (buf.length % 16))]);
    }

    return Buffer.concat([salt, this.saltEnDecrypt(buf, salt, true)]);
  }

  saltDecrypt(value: Buffer): Buffer {
    const salt = value.subarray(0, 2);
    let decrypted = this.saltEnDecrypt(value.subarray(2), salt, false);
    const length = decrypted[0];
    return decrypted.subarray(1, length + 1);
  }

  private saltEnDecrypt(data: Buffer, salt: Buffer, encrypting = true): Buffer {
    let result = Buffer.alloc(0);
    let last: Buffer = Buffer.concat([
      this.requestAuthenticator ?? this.authenticator!,
      salt,
    ]);

    let remaining = data;
    while (remaining.length > 0) {
      const hash = crypto.createHash('md5').update(this.secret).update(last).digest();
      const chunk = Buffer.alloc(16);
      for (let i = 0; i < 16; i++) {
        chunk[i] = hash[i] ^ remaining[i];
      }
      // RFC 2868: next hash always depends on the CIPHERTEXT block
      // Encrypting: output is ciphertext → last = chunk
      // Decrypting: input is ciphertext → last = remaining slice
      last = encrypting ? chunk : Buffer.from(remaining.subarray(0, 16));
      result = Buffer.concat([result, chunk]);
      remaining = remaining.subarray(16);
    }
    return result;
  }

  // ---- CHAP verification ----

  verifyChapPasswd(userPwd: string): boolean {
    if (!this.authenticator) this.authenticator = Packet.createAuthenticator();

    const chapPassword = (this.data.get(3) as AttrValue)?.[0];
    if (!chapPassword || chapPassword.length !== 17) return false;

    const chapId = chapPassword.subarray(0, 1);
    const password = chapPassword.subarray(1);

    let challenge = this.authenticator;
    if (this.has('CHAP-Challenge')) {
      challenge = (this.getAttribute('CHAP-Challenge'))[0];
    }

    const expected = crypto.createHash('md5')
      .update(chapId)
      .update(Buffer.from(userPwd, 'utf-8'))
      .update(challenge)
      .digest();

    return password.equals(expected);
  }
}

// -------------------------
// AuthPacket
// -------------------------

export class AuthPacket extends Packet {
  authType: string;

  constructor(opts: PacketOptions & { authType?: string } = {}) {
    super({ code: AccessRequest, ...opts });
    this.authType = opts.authType ?? 'pap';
  }

  createReply(opts?: PacketOptions): AuthPacket {
    return new AuthPacket({
      code: AccessAccept,
      id: this.id,
      secret: this.secret,
      authenticator: this.authenticator,
      dict: this.dict,
      authType: this.authType,
      ...opts,
    });
  }

  requestPacket(): Buffer {
    if (this.authenticator === null) {
      this.authenticator = Packet.createAuthenticator();
    }
    if (this.messageAuthenticator) {
      this.refreshMessageAuthenticator();
    }

    const attr = this.pktEncodeAttributes();
    const header = Buffer.alloc(20);
    header.writeUInt8(this.code, 0);
    header.writeUInt8(this.id, 1);
    header.writeUInt16BE(20 + attr.length, 2);
    this.authenticator.copy(header, 4);

    return Buffer.concat([header, attr]);
  }

  verifyAuthRequest(): boolean {
    if (!this.rawPacket) throw new Error('No raw packet');
    const hash = crypto.createHash('md5');
    hash.update(this.rawPacket.subarray(0, 4));
    hash.update(Buffer.alloc(16));
    hash.update(this.rawPacket.subarray(20));
    hash.update(this.secret);
    return hash.digest().equals(this.authenticator!);
  }
}

// -------------------------
// AcctPacket
// -------------------------

export class AcctPacket extends Packet {
  constructor(opts: PacketOptions = {}) {
    super({ code: AccountingRequest, ...opts });
  }

  createReply(opts?: PacketOptions): AcctPacket {
    return new AcctPacket({
      code: AccountingResponse,
      id: this.id,
      secret: this.secret,
      authenticator: this.authenticator,
      dict: this.dict,
      ...opts,
    });
  }

  requestPacket(): Buffer {
    if (this.messageAuthenticator) {
      this.refreshMessageAuthenticator();
    }

    const attr = this.pktEncodeAttributes();
    const header = Buffer.alloc(4);
    header.writeUInt8(this.code, 0);
    header.writeUInt8(this.id, 1);
    header.writeUInt16BE(20 + attr.length, 2);

    this.authenticator = crypto.createHash('md5')
      .update(header)
      .update(Buffer.alloc(16))
      .update(attr)
      .update(this.secret)
      .digest();

    return Buffer.concat([header, this.authenticator, attr]);
  }

  verifyAcctRequest(): boolean {
    if (!this.rawPacket) throw new Error('No raw packet');
    const hash = crypto.createHash('md5');
    hash.update(this.rawPacket.subarray(0, 4));
    hash.update(Buffer.alloc(16));
    hash.update(this.rawPacket.subarray(20));
    hash.update(this.secret);
    return hash.digest().equals(this.authenticator!);
  }
}

// -------------------------
// CoAPacket
// -------------------------

export class CoAPacket extends Packet {
  constructor(opts: PacketOptions = {}) {
    super({ code: CoARequest, ...opts });
  }

  createReply(opts?: PacketOptions): CoAPacket {
    return new CoAPacket({
      code: CoAACK,
      id: this.id,
      secret: this.secret,
      authenticator: this.authenticator,
      dict: this.dict,
      ...opts,
    });
  }

  requestPacket(): Buffer {
    let attr = this.pktEncodeAttributes();

    const header = Buffer.alloc(4);
    header.writeUInt8(this.code, 0);
    header.writeUInt8(this.id, 1);
    header.writeUInt16BE(20 + attr.length, 2);

    this.authenticator = crypto.createHash('md5')
      .update(header)
      .update(Buffer.alloc(16))
      .update(attr)
      .update(this.secret)
      .digest();

    if (this.messageAuthenticator) {
      this.refreshMessageAuthenticator();
      attr = this.pktEncodeAttributes();
      this.authenticator = crypto.createHash('md5')
        .update(header)
        .update(Buffer.alloc(16))
        .update(attr)
        .update(this.secret)
        .digest();
    }

    return Buffer.concat([header, this.authenticator, attr]);
  }

  verifyCoARequest(): boolean {
    if (!this.rawPacket) throw new Error('No raw packet');
    const hash = crypto.createHash('md5');
    hash.update(this.rawPacket.subarray(0, 4));
    hash.update(Buffer.alloc(16));
    hash.update(this.rawPacket.subarray(20));
    hash.update(this.secret);
    return hash.digest().equals(this.authenticator!);
  }
}

// -------------------------
// Helpers
// -------------------------

function findAttributeOffset(attrs: Buffer, targetType: number): number {
  let offset = 0;
  while (offset < attrs.length) {
    const type = attrs.readUInt8(offset);
    const len = attrs.readUInt8(offset + 1);
    if (type === targetType) return offset;
    offset += len;
  }
  return -1;
}
