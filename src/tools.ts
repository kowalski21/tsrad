/**
 * tools.ts — Encoding/decoding helpers for RADIUS attribute types
 *
 * Port of pyrad/tools.py
 */

import * as net from 'node:net';

// -------------------------
// Encoding helpers
// -------------------------

export function encodeString(value: string | Buffer): Buffer {
  if (value === null || value === undefined) return Buffer.alloc(0);
  if (Buffer.isBuffer(value)) {
    if (value.length > 253) throw new Error('Can only encode strings of <= 253 characters');
    return value;
  }
  if (typeof value === 'string') {
    const buf = Buffer.from(value, 'utf-8');
    if (buf.length > 253) throw new Error('Can only encode strings of <= 253 characters');
    return buf;
  }
  throw new TypeError('Can only encode string/Buffer as string');
}

export function encodeOctets(value: string | Buffer): Buffer {
  if (value === null || value === undefined) return Buffer.alloc(0);

  if (Buffer.isBuffer(value)) {
    let out: Buffer;
    if (value.length >= 2 && value[0] === 0x30 && value[1] === 0x78) {
      // starts with "0x"
      out = Buffer.from(value.subarray(2).toString(), 'hex');
    } else {
      out = value;
    }
    if (out.length > 253) throw new Error('Can only encode strings of <= 253 characters');
    return out;
  }

  if (typeof value === 'string') {
    let out: Buffer;
    if (value.startsWith('0x')) {
      out = Buffer.from(value.slice(2), 'hex');
    } else if (/^\d+$/.test(value)) {
      const n = parseInt(value, 10);
      if (n < 0) throw new Error('Octet decimal value must be >= 0');
      if (n <= 255) {
        out = Buffer.alloc(1);
        out.writeUInt8(n);
      } else {
        const byteLen = Math.ceil(Math.log2(n + 1) / 8) || 1;
        out = Buffer.alloc(byteLen);
        let tmp = BigInt(n);
        for (let i = byteLen - 1; i >= 0; i--) {
          out[i] = Number(tmp & 0xffn);
          tmp >>= 8n;
        }
      }
    } else {
      out = Buffer.from(value, 'utf-8');
    }
    if (out.length > 253) throw new Error('Can only encode strings of <= 253 characters');
    return out;
  }

  throw new TypeError('Can only encode string/Buffer as octets');
}

export function encodeAddress(addr: string): Buffer {
  if (typeof addr !== 'string') throw new TypeError('Address has to be a string');
  if (net.isIPv4(addr)) {
    const parts = addr.split('.').map(Number);
    return Buffer.from(parts);
  }
  if (net.isIPv6(addr)) {
    return encodeIPv6Address(addr);
  }
  throw new Error('Invalid IP address: ' + addr);
}

export function encodeIPv6Address(addr: string): Buffer {
  if (typeof addr !== 'string') throw new TypeError('IPv6 Address has to be a string');
  return ipv6ToBuffer(addr);
}

export function encodeIPv6Prefix(value: string, defaultPrefixLen = 128): Buffer {
  let addr: string;
  let prefixLen: number;

  if (typeof value === 'string') {
    if (value.includes('/')) {
      const [a, p] = value.split('/');
      addr = a;
      prefixLen = parseInt(p, 10);
    } else {
      addr = value;
      prefixLen = defaultPrefixLen;
    }
  } else {
    throw new TypeError('IPv6 Prefix has to be a string');
  }

  const addrBuf = ipv6ToBuffer(addr);
  const result = Buffer.alloc(18);
  result[0] = 0; // reserved
  result[1] = prefixLen;
  addrBuf.copy(result, 2);
  return result;
}

export function encodeAscendBinary(origStr: string): Buffer {
  const terms: Record<string, Buffer> = {
    family: Buffer.from([0x01]),
    action: Buffer.from([0x00]),
    direction: Buffer.from([0x01]),
    src: Buffer.from([0, 0, 0, 0]),
    dst: Buffer.from([0, 0, 0, 0]),
    srcl: Buffer.from([0x00]),
    dstl: Buffer.from([0x00]),
    proto: Buffer.from([0x00]),
    sport: Buffer.from([0x00, 0x00]),
    dport: Buffer.from([0x00, 0x00]),
    sportq: Buffer.from([0x00]),
    dportq: Buffer.from([0x00]),
  };

  if (origStr.trim() === 'delete') {
    return Buffer.alloc(8);
  }

  for (const t of origStr.split(' ')) {
    const [key, value] = t.split('=');
    if (key === 'family' && value === 'ipv6') {
      terms.family = Buffer.from([0x03]);
      if (terms.src.equals(Buffer.from([0, 0, 0, 0]))) terms.src = Buffer.alloc(16);
      if (terms.dst.equals(Buffer.from([0, 0, 0, 0]))) terms.dst = Buffer.alloc(16);
    } else if (key === 'action' && value === 'accept') {
      terms.action = Buffer.from([0x01]);
    } else if (key === 'action' && value === 'redirect') {
      terms.action = Buffer.from([0x20]);
    } else if (key === 'direction' && value === 'out') {
      terms.direction = Buffer.from([0x00]);
    } else if (key === 'src' || key === 'dst') {
      const [netAddr, prefix] = value.includes('/') ? value.split('/') : [value, '32'];
      if (net.isIPv4(netAddr)) {
        terms[key] = Buffer.from(netAddr.split('.').map(Number));
      } else {
        terms[key] = ipv6ToBuffer(netAddr);
      }
      terms[key + 'l'] = Buffer.from([parseInt(prefix, 10)]);
    } else if (key === 'sport' || key === 'dport') {
      const buf = Buffer.alloc(2);
      buf.writeUInt16BE(parseInt(value, 10));
      terms[key] = buf;
    } else if (key === 'sportq' || key === 'dportq' || key === 'proto') {
      terms[key] = Buffer.from([parseInt(value, 10)]);
    }
  }

  const trailer = Buffer.alloc(8);
  return Buffer.concat([
    terms.family, terms.action, terms.direction, Buffer.from([0x00]),
    terms.src, terms.dst, terms.srcl, terms.dstl,
    terms.proto, Buffer.from([0x00]), terms.sport, terms.dport,
    terms.sportq, terms.dportq, Buffer.from([0x00, 0x00]), trailer,
  ]);
}

export function encodeInteger(num: number | string, format: IntFormat = 'I'): Buffer {
  const n = typeof num === 'string' ? parseInt(num, 10) : num;
  if (isNaN(n)) throw new TypeError('Can not encode non-integer as integer');
  return packInt(n, format);
}

export function encodeInteger64(num: number | bigint | string): Buffer {
  let n: bigint;
  if (typeof num === 'bigint') n = num;
  else if (typeof num === 'string') n = BigInt(num);
  else n = BigInt(num);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(n);
  return buf;
}

export function encodeDate(num: number): Buffer {
  if (typeof num !== 'number') throw new TypeError('Can not encode non-integer as date');
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(num);
  return buf;
}

// -------------------------
// Decoding helpers
// -------------------------

export function decodeString(value: Buffer): string {
  return value.toString('utf-8');
}

export function decodeOctets(value: Buffer): Buffer {
  return value;
}

export function decodeAddress(addr: Buffer): string {
  if (addr.length === 4) {
    return `${addr[0]}.${addr[1]}.${addr[2]}.${addr[3]}`;
  }
  return decodeIPv6Address(addr);
}

export function decodeIPv6Address(addr: Buffer): string {
  const padded = Buffer.alloc(16);
  addr.copy(padded);
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(padded.readUInt16BE(i).toString(16));
  }
  return parts.join(':').replace(/(^|:)(0(:0)*)(:|$)/, '::');
}

export function decodeIPv6Prefix(addr: Buffer): string {
  const padded = Buffer.alloc(18);
  addr.copy(padded);
  const prefixLen = padded[1];
  const addrBuf = padded.subarray(2, 18);
  const addrStr = decodeIPv6Address(addrBuf);
  return `${addrStr}/${prefixLen}`;
}

export function decodeAscendBinary(value: Buffer): Buffer {
  return value;
}

export function decodeInteger(num: Buffer, format: IntFormat = 'I'): number {
  return unpackInt(num, format);
}

export function decodeInteger64(num: Buffer): bigint {
  return num.readBigUInt64BE(0);
}

export function decodeDate(num: Buffer): number {
  return num.readUInt32BE(0);
}

// -------------------------
// Dispatch
// -------------------------

export type RadiusDataType =
  | 'string' | 'octets' | 'integer' | 'ipaddr'
  | 'ipv6prefix' | 'ipv6addr' | 'abinary' | 'signed'
  | 'short' | 'byte' | 'date' | 'integer64' | 'tlv'
  | 'ifid' | 'ether';

export function encodeAttr(datatype: RadiusDataType, value: any): Buffer {
  switch (datatype) {
    case 'string': return encodeString(value);
    case 'octets': return encodeOctets(value);
    case 'integer': return encodeInteger(value, 'I');
    case 'ipaddr': return encodeAddress(value);
    case 'ipv6prefix': return encodeIPv6Prefix(value);
    case 'ipv6addr': return encodeIPv6Address(value);
    case 'abinary': return encodeAscendBinary(value);
    case 'signed': return encodeInteger(value, 'i');
    case 'short': return encodeInteger(value, 'H');
    case 'byte': return encodeInteger(value, 'B');
    case 'date': return encodeDate(value);
    case 'integer64': return encodeInteger64(value);
    default: throw new Error(`Unknown attribute type: ${datatype}`);
  }
}

export function decodeAttr(datatype: RadiusDataType, value: Buffer): any {
  switch (datatype) {
    case 'string': return decodeString(value);
    case 'octets': return decodeOctets(value);
    case 'integer': return decodeInteger(value, 'I');
    case 'ipaddr': return decodeAddress(value);
    case 'ipv6prefix': return decodeIPv6Prefix(value);
    case 'ipv6addr': return decodeIPv6Address(value);
    case 'abinary': return decodeAscendBinary(value);
    case 'signed': return decodeInteger(value, 'i');
    case 'short': return decodeInteger(value, 'H');
    case 'byte': return decodeInteger(value, 'B');
    case 'date': return decodeDate(value);
    case 'integer64': return decodeInteger64(value);
    default: throw new Error(`Unknown attribute type: ${datatype}`);
  }
}

// -------------------------
// Internal helpers
// -------------------------

type IntFormat = 'I' | 'i' | 'H' | 'B';

function packInt(num: number, format: IntFormat): Buffer {
  switch (format) {
    case 'I': { const b = Buffer.alloc(4); b.writeUInt32BE(num); return b; }
    case 'i': { const b = Buffer.alloc(4); b.writeInt32BE(num); return b; }
    case 'H': { const b = Buffer.alloc(2); b.writeUInt16BE(num); return b; }
    case 'B': { const b = Buffer.alloc(1); b.writeUInt8(num); return b; }
  }
}

function unpackInt(buf: Buffer, format: IntFormat): number {
  switch (format) {
    case 'I': return buf.readUInt32BE(0);
    case 'i': return buf.readInt32BE(0);
    case 'H': return buf.readUInt16BE(0);
    case 'B': return buf.readUInt8(0);
  }
}

function ipv6ToBuffer(addr: string): Buffer {
  // Expand :: and convert to 16 bytes
  const parts = addr.split(':');
  const result = Buffer.alloc(16);

  // Handle :: expansion
  let fullParts: string[] = [];
  const emptyIdx = parts.indexOf('');
  if (addr.includes('::')) {
    const before = addr.split('::')[0].split(':').filter(Boolean);
    const after = addr.split('::')[1].split(':').filter(Boolean);
    const fill = 8 - before.length - after.length;
    fullParts = [...before, ...Array(fill).fill('0'), ...after];
  } else {
    fullParts = parts;
  }

  for (let i = 0; i < 8 && i < fullParts.length; i++) {
    const val = parseInt(fullParts[i] || '0', 16);
    result.writeUInt16BE(val, i * 2);
  }

  return result;
}
