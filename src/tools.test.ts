import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import {
  encodeString, decodeString,
  encodeOctets, decodeOctets,
  encodeAddress, decodeAddress,
  encodeIPv6Address, decodeIPv6Address,
  encodeIPv6Prefix, decodeIPv6Prefix,
  encodeInteger, decodeInteger,
  encodeInteger64, decodeInteger64,
  encodeDate, decodeDate,
  encodeAscendBinary,
  encodeAttr, decodeAttr,
} from './tools.js';

describe('tools - encoding', () => {
  it('encodes string', () => {
    assert.deepEqual(encodeString('1234567890'), Buffer.from('1234567890'));
  });

  it('rejects string > 253 bytes', () => {
    assert.throws(() => encodeString('x'.repeat(254)), /253/);
  });

  it('rejects non-string for encodeString', () => {
    assert.throws(() => encodeString(1 as any), TypeError);
  });

  it('encodes address', () => {
    assert.deepEqual(
      encodeAddress('192.168.0.255'),
      Buffer.from([0xc0, 0xa8, 0x00, 0xff]),
    );
  });

  it('rejects invalid address', () => {
    assert.throws(() => encodeAddress('TEST123'));
  });

  it('rejects non-string address', () => {
    assert.throws(() => encodeAddress(1 as any), TypeError);
  });

  it('encodes integer', () => {
    assert.deepEqual(
      encodeInteger(0x01020304),
      Buffer.from([0x01, 0x02, 0x03, 0x04]),
    );
  });

  it('encodes unsigned integer', () => {
    assert.deepEqual(
      encodeInteger(0xFFFFFFFF),
      Buffer.from([0xff, 0xff, 0xff, 0xff]),
    );
  });

  it('rejects non-numeric integer', () => {
    assert.throws(() => encodeInteger('ONE' as any), TypeError);
  });

  it('encodes integer64', () => {
    assert.deepEqual(
      encodeInteger64(0xFFFFFFFFFFFFFFFFn),
      Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
    );
  });

  it('encodes date', () => {
    assert.deepEqual(
      encodeDate(0x01020304),
      Buffer.from([0x01, 0x02, 0x03, 0x04]),
    );
  });

  it('rejects non-number date', () => {
    assert.throws(() => encodeDate('1' as any), TypeError);
  });

  it('encodes octets from hex string', () => {
    assert.deepEqual(
      encodeOctets('0x01020304'),
      Buffer.from([0x01, 0x02, 0x03, 0x04]),
    );
  });

  it('encodes octets from hex buffer', () => {
    assert.deepEqual(
      encodeOctets(Buffer.from('0x01020304')),
      Buffer.from([0x01, 0x02, 0x03, 0x04]),
    );
  });

  it('encodes octets from decimal string', () => {
    assert.deepEqual(
      encodeOctets('16909060'),
      Buffer.from([0x01, 0x02, 0x03, 0x04]),
    );
  });

  it('rejects octets > 253 bytes', () => {
    const longHex = '0x' + '01'.repeat(254);
    assert.throws(() => encodeOctets(longHex), /253/);
  });

  it('encodes ascend binary', () => {
    const result = encodeAscendBinary(
      'family=ipv4 action=discard direction=in dst=10.10.255.254/32',
    );
    const expected = Buffer.from([
      0x01, 0x00, 0x01, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x0a, 0x0a, 0xff, 0xfe,
      0x00, 0x20, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
    ]);
    assert.deepEqual(result, expected);
  });

  it('encodes IPv6 address', () => {
    const buf = encodeIPv6Address('2001:db8::1');
    assert.equal(buf.length, 16);
    assert.equal(buf.readUInt16BE(0), 0x2001);
    assert.equal(buf.readUInt16BE(2), 0x0db8);
    assert.equal(buf.readUInt16BE(14), 0x0001);
  });

  it('encodes IPv6 prefix', () => {
    const buf = encodeIPv6Prefix('2001:db8::/32');
    assert.equal(buf.length, 18);
    assert.equal(buf[0], 0); // reserved
    assert.equal(buf[1], 32); // prefix length
    assert.equal(buf.readUInt16BE(2), 0x2001);
  });
});

describe('tools - decoding', () => {
  it('decodes string', () => {
    assert.equal(decodeString(Buffer.from('1234567890')), '1234567890');
  });

  it('decodes address', () => {
    assert.equal(
      decodeAddress(Buffer.from([0xc0, 0xa8, 0x00, 0xff])),
      '192.168.0.255',
    );
  });

  it('decodes integer', () => {
    assert.equal(
      decodeInteger(Buffer.from([0x01, 0x02, 0x03, 0x04])),
      0x01020304,
    );
  });

  it('decodes integer64', () => {
    assert.equal(
      decodeInteger64(Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])),
      0xFFFFFFFFFFFFFFFFn,
    );
  });

  it('decodes date', () => {
    assert.equal(
      decodeDate(Buffer.from([0x01, 0x02, 0x03, 0x04])),
      0x01020304,
    );
  });

  it('decodes octets', () => {
    const buf = Buffer.from([1, 2, 3, 4]);
    assert.deepEqual(decodeOctets(buf), buf);
  });

  it('decodes IPv6 address', () => {
    const buf = Buffer.alloc(16);
    buf.writeUInt16BE(0x2001, 0);
    buf.writeUInt16BE(0x0db8, 2);
    buf.writeUInt16BE(0x0001, 14);
    const addr = decodeIPv6Address(buf);
    assert.ok(addr.includes('2001'));
    assert.ok(addr.includes('db8'));
  });

  it('decodes IPv6 prefix', () => {
    const buf = Buffer.alloc(18);
    buf[1] = 64; // prefix length
    buf.writeUInt16BE(0x2001, 2);
    buf.writeUInt16BE(0x0db8, 4);
    const result = decodeIPv6Prefix(buf);
    assert.ok(result.includes('/64'));
    assert.ok(result.includes('2001'));
  });
});

describe('tools - encodeAttr/decodeAttr dispatch', () => {
  it('dispatches string encoding', () => {
    assert.deepEqual(encodeAttr('string', 'string'), Buffer.from('string'));
  });

  it('dispatches octets encoding', () => {
    assert.deepEqual(encodeAttr('octets', Buffer.from('string')), Buffer.from('string'));
  });

  it('dispatches ipaddr encoding', () => {
    assert.deepEqual(
      encodeAttr('ipaddr', '192.168.0.255'),
      Buffer.from([0xc0, 0xa8, 0x00, 0xff]),
    );
  });

  it('dispatches integer encoding', () => {
    assert.deepEqual(
      encodeAttr('integer', 0x01020304),
      Buffer.from([0x01, 0x02, 0x03, 0x04]),
    );
  });

  it('dispatches date encoding', () => {
    assert.deepEqual(
      encodeAttr('date', 0x01020304),
      Buffer.from([0x01, 0x02, 0x03, 0x04]),
    );
  });

  it('dispatches integer64 encoding', () => {
    assert.deepEqual(
      encodeAttr('integer64', 0xFFFFFFFFFFFFFFFFn),
      Buffer.alloc(8, 0xff),
    );
  });

  it('dispatches string decoding', () => {
    assert.equal(decodeAttr('string', Buffer.from('string')), 'string');
  });

  it('dispatches ipaddr decoding', () => {
    assert.equal(
      decodeAttr('ipaddr', Buffer.from([0xc0, 0xa8, 0x00, 0xff])),
      '192.168.0.255',
    );
  });

  it('dispatches integer decoding', () => {
    assert.equal(
      decodeAttr('integer', Buffer.from([0x01, 0x02, 0x03, 0x04])),
      0x01020304,
    );
  });

  it('dispatches integer64 decoding', () => {
    assert.equal(
      decodeAttr('integer64', Buffer.alloc(8, 0xff)),
      0xFFFFFFFFFFFFFFFFn,
    );
  });

  it('dispatches date decoding', () => {
    assert.equal(
      decodeAttr('date', Buffer.from([0x01, 0x02, 0x03, 0x04])),
      0x01020304,
    );
  });

  it('rejects unknown type for encode', () => {
    assert.throws(() => encodeAttr('unknown' as any, null));
  });

  it('rejects unknown type for decode', () => {
    assert.throws(() => decodeAttr('unknown' as any, Buffer.alloc(0)));
  });
});
