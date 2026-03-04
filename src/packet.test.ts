import { describe, it, beforeEach } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as path from 'node:path';
import {
  Packet, AuthPacket, AcctPacket, CoAPacket,
  PacketError, createID,
  AccessRequest, AccessAccept, AccessReject, AccessChallenge,
  AccountingRequest, AccountingResponse,
  CoARequest, CoAACK,
  DisconnectRequest, DisconnectACK,
} from './packet.js';
import { Dictionary } from './dictionary.js';

const dataDir = path.resolve(__dirname, '..', 'tests', 'data');

describe('createID', () => {
  it('returns an integer', () => {
    const id = createID();
    assert.equal(typeof id, 'number');
    assert.ok(id >= 0 && id <= 255);
  });

  it('returns different values on successive calls', () => {
    const id1 = createID();
    const id2 = createID();
    assert.notEqual(id1, id2);
  });
});

describe('Packet - construction', () => {
  let dict: Dictionary;

  beforeEach(() => {
    dict = new Dictionary(path.join(dataDir, 'simple'));
  });

  it('basic constructor defaults', () => {
    const pkt = new Packet();
    assert.equal(typeof pkt.code, 'number');
    assert.equal(typeof pkt.id, 'number');
    assert.ok(Buffer.isBuffer(pkt.secret));
  });

  it('named constructor', () => {
    const pkt = new Packet({
      code: 26,
      id: 38,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('0123456789ABCDEF'),
      dict,
    });
    assert.equal(pkt.code, 26);
    assert.equal(pkt.id, 38);
    assert.deepEqual(pkt.secret, Buffer.from('secret'));
    assert.deepEqual(pkt.authenticator, Buffer.from('0123456789ABCDEF'));
    assert.equal(pkt.dict, dict);
  });

  it('uses provided dictionary', () => {
    const pkt = new Packet({ dict });
    assert.equal(pkt.dict, dict);
  });

  it('secret must be a Buffer', () => {
    assert.throws(() => new Packet({ secret: 'secret' as any }), TypeError);
  });

  it('constructor with named attributes', () => {
    const pkt = new Packet({ dict, Test_String: 'this works' });
    assert.deepEqual(pkt.getAttribute('Test-String'), ['this works']);
  });

  it('constructor with TLV attribute', () => {
    const pkt = new Packet({
      dict,
      Test_Tlv_Str: 'this works',
      Test_Tlv_Int: 10,
    });
    const tlv = pkt.getAttribute('Test-Tlv');
    assert.deepEqual(tlv, [{ 'Test-Tlv-Str': ['this works'], 'Test-Tlv-Int': [10] }]);
  });
});

describe('Packet - attributes', () => {
  let dict: Dictionary;
  let pkt: Packet;

  beforeEach(() => {
    dict = new Dictionary(path.join(dataDir, 'full'));
    pkt = new Packet({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });
  });

  it('set and get string attribute', () => {
    pkt.set('Test-String', [Buffer.from('dummy')]);
    assert.deepEqual(pkt.getAttribute('Test-String'), ['dummy']);
    assert.deepEqual(pkt.get(1), [Buffer.from('dummy')]);
  });

  it('set and get integer attribute', () => {
    pkt.addAttribute('Test-Integer', 10);
    assert.deepEqual(pkt.getAttribute('Test-Integer'), [10]);
    const rawVal = pkt.get(3) as Buffer[];
    assert.deepEqual(rawVal[0], Buffer.from([0x00, 0x00, 0x00, 0x0a]));
  });

  it('named value access', () => {
    pkt.addAttribute('Test-Integer', 'Three');
    assert.deepEqual(pkt.getAttribute('Test-Integer'), ['Three']);
    const rawVal = pkt.get(3) as Buffer[];
    assert.deepEqual(rawVal[0], Buffer.from([0x00, 0x00, 0x00, 0x03]));
  });

  it('vendor attribute access', () => {
    pkt.addAttribute('Simplon-Number', 10);
    assert.deepEqual(pkt.getAttribute('Simplon-Number'), [10]);

    // Replace with named value
    pkt.delete('Simplon-Number');
    pkt.addAttribute('Simplon-Number', 'Four');
    assert.deepEqual(pkt.getAttribute('Simplon-Number'), ['Four']);
  });

  it('has() and delete()', () => {
    assert.equal(pkt.has('Test-String'), false);
    pkt.addAttribute('Test-String', 'dummy');
    assert.equal(pkt.has('Test-String'), true);
    pkt.delete('Test-String');
    assert.equal(pkt.has('Test-String'), false);
  });

  it('has() returns false for unknown key', () => {
    assert.equal(pkt.has('Unknown-Attribute'), false);
  });

  it('keys()', () => {
    assert.deepEqual(pkt.keys(), []);
    pkt.addAttribute('Test-String', 'dummy');
    const k = pkt.keys();
    assert.ok(k.includes('Test-String'));
  });

  it('addAttribute appends values', () => {
    pkt.addAttribute('Test-String', '1');
    assert.deepEqual(pkt.getAttribute('Test-String'), ['1']);
    pkt.addAttribute('Test-String', '2');
    assert.deepEqual(pkt.getAttribute('Test-String'), ['1', '2']);
  });

  it('encrypted attributes round-trip', () => {
    pkt.addAttribute('Test-Encrypted-String', 'dummy');
    assert.deepEqual(pkt.getAttribute('Test-Encrypted-String'), ['dummy']);
  });
});

describe('Packet - authenticator', () => {
  it('createAuthenticator returns 16 random bytes', () => {
    const a = Packet.createAuthenticator();
    assert.ok(Buffer.isBuffer(a));
    assert.equal(a.length, 16);
    const b = Packet.createAuthenticator();
    assert.ok(!a.equals(b));
  });
});

describe('Packet - createReply', () => {
  let dict: Dictionary;
  let pkt: Packet;

  beforeEach(() => {
    dict = new Dictionary(path.join(dataDir, 'full'));
    pkt = new Packet({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });
  });

  it('reply shares id, secret, authenticator', () => {
    const reply = pkt.createReply();
    assert.equal(reply.id, pkt.id);
    assert.deepEqual(reply.secret, pkt.secret);
    assert.deepEqual(reply.authenticator, pkt.authenticator);
  });
});

describe('Packet - replyPacket', () => {
  it('encodes reply packet with correct authenticator', () => {
    const dict = new Dictionary(path.join(dataDir, 'full'));
    const pkt = new Packet({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });
    const reply = pkt.replyPacket();
    assert.ok(Buffer.isBuffer(reply));
    assert.equal(reply.length, 20); // header only, no attrs
    assert.equal(reply[0], 0); // code
    assert.equal(reply[1], 0); // id
    assert.equal(reply.readUInt16BE(2), 20); // length
  });
});

describe('Packet - verifyReply', () => {
  let dict: Dictionary;
  let pkt: Packet;

  beforeEach(() => {
    dict = new Dictionary(path.join(dataDir, 'full'));
    pkt = new Packet({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });
  });

  it('valid reply', () => {
    const reply = pkt.createReply();
    assert.equal(pkt.verifyReply(reply), true);
  });

  it('invalid reply - wrong id', () => {
    const reply = pkt.createReply();
    reply.id += 1;
    assert.equal(pkt.verifyReply(reply), false);
  });

  it('invalid reply - wrong secret', () => {
    const reply = pkt.createReply();
    reply.secret = Buffer.from('different');
    assert.equal(pkt.verifyReply(reply), false);
  });

  it('invalid reply - wrong authenticator', () => {
    const reply = pkt.createReply();
    reply.authenticator = Buffer.alloc(16, 0x58);
    assert.equal(pkt.verifyReply(reply), false);
  });
});

describe('Packet - encoding attributes', () => {
  let dict: Dictionary;
  let pkt: Packet;

  beforeEach(() => {
    dict = new Dictionary(path.join(dataDir, 'full'));
    pkt = new Packet({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });
  });

  it('encodes normal attribute', () => {
    pkt.set(1, [Buffer.from('value')]);
    const encoded = (pkt as any).pktEncodeAttributes() as Buffer;
    assert.deepEqual(encoded, Buffer.from([0x01, 0x07, ...Buffer.from('value')]));
  });

  it('encodes vendor attribute', () => {
    // Use numeric tuple key to bypass string encoding
    pkt.set([16, 2] as [number, number], [Buffer.from('value')]);
    const encoded = (pkt as any).pktEncodeAttributes() as Buffer;
    // VSA: type=26, len=13, vendorId=16(4 bytes), type=2, len=7, value
    assert.equal(encoded[0], 26); // VSA
    assert.equal(encoded.readUInt32BE(2), 16); // vendor 16
  });

  it('encodes multiple values', () => {
    pkt.set(1, [Buffer.from('one'), Buffer.from('two'), Buffer.from('three')]);
    const encoded = (pkt as any).pktEncodeAttributes() as Buffer;
    assert.deepEqual(
      encoded,
      Buffer.from([
        0x01, 0x05, ...Buffer.from('one'),
        0x01, 0x05, ...Buffer.from('two'),
        0x01, 0x07, ...Buffer.from('three'),
      ]),
    );
  });
});

describe('Packet - decoding', () => {
  let dict: Dictionary;
  let pkt: Packet;

  beforeEach(() => {
    dict = new Dictionary(path.join(dataDir, 'full'));
    pkt = new Packet({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });
  });

  it('rejects empty packet', () => {
    assert.throws(
      () => pkt.decodePacket(Buffer.alloc(0)),
      (err: any) => err instanceof PacketError && err.message.includes('corrupt'),
    );
  });

  it('rejects packet with invalid length', () => {
    const bad = Buffer.alloc(20);
    bad.writeUInt16BE(0, 2); // length = 0
    bad.write('1234567890123456', 4);
    assert.throws(
      () => pkt.decodePacket(bad),
      (err: any) => err instanceof PacketError && err.message.includes('invalid length'),
    );
  });

  it('rejects too-long packet', () => {
    const len = 0x2400;
    const raw = Buffer.alloc(len);
    raw.writeUInt16BE(len, 2);
    assert.throws(
      () => pkt.decodePacket(raw),
      (err: any) => err instanceof PacketError && err.message.includes('too long'),
    );
  });

  it('rejects partial attributes', () => {
    // 21 bytes: 20-byte header + 1 byte (incomplete attribute)
    const raw = Buffer.alloc(21);
    raw[0] = 1; // code
    raw[1] = 2; // id
    raw.writeUInt16BE(21, 2);
    Buffer.from('1234567890123456').copy(raw, 4);
    raw[20] = 0x00; // single byte - no length
    assert.throws(
      () => pkt.decodePacket(raw),
      (err: any) => err instanceof PacketError,
    );
  });

  it('decodes packet without attributes', () => {
    const raw = Buffer.alloc(20);
    raw[0] = 1; // code
    raw[1] = 2; // id
    raw.writeUInt16BE(20, 2);
    Buffer.from('1234567890123456').copy(raw, 4);

    pkt.decodePacket(raw);
    assert.equal(pkt.code, 1);
    assert.equal(pkt.id, 2);
    assert.deepEqual(pkt.authenticator, Buffer.from('1234567890123456'));
    assert.deepEqual(pkt.keys(), []);
  });

  it('decodes packet with bad attribute length', () => {
    const raw = Buffer.alloc(22);
    raw[0] = 1;
    raw[1] = 2;
    raw.writeUInt16BE(22, 2);
    Buffer.from('1234567890123456').copy(raw, 4);
    raw[20] = 0x00; // type
    raw[21] = 0x01; // length = 1 (< 2 = too small)
    assert.throws(
      () => pkt.decodePacket(raw),
      (err: any) => err instanceof PacketError && err.message.includes('too small'),
    );
  });

  it('decodes packet with empty attribute', () => {
    const raw = Buffer.alloc(22);
    raw[0] = 1;
    raw[1] = 2;
    raw.writeUInt16BE(22, 2);
    Buffer.from('1234567890123456').copy(raw, 4);
    raw[20] = 0x01; // type = 1 (Test-String)
    raw[21] = 0x02; // length = 2 (header only)

    pkt.decodePacket(raw);
    assert.deepEqual(pkt.get(1), [Buffer.alloc(0)]);
  });

  it('decodes packet with attribute', () => {
    const value = Buffer.from('value');
    const raw = Buffer.alloc(20 + 2 + value.length);
    raw[0] = 1;
    raw[1] = 2;
    raw.writeUInt16BE(raw.length, 2);
    Buffer.from('1234567890123456').copy(raw, 4);
    raw[20] = 0x01; // type
    raw[21] = value.length + 2; // length
    value.copy(raw, 22);

    pkt.decodePacket(raw);
    assert.deepEqual(pkt.get(1), [Buffer.from('value')]);
  });

  it('decodes packet with multiple values', () => {
    // Two Test-String attributes: "one" and "two"
    const a1 = Buffer.from([0x01, 0x05, ...Buffer.from('one')]);
    const a2 = Buffer.from([0x01, 0x05, ...Buffer.from('two')]);
    const attrs = Buffer.concat([a1, a2]);
    const raw = Buffer.alloc(20 + attrs.length);
    raw[0] = 1;
    raw[1] = 2;
    raw.writeUInt16BE(raw.length, 2);
    Buffer.from('1234567890123456').copy(raw, 4);
    attrs.copy(raw, 20);

    pkt.decodePacket(raw);
    assert.deepEqual(pkt.get(1), [Buffer.from('one'), Buffer.from('two')]);
  });

  it('decodes TLV attribute', () => {
    // Test-Tlv (code 4) with sub-attribute Test-Tlv-Str (code 1) = "value"
    const subAttr = Buffer.from([0x01, 0x07, ...Buffer.from('value')]);
    const tlvAttr = Buffer.from([0x04, subAttr.length + 2, ...subAttr]);
    const raw = Buffer.alloc(20 + tlvAttr.length);
    raw[0] = 1;
    raw[1] = 2;
    raw.writeUInt16BE(raw.length, 2);
    Buffer.from('1234567890123456').copy(raw, 4);
    tlvAttr.copy(raw, 20);

    pkt.decodePacket(raw);
    const tlv = pkt.get(4) as Map<number, Buffer[]>;
    assert.ok(tlv instanceof Map);
    assert.deepEqual(tlv.get(1), [Buffer.from('value')]);
  });

  it('decodes vendor attribute', () => {
    // Vendor-Specific (26) wrapping vendor=16, type=2, value="value"
    const vendorId = Buffer.alloc(4);
    vendorId.writeUInt32BE(16);
    const inner = Buffer.from([0x02, 0x07, ...Buffer.from('value')]);
    const vsaPayload = Buffer.concat([vendorId, inner]);
    const vsa = Buffer.from([26, vsaPayload.length + 2, ...vsaPayload]);

    const raw = Buffer.alloc(20 + vsa.length);
    raw[0] = 1;
    raw[1] = 2;
    raw.writeUInt16BE(raw.length, 2);
    Buffer.from('1234567890123456').copy(raw, 4);
    vsa.copy(raw, 20);

    pkt.decodePacket(raw);
    // Use numeric tuple key for vendor attribute lookup
    assert.deepEqual(pkt.get([16, 2] as [number, number]), [Buffer.from('value')]);
  });
});

describe('AuthPacket', () => {
  let dict: Dictionary;

  beforeEach(() => {
    dict = new Dictionary(path.join(dataDir, 'full'));
  });

  it('defaults to AccessRequest code', () => {
    const pkt = new AuthPacket({ dict });
    assert.equal(pkt.code, AccessRequest);
  });

  it('createReply defaults to AccessAccept', () => {
    const pkt = new AuthPacket({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });
    const reply = pkt.createReply();
    assert.equal(reply.code, AccessAccept);
    assert.equal(reply.id, pkt.id);
    assert.deepEqual(reply.secret, pkt.secret);
    assert.deepEqual(reply.authenticator, pkt.authenticator);
  });

  it('requestPacket encodes correctly', () => {
    const pkt = new AuthPacket({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDE'),
      dict,
    });
    const raw = pkt.requestPacket();
    assert.equal(raw[0], AccessRequest);
    assert.equal(raw[1], 0); // id
    assert.equal(raw.readUInt16BE(2), 20); // length
    assert.deepEqual(raw.subarray(4, 20), Buffer.from('01234567890ABCDE'));
  });

  it('requestPacket creates authenticator if null', () => {
    const pkt = new AuthPacket({
      id: 0,
      secret: Buffer.from('secret'),
      dict,
    });
    pkt.authenticator = null;
    pkt.requestPacket();
    assert.ok(pkt.authenticator !== null);
  });

  it('pwCrypt encrypts password', () => {
    const pkt = new AuthPacket({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });
    const encrypted = pkt.pwCrypt('Simplon');
    assert.ok(Buffer.isBuffer(encrypted));
    assert.equal(encrypted.length, 16);
    assert.deepEqual(
      encrypted,
      Buffer.from([0xd3, 0x55, 0x3b, 0xb2, 0x33, 0x0d, 0x11, 0xba, 0x07, 0xe3, 0xa8, 0x2a, 0xa8, 0x78, 0x14, 0x01]),
    );
  });

  it('pwCrypt sets authenticator', () => {
    const pkt = new AuthPacket({
      id: 0,
      secret: Buffer.from('secret'),
      dict,
    });
    pkt.authenticator = null;
    pkt.pwCrypt('test');
    assert.ok(pkt.authenticator !== null);
  });

  it('pwDecrypt decrypts password', () => {
    const pkt = new AuthPacket({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });
    const decrypted = pkt.pwDecrypt(
      Buffer.from([0xd3, 0x55, 0x3b, 0xb2, 0x33, 0x0d, 0x11, 0xba, 0x07, 0xe3, 0xa8, 0x2a, 0xa8, 0x78, 0x14, 0x01]),
    );
    assert.equal(decrypted, 'Simplon');
  });

  it('pwCrypt/pwDecrypt round-trip', () => {
    const pkt = new AuthPacket({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });
    const password = 'mySecretPassword123!';
    const encrypted = pkt.pwCrypt(password);
    const decrypted = pkt.pwDecrypt(encrypted);
    assert.equal(decrypted, password);
  });

  it('pwCrypt/pwDecrypt round-trip for long password', () => {
    const pkt = new AuthPacket({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });
    const password = 'a'.repeat(48); // 3 blocks
    const encrypted = pkt.pwCrypt(password);
    const decrypted = pkt.pwDecrypt(encrypted);
    assert.equal(decrypted, password);
  });
});

describe('AuthPacket - CHAP', () => {
  it('verifyChapPasswd works', () => {
    const dict = new Dictionary(path.join(dataDir, 'chap'));
    const chapId = Buffer.from('9');
    const chapChallenge = Buffer.from('987654321');
    const chapHash = crypto.createHash('md5')
      .update(chapId)
      .update(Buffer.from('test_password'))
      .update(chapChallenge)
      .digest();
    const chapPassword = Buffer.concat([chapId, chapHash]);

    const pkt = new AuthPacket({
      code: AccessChallenge,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('ABCDEFGHIJKLMNOP'),
      dict,
    });
    pkt.addAttribute('User-Name', 'test_name');
    // Set raw CHAP-Password (code 3) and CHAP-Challenge (code 60)
    pkt.set(3, [chapPassword]);
    pkt.set(60, [chapChallenge]);

    assert.equal(pkt.verifyChapPasswd('test_password'), true);
    assert.equal(pkt.verifyChapPasswd('wrong_password'), false);
  });
});

describe('AcctPacket', () => {
  let dict: Dictionary;

  beforeEach(() => {
    dict = new Dictionary(path.join(dataDir, 'full'));
  });

  it('defaults to AccountingRequest code', () => {
    const pkt = new AcctPacket({ dict });
    assert.equal(pkt.code, AccountingRequest);
  });

  it('createReply defaults to AccountingResponse', () => {
    const pkt = new AcctPacket({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });
    const reply = pkt.createReply();
    assert.equal(reply.code, AccountingResponse);
    assert.equal(reply.id, pkt.id);
    assert.deepEqual(reply.secret, pkt.secret);
  });

  it('requestPacket computes authenticator', () => {
    const pkt = new AcctPacket({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });
    const raw = pkt.requestPacket();
    assert.equal(raw[0], AccountingRequest);
    assert.ok(pkt.authenticator !== null);
    assert.equal(raw.length, 20);
  });

  it('verifyAcctRequest succeeds for valid packet', () => {
    const pkt = new AcctPacket({
      id: 0,
      secret: Buffer.from('secret'),
      dict,
    });
    const raw = pkt.requestPacket();
    const pkt2 = new AcctPacket({ secret: Buffer.from('secret'), packet: raw });
    assert.equal(pkt2.verifyAcctRequest(), true);
  });

  it('verifyAcctRequest fails for wrong secret', () => {
    const pkt = new AcctPacket({
      id: 0,
      secret: Buffer.from('secret'),
      dict,
    });
    const raw = pkt.requestPacket();
    const pkt2 = new AcctPacket({ secret: Buffer.from('different'), packet: raw });
    assert.equal(pkt2.verifyAcctRequest(), false);
  });

  it('verifyAcctRequest fails for tampered packet', () => {
    const pkt = new AcctPacket({
      id: 0,
      secret: Buffer.from('secret'),
      dict,
    });
    const raw = pkt.requestPacket();
    const tampered = Buffer.from(raw);
    tampered[0] = 0x58; // tamper code
    const pkt2 = new AcctPacket({ secret: Buffer.from('secret'), packet: tampered });
    assert.equal(pkt2.verifyAcctRequest(), false);
  });

  it('decodes from raw packet', () => {
    const pkt = new AcctPacket({
      id: 0,
      secret: Buffer.from('secret'),
      dict,
    });
    const raw = pkt.requestPacket();
    const pkt2 = new AcctPacket({ packet: raw });
    assert.equal(pkt2.rawPacket!.length, raw.length);
    assert.deepEqual(pkt2.rawPacket, raw);
  });
});

describe('AcctPacket - realistic', () => {
  it('decodes realistic accounting packet', () => {
    const dict = new Dictionary(path.join(dataDir, 'realistic'));
    const raw = Buffer.from(
      '048e00c4b2f87adbacfd396c9d493f458c25e9f5' +
      '011275736572406578616d706c652e636f6d' +
      '040601020304' +
      '060600000002' +
      '070600000007' +
      '080601020304' +
      '280600000003' +
      '290600000000' +
      '2a064cf0746a' +
      '2b06d3a9806b' +
      '2c11393064626436356131386230613663' +
      '2d0600000001' +
      '2e06000bbddc' +
      '2f060070f955' +
      '300600a6c02a' +
      '330600000001' +
      '340600000000' +
      '350600000002' +
      '37065ca289d5' +
      '3d0600000005' +
      '1a17000002520111554e4b4e4f574e5f50524f44554354' +
      'e00a3234501000229609' +  // unknown attr 224
      'e406fe99d050',           // unknown attr 228
      'hex',
    );

    const pkt = new AcctPacket({ dict, packet: raw });
    assert.equal(pkt.code, AccountingRequest);
    assert.deepEqual(pkt.getAttribute('User-Name'), ['user@example.com']);
    assert.deepEqual(pkt.getAttribute('NAS-IP-Address'), ['1.2.3.4']);
    assert.deepEqual(pkt.getAttribute('Acct-Status-Type'), ['Interim-Update']);
    assert.deepEqual(pkt.getAttribute('Acct-Session-Id'), ['90dbd65a18b0a6c']);
    assert.deepEqual(pkt.getAttribute('Acct-Authentic'), ['RADIUS']);

    // Unknown standard attributes preserved as raw
    const attr224 = pkt.get(224) as Buffer[];
    assert.ok(attr224);
    assert.equal(attr224.length, 1);

    const attr228 = pkt.get(228) as Buffer[];
    assert.ok(attr228);
    assert.equal(attr228.length, 1);

    // Unknown vendor attribute preserved
    const vendorAttr = pkt.get([594, 1] as [number, number]) as Buffer[];
    assert.ok(vendorAttr);
    assert.deepEqual(vendorAttr[0], Buffer.from('UNKNOWN_PRODUCT'));
  });
});

describe('CoAPacket', () => {
  let dict: Dictionary;

  beforeEach(() => {
    dict = new Dictionary(path.join(dataDir, 'full'));
  });

  it('defaults to CoARequest code', () => {
    const pkt = new CoAPacket({ dict });
    assert.equal(pkt.code, CoARequest);
  });

  it('createReply defaults to CoAACK', () => {
    const pkt = new CoAPacket({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });
    const reply = pkt.createReply();
    assert.equal(reply.code, CoAACK);
  });

  it('requestPacket computes authenticator', () => {
    const pkt = new CoAPacket({
      id: 0,
      secret: Buffer.from('secret'),
      dict,
    });
    const raw = pkt.requestPacket();
    assert.equal(raw[0], CoARequest);
    assert.ok(pkt.authenticator !== null);
  });

  it('verifyCoARequest succeeds for valid packet', () => {
    const pkt = new CoAPacket({
      id: 0,
      secret: Buffer.from('secret'),
      dict,
    });
    const raw = pkt.requestPacket();
    const pkt2 = new CoAPacket({ secret: Buffer.from('secret'), packet: raw });
    assert.equal(pkt2.verifyCoARequest(), true);
  });

  it('verifyCoARequest fails for wrong secret', () => {
    const pkt = new CoAPacket({
      id: 0,
      secret: Buffer.from('secret'),
      dict,
    });
    const raw = pkt.requestPacket();
    const pkt2 = new CoAPacket({ secret: Buffer.from('wrong'), packet: raw });
    assert.equal(pkt2.verifyCoARequest(), false);
  });

  it('DisconnectRequest code', () => {
    const pkt = new CoAPacket({
      code: DisconnectRequest,
      id: 0,
      secret: Buffer.from('secret'),
      dict,
    });
    assert.equal(pkt.code, DisconnectRequest);
  });
});

describe('Packet - Message-Authenticator', () => {
  let dict: Dictionary;

  beforeEach(() => {
    dict = new Dictionary(path.join(dataDir, 'full'));
  });

  it('addMessageAuthenticator sets flag', () => {
    const pkt = new Packet({
      code: AccessRequest,
      secret: Buffer.from('secret'),
      dict,
    });
    pkt.addMessageAuthenticator();
    assert.equal(pkt.messageAuthenticator, true);
    assert.ok(pkt.has(80));
  });

  it('Message-Authenticator round-trip on auth packet', () => {
    const pkt = new AuthPacket({
      id: 42,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('0123456789ABCDEF'),
      dict,
    });
    pkt.addAttribute('Test-String', 'test');
    pkt.addAttribute('Test-Integer', 3);
    pkt.addMessageAuthenticator();

    const raw = pkt.requestPacket();
    const decoded = new AuthPacket({
      secret: Buffer.from('secret'),
      dict,
      packet: raw,
    });
    assert.equal(decoded.messageAuthenticator, true);
    assert.equal(decoded.verifyMessageAuthenticator(), true);
  });

  it('Message-Authenticator fails with wrong secret', () => {
    const pkt = new AuthPacket({
      id: 42,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('0123456789ABCDEF'),
      dict,
    });
    pkt.addAttribute('Test-String', 'test');
    pkt.addMessageAuthenticator();

    const raw = pkt.requestPacket();
    const decoded = new AuthPacket({
      secret: Buffer.from('wrong'),
      dict,
      packet: raw,
    });
    assert.equal(decoded.verifyMessageAuthenticator(), false);
  });
});

describe('Packet - salt encryption', () => {
  it('saltCrypt/saltDecrypt round-trip', () => {
    const dict = new Dictionary(path.join(dataDir, 'full'));
    const pkt = new Packet({
      secret: Buffer.from('secret'),
      authenticator: Packet.createAuthenticator(),
      dict,
    });

    const original = 'tunnel-secret-data';
    const encrypted = pkt.saltCrypt(original);
    assert.ok(Buffer.isBuffer(encrypted));
    assert.ok(encrypted.length > 2); // at least salt + data

    const decrypted = pkt.saltDecrypt(encrypted);
    assert.equal(decrypted.toString('utf-8'), original);
  });
});

describe('Packet - TLV encoding', () => {
  it('encodes and decodes TLV attributes', () => {
    const dict = new Dictionary(path.join(dataDir, 'full'));
    const pkt = new Packet({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });

    pkt.addAttribute('Test-Tlv-Str', 'hello');
    pkt.addAttribute('Test-Tlv-Int', 42);

    const tlv = pkt.getAttribute('Test-Tlv');
    assert.deepEqual(tlv, [{
      'Test-Tlv-Str': ['hello'],
      'Test-Tlv-Int': [42],
    }]);
  });

  it('encodes normal TLV to wire format', () => {
    const dict = new Dictionary(path.join(dataDir, 'full'));
    const pkt = new Packet({
      id: 0,
      secret: Buffer.from('secret'),
      authenticator: Buffer.from('01234567890ABCDEF'),
      dict,
    });

    pkt.addAttribute('Test-Tlv-Str', 'value');
    pkt.addAttribute('Test-Tlv-Int', 2);

    const encoded = (pkt as any).pktEncodeTlv(4, pkt.get(4)) as Buffer;
    // TLV code=4, sub-attrs: 1->value, 2->int(2)
    assert.equal(encoded[0], 4); // TLV type
    const subAttrs = encoded.subarray(2);
    assert.equal(subAttrs[0], 1); // sub-attr type
    assert.equal(subAttrs[1], 7); // sub-attr length (2 + 5)
    assert.deepEqual(subAttrs.subarray(2, 7), Buffer.from('value'));
  });
});
