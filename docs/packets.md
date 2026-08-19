# Packets Guide

RADIUS packets are the core data unit. tsrad provides a base `Packet` class and three specialized subclasses: `AuthPacket`, `AcctPacket`, and `CoAPacket`.

## Packet Codes

```ts
import {
  AccessRequest,       // 1
  AccessAccept,        // 2
  AccessReject,        // 3
  AccountingRequest,   // 4
  AccountingResponse,  // 5
  AccessChallenge,     // 11
  StatusServer,        // 12
  StatusClient,        // 13
  DisconnectRequest,   // 40
  DisconnectACK,       // 41
  DisconnectNAK,       // 42
  CoARequest,          // 43
  CoAACK,              // 44
  CoANAK,              // 45
} from 'tsrad';
```

## Packet Classes

### Packet (base)

The base class for all RADIUS packets. Used directly for reply packets.

```ts
import { Packet } from 'tsrad';

const pkt = new Packet({
  code: AccessAccept,
  id: 42,
  secret: Buffer.from('testing123'),
  authenticator: Buffer.alloc(16),
  dict: myDictionary,
});
```

### AuthPacket

For Access-Request packets. Default code: `AccessRequest` (1).

```ts
const req = new AuthPacket({
  secret: Buffer.from('testing123'),
  dict: myDictionary,
});
// req.code === 1 (AccessRequest)
```

Key method: `requestPacket()` — encodes the packet with a random authenticator for sending.

### AcctPacket

For Accounting-Request packets. Default code: `AccountingRequest` (4).

```ts
const acct = new AcctPacket({
  secret: Buffer.from('testing123'),
  dict: myDictionary,
});
// acct.code === 4 (AccountingRequest)
```

Key method: `requestPacket()` — encodes the packet with a computed authenticator (MD5 of header + zero-auth + attrs + secret).

### CoAPacket

For CoA/Disconnect packets. Default code: `CoARequest` (43).

```ts
const coa = new CoAPacket({
  secret: Buffer.from('testing123'),
  dict: myDictionary,
});

// For disconnect:
const disc = new CoAPacket({
  code: DisconnectRequest,
  secret: Buffer.from('testing123'),
  dict: myDictionary,
});
```

Key method: `requestPacket()` — encodes with computed authenticator.

## Working with Attributes

### Adding attributes

```ts
// By name (requires dictionary)
pkt.addAttribute('User-Name', 'alice');
pkt.addAttribute('NAS-IP-Address', '192.168.1.1');
pkt.addAttribute('NAS-Port', 42);

// Multiple values for the same attribute
pkt.addAttribute('Reply-Message', 'Hello');
pkt.addAttribute('Reply-Message', 'World');
```

`addAttribute()` appends to existing values. Use `set()` to replace.

### Reading attributes

```ts
// getAttribute() returns decoded values as an array
const names = pkt.getAttribute('User-Name');     // ['alice']
const msgs = pkt.getAttribute('Reply-Message');  // ['Hello', 'World']
const port = pkt.getAttribute('NAS-Port');       // [42]
const ip = pkt.getAttribute('NAS-IP-Address');   // ['192.168.1.1']
```

### Setting attributes (replace)

```ts
// set() replaces all values for an attribute
// Values must be pre-encoded Buffers in an array
pkt.set('User-Name', [Buffer.from('bob')]);

// For passwords (must be encrypted)
pkt.set('User-Password', [pkt.pwCrypt('mypassword')]);
```

### Checking and deleting

```ts
pkt.has('User-Name');     // true
pkt.delete('User-Name');
pkt.has('User-Name');     // false
```

For common request fields, typed convenience helpers avoid indexing and casting:

```ts
pkt.setUserName('alice');
pkt.setPassword('correct horse battery staple');
pkt.setNasIpAddress('192.0.2.10');
const username = pkt.getStringAttribute('User-Name');
const nasPort = pkt.getNumberAttribute('NAS-Port', 0);
```

### Listing all attributes

```ts
const attrNames = pkt.keys();
// ['User-Name', 'NAS-IP-Address', 'NAS-Port', ...]
```

### Low-level access (by numeric code)

```ts
// get/set by attribute code
pkt.get(1);                              // User-Name raw values
pkt.set(1, [Buffer.from('alice')]);

// Vendor-specific by tuple key
pkt.get('[14988,3]');                    // Mikrotik-Group
```

## Named Values

When the dictionary defines VALUE mappings, you can use symbolic names:

```ts
// Dictionary defines:
// VALUE Service-Type Login-User 1
// VALUE Service-Type Framed-User 2

pkt.addAttribute('Service-Type', 'Framed-User');

const val = pkt.getAttribute('Service-Type')[0];
// val === 'Framed-User' (resolved from the dictionary)
```

## Tagged Attributes

For attributes with `has_tag` (RFC 2868, used in tunnel attributes):

```ts
// Add with tag using "Attribute-Name:tag" syntax
pkt.addAttribute('Tunnel-Type:1', 'L2TP');
pkt.addAttribute('Tunnel-Medium-Type:1', 'IPv4');
pkt.addAttribute('Tunnel-Server-Endpoint:1', '10.0.0.1');
```

## Password Encryption

### PAP (RFC 2865 section 5.2)

```ts
// Encrypt
const encrypted = pkt.pwCrypt('mypassword');
pkt.set('User-Password', [encrypted]);

// Decrypt (on the server side)
const password = pkt.pwDecrypt(encrypted);
// 'mypassword'
```

The encryption uses `MD5(secret + authenticator)` XOR'd with the password in 16-byte blocks.

### Salt Encryption (RFC 2868)

Used for Tunnel-Password and similar attributes. Handled automatically when the dictionary defines `encrypt=2`:

```ts
// Manual salt encrypt/decrypt
const encrypted = pkt.saltCrypt('tunnel-secret');
const decrypted = pkt.saltDecrypt(encrypted);
```

## CHAP Verification

On the server side, verify CHAP passwords:

```ts
const isValid = pkt.verifyChapPasswd('expected_password');
```

This checks the CHAP-Password attribute (code 3) against an MD5 of the CHAP ID + password + challenge (from CHAP-Challenge attribute or the authenticator).

## Message-Authenticator

HMAC-MD5 integrity check (RFC 3579):

```ts
// Add to a packet before sending
pkt.addMessageAuthenticator();

// Verify on received packet
const valid = pkt.verifyMessageAuthenticator();

// Verify with original authenticator (for reply verification)
const valid = pkt.verifyMessageAuthenticator(secret, originalAuthenticator);
```

## Creating Reply Packets

```ts
// From any packet, create a reply with the same id and authenticator
const reply = pkt.createReply({ code: AccessAccept });
reply.addAttribute('Reply-Message', 'Welcome');

// Encode the reply for sending
const buf = reply.replyPacket();
```

### Subclass-specific replies

Each subclass's `createReply()` returns the same type:

```ts
// AuthPacket.createReply() → AuthPacket (default code: AccessAccept)
// AcctPacket.createReply() → AcctPacket (default code: AccountingResponse)
// CoAPacket.createReply()  → CoAPacket  (default code: CoAACK)
```

## Encoding and Decoding Raw Packets

### Encode a request

```ts
// Auth: random authenticator
const authBuf = authPacket.requestPacket();

// Acct/CoA: computed authenticator
const acctBuf = acctPacket.requestPacket();
const coaBuf = coaPacket.requestPacket();
```

### Encode a reply

```ts
const replyBuf = reply.replyPacket();
```

### Decode a received packet

```ts
const pkt = new Packet({
  packet: rawBuffer,  // received UDP data
  secret: Buffer.from('testing123'),
  dict: myDictionary,
});
// pkt.code, pkt.id, pkt.authenticator are now set
// attributes are decoded and accessible via get/getAttribute
```

## Verify Replies

```ts
// On the client side, verify the reply matches the request
const isValid = request.verifyReply(reply, rawReplyBuffer);
```

This checks that the reply's authenticator is `MD5(code + id + length + request_authenticator + reply_attrs + secret)`.

## Packet Wire Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |  Identifier   |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                         Authenticator                         |
|                         (16 bytes)                            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Attributes ...
+-+-+-+-+-+-+-+-+-+-+-+-+-

Each attribute:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |    Length     |  Value ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Maximum packet size: 8192 bytes. Minimum header: 20 bytes.
