# tsrad

A TypeScript RADIUS client/server library. Complete port of [pyrad](https://github.com/pyradius/pyrad) to idiomatic TypeScript.

Implements RFC 2865, RFC 2866, RFC 2868, RFC 3576, RFC 3579, RFC 5080, RFC 5997, RFC 6614, and RFC 6929.

---

## Philosophy

### Why tsrad exists

RADIUS is the backbone of AAA (Authentication, Authorization, Accounting) in network infrastructure. Every ISP, enterprise Wi-Fi deployment, and VPN concentrator speaks RADIUS. Yet the Node.js ecosystem has had no serious, complete RADIUS library — just thin wrappers that handle basic auth and nothing else.

tsrad is a faithful port of pyrad, the most battle-tested Python RADIUS library, brought to TypeScript with full type safety. The goal is a library that ISP engineers, network automation developers, and infrastructure teams can use to build real production RADIUS systems in Node.js — not toy examples, but actual NAS integration, subscriber management, and dynamic authorization.

### Design decisions

**Port, don't reinvent.** pyrad has been used in production for over a decade. Its architecture is proven. Rather than redesigning from scratch and introducing subtle protocol bugs, tsrad preserves pyrad's structure: the same class hierarchy (`Host` -> `Client`/`Server`), the same packet model, the same dictionary parser. If you know pyrad, you know tsrad.

**FreeRADIUS dictionary compatibility.** The RADIUS protocol defines hundreds of attributes across dozens of RFCs and vendor extensions. Rather than hardcoding these, tsrad uses the same dictionary file format as FreeRADIUS — the de facto standard RADIUS server. You can point tsrad at your existing FreeRADIUS dictionary files and everything works. This also means you get vendor-specific attributes (Mikrotik, Cisco, Juniper, etc.) for free.

**Buffers, not strings, for secrets.** Shared secrets are binary data. tsrad enforces `Buffer` for all secrets to prevent encoding bugs that cause authentication failures. This is a deliberate friction — `Buffer.from('secret')` is slightly more verbose than a bare string, but it eliminates an entire class of interoperability bugs.

**Dependency-light core.** The RADIUS transports use only Node.js built-in modules. Database integration uses the optional `knex` peer dependency; SQLite and TypeScript tooling are development-only dependencies.

**Subclass, don't configure.** The server uses a handler pattern: you subclass `Server` and override `handleAuthPacket()`, `handleAcctPacket()`, etc. This is more explicit than callback registration and gives you full control over the request lifecycle. Each handler receives the parsed packet with source info attached — you decode attributes, make your authorization decision, build a reply, and send it back.

**Protocol correctness over convenience.** tsrad implements the full authenticator verification chain, Message-Authenticator (HMAC-MD5), salt encryption for tunnel attributes, CHAP verification, and proper retry semantics with Acct-Delay-Time increment. These aren't optional — they're what makes a RADIUS implementation actually work with real NAS equipment.

### Architecture

```
                +-----------+
                |   Host    |  Base class: ports, dictionary, packet factories
                +-----+-----+
                      |
            +---------+---------+
            |                   |
      +-----+-----+      +-----+-----+
      |   Client   |      |   Server   |
      +-----+-----+      +-----+-----+
            |                   |
     UDP send/recv        UDP listeners
     retry + timeout      handler dispatch
```

The packet hierarchy is flat:

```
Packet (base)
  |- AuthPacket   (Access-Request, code 1)
  |- AcctPacket   (Accounting-Request, code 4)
  |- CoAPacket    (CoA-Request/Disconnect-Request, code 43/40)
```

All packets share the same attribute storage, encoding, and decoding logic. The subclasses differ only in how they compute the authenticator (random for auth requests, MD5-based for acct/CoA) and what default reply codes they use.

---

## Development

### Prerequisites

- Node.js >= 20 (required by the database test driver)
- TypeScript >= 5.7

### Setup

```bash
cd tsrad
npm install
```

### Build

```bash
# One-shot compile
npx tsc

# Watch mode — recompiles on file changes
npm run dev
```

TypeScript source lives in `src/`, compiled JavaScript goes to `dist/`. The tsconfig targets ES2022 with Node16 module resolution and strict mode enabled. The published package currently uses CommonJS output.

### Run tests

```bash
# Compile tests into a clean output directory, then run them
npm test

# Real transport-level E2E tests
npm run test:e2e
```

Tests use Node.js built-in test runner (`node:test` + `node:assert/strict`). There are 310 tests across the source test files covering every module:

| Test file | Tests | Coverage |
|-----------|-------|----------|
| `bidict.test.ts` | 8 | Forward/backward access, deletion, Buffer keys |
| `tools.test.ts` | 32 | All data type encode/decode, dispatch, errors |
| `dictionary.test.ts` | 19 | Parsing, vendors, TLV, hex/octal codes, errors |
| `packet.test.ts` | 62 | Construction, attributes, encode/decode, auth, vendor, TLV, CHAP, Message-Authenticator, salt encryption |
| `host.test.ts` | 7 | Construction, packet factories |
| `client.test.ts` | 8 | Construction, packet creation, timeout with real UDP |
| `server.test.ts` | 12 | Construction, auth/acct round-trip integration, error handling |
| `db.test.ts` | 25 | Schema, operators, queries, PAP/CHAP auth, acct, groups, DatabaseServer integration |
| `e2e.test.ts` | 6 | UDP auth/accounting/CoA, IPv6, proxy/failover secrets, bind errors, RadSec TLS |

The integration tests in `server.test.ts` spin up a real UDP server and client on localhost, so they test the full encode-send-receive-decode-reply cycle.

### Project structure

```
tsrad/
  src/
    index.ts            Barrel exports — the public API surface
    bidict.ts           Bidirectional map (Buffer-safe key comparison)
    dictfile.ts         Dictionary file reader with $INCLUDE support
    dictionary.ts       FreeRADIUS dictionary parser
    tools.ts            Attribute type encoding/decoding (RFC 2865 types)
    packet.ts           Packet classes, authenticator, encryption
    host.ts             Base class for Client and Server
    client.ts           RADIUS client with retry/timeout and IPv6 binding
    client_async.ts     Promise-based async client compatibility API
    server.ts           RADIUS server with handler dispatch
    server_async.ts     Async server lifecycle compatibility API
    db.ts               Database integration (knex, rlm_sql compatible)
  examples/
    client.ts           Environment-configured client example
    server.ts           Environment-configured server example
  .env.example          Copy to .env for local examples
    *.test.ts           Tests (co-located with source)
  tests/
    data/
      simple            Minimal dictionary for basic tests
      full              Dictionary with vendors, values, TLV, encryption
      chap              CHAP-specific attributes
      realistic         RFC 2865/2866 dictionary (~60 attributes)
      db                Standard RADIUS attributes for database tests
  docs/                 API reference and guides
  dist/                 Compiled output (gitignored)
  package.json
  tsconfig.json
```

### Development workflow

1. Edit `.ts` files in `src/`
2. Run `npx tsc` to compile (or `npm run dev` for watch mode)
3. Run `npm test` to verify
4. Tests run against compiled JS in `dist/`, so always compile before testing

### Writing tests

Tests live next to the source they test. Use Node.js built-in test runner:

```ts
import { describe, it, beforeEach } from 'node:test';
import * as assert from 'node:assert/strict';

describe('MyFeature', () => {
  it('does the thing', () => {
    assert.equal(1 + 1, 2);
  });
});
```

Test dictionary files go in `tests/data/`. Use the FreeRADIUS dictionary format — see existing files for examples.

For tests that need file paths, use `__dirname` (not `import.meta.dirname` — the output is CJS):

```ts
import * as path from 'node:path';
const dataDir = path.resolve(__dirname, '..', 'tests', 'data');
const dict = new Dictionary(path.join(dataDir, 'realistic'));
```

---

## Installation

```bash
npm install tsrad
```

The core client, server, proxy, and RadSec APIs have no runtime dependencies.
For database-backed authentication and accounting, install Knex and a database
driver, then import database APIs from `tsrad/db`.

## Usage

For local development or small services, a dictionary can be embedded directly:

```ts
const dict = Dictionary.fromText(`
ATTRIBUTE User-Name 1 string
ATTRIBUTE User-Password 2 string
`);
```

For deployed applications, `clientOptionsFromEnv()` and `serverOptionsFromEnv()` map
the `RADIUS_*` variables in `.env.example` to validated options. Pass a second object
to override any generated option.

### Contents

- [Dictionary](#loading-a-dictionary)
- [Client authentication](#pap-authentication-client)
- [Accounting](#accounting)
- [CoA and Disconnect](#coa-change-of-authorization)
- [Server](#building-a-radius-server)
- [Database](#database-backed-auth-and-accounting)
- [Timeouts and retries](#timeout-handling)
- [Migration from pyrad](#migrating-from-pyrad)

### Loading a dictionary

Every RADIUS interaction starts with a dictionary. The dictionary defines what attributes exist, their numeric codes, data types, and any named values.

```ts
import { Dictionary } from 'tsrad';

// Load a single file
const dict = new Dictionary('/usr/share/freeradius/dictionary');

// Load multiple files
const dict = new Dictionary(
  '/usr/share/freeradius/dictionary.rfc2865',
  '/usr/share/freeradius/dictionary.rfc2866',
  '/usr/share/freeradius/dictionary.rfc3576',
  '/usr/share/freeradius/dictionary.mikrotik',
);

// Load additional files after construction
dict.readDictionary('/path/to/dictionary.custom');

// Empty dictionary (for low-level use with numeric attribute codes)
const empty = new Dictionary();
```

Dictionary files use the FreeRADIUS format. Here's a minimal one:

```
# my-dictionary
ATTRIBUTE  User-Name         1   string
ATTRIBUTE  User-Password     2   string    encrypt=1
ATTRIBUTE  NAS-IP-Address    4   ipaddr
ATTRIBUTE  NAS-Port          5   integer
ATTRIBUTE  Service-Type      6   integer
ATTRIBUTE  Framed-IP-Address 8   ipaddr
ATTRIBUTE  Acct-Status-Type  40  integer
ATTRIBUTE  Acct-Session-Id   44  string

VALUE  Service-Type     Login-User   1
VALUE  Service-Type     Framed-User  2
VALUE  Acct-Status-Type Start        1
VALUE  Acct-Status-Type Stop         2
VALUE  Acct-Status-Type Interim-Update 3
```

With vendor-specific attributes:

```
VENDOR  Mikrotik  14988

BEGIN-VENDOR Mikrotik
ATTRIBUTE  Mikrotik-Recv-Limit    1  integer
ATTRIBUTE  Mikrotik-Xmit-Limit    2  integer
ATTRIBUTE  Mikrotik-Rate-Limit    8  string
ATTRIBUTE  Mikrotik-Realm        11  string
ATTRIBUTE  Mikrotik-Wireless-PSK 17  string
END-VENDOR Mikrotik
```

### Inspecting the dictionary

```ts
const dict = new Dictionary('/path/to/dictionary');

// Check if an attribute is defined
dict.has('User-Name');                  // true

// Get the full attribute definition
const attr = dict.get('User-Name')!;
attr.name;        // 'User-Name'
attr.code;        // 1
attr.type;        // 'string'
attr.vendor;      // '' (empty for standard attributes)
attr.encrypt;     // 0 (no encryption)

// Vendor attribute
const vattr = dict.get('Mikrotik-Rate-Limit')!;
vattr.vendor;     // 'Mikrotik'
vattr.code;       // 8

// Look up vendor ID
dict.vendors.getForward('Mikrotik');    // 14988
dict.vendors.getBackward(14988);        // 'Mikrotik'

// Look up attribute index key
dict.attrindex.getForward('User-Name');           // 1
dict.attrindex.getForward('Mikrotik-Rate-Limit'); // [14988, 8]
```

---

### PAP authentication (client)

The most common RADIUS operation: send an Access-Request with username and encrypted password, get back Access-Accept or Access-Reject.

```ts
import {
  Client, Dictionary,
  AccessAccept, AccessReject, AccessChallenge,
} from 'tsrad';

const dict = new Dictionary('/usr/share/freeradius/dictionary');
const client = new Client({
  server: '192.168.1.1',
  secret: Buffer.from('testing123'),
  dict,
  timeout: 5,    // seconds per attempt
  retries: 3,    // total attempts, including the initial send
});

try {
  // Build the request
  const req = client.createAuthPacket();
  req.addAttribute('User-Name', 'alice@example.com');
  req.set('User-Password', [req.pwCrypt('s3cret!')]);
  req.addAttribute('NAS-IP-Address', '10.0.0.1');
  req.addAttribute('NAS-Port', 0);
  req.addAttribute('Service-Type', 'Framed-User');

  // Send and wait for reply
  const reply = await client.sendPacket(req);

  switch (reply.code) {
    case AccessAccept:
      console.log('Authenticated!');
      if (reply.has('Framed-IP-Address')) {
        console.log('Assigned IP:', reply.getAttribute('Framed-IP-Address')[0]);
      }
      if (reply.has('Session-Timeout')) {
        console.log('Session timeout:', reply.getAttribute('Session-Timeout')[0], 'seconds');
      }
      break;

    case AccessReject:
      console.log('Rejected.');
      if (reply.has('Reply-Message')) {
        console.log('Reason:', reply.getAttribute('Reply-Message')[0]);
      }
      break;

    case AccessChallenge:
      console.log('Challenge received — MFA or EAP continuation needed');
      break;
  }
} finally {
  client.close();
}
```

### CHAP authentication (client)

CHAP never sends the password in cleartext — not even encrypted. Instead, the client sends a hash of (CHAP-ID + password + challenge). The server must know the plaintext password to verify the hash.

```ts
import * as crypto from 'node:crypto';
import { Client, Dictionary, AccessAccept } from 'tsrad';

const dict = new Dictionary('/usr/share/freeradius/dictionary');
const client = new Client({
  server: '192.168.1.1',
  secret: Buffer.from('testing123'),
  dict,
});

const req = client.createAuthPacket();
req.addAttribute('User-Name', 'alice@example.com');

// Generate CHAP credentials
const chapId = Buffer.from([crypto.randomInt(0, 256)]);
const challenge = crypto.randomBytes(16);
const chapHash = crypto.createHash('md5')
  .update(chapId)
  .update(Buffer.from('s3cret!'))
  .update(challenge)
  .digest();

// CHAP-Password = 1 byte ID + 16 byte hash
req.set(3, [Buffer.concat([chapId, chapHash])]);    // code 3 = CHAP-Password
req.set(60, [challenge]);                             // code 60 = CHAP-Challenge

const reply = await client.sendPacket(req);
console.log(reply.code === AccessAccept ? 'OK' : 'FAIL');
client.close();
```

### IPv6 and local binding

Transport family is inferred from the server address, or can be selected
explicitly. Clients can bind to a local address or port:

```ts
const client = new Client({
  server: '2001:db8::10',
  family: 'udp6',
  localAddress: '2001:db8::20',
  localPort: 0,
  secret: Buffer.from('testing123'),
  dict,
});

client.bind('2001:db8::20');
```

Servers infer `udp4` or `udp6` from each address in `addresses`.

### Async APIs

Node's UDP API is already event-driven, but tsrad also exports `ClientAsync`
and `ServerAsync`. `ClientAsync` has the same Promise-based API as `Client`;
`ServerAsync` adds explicit transport lifecycle methods:

```ts
const server = new ServerAsync({ dict, hosts });
await server.initializeTransports(['127.0.0.1']);
await server.deinitializeTransports();
```

### Message-Authenticator

RFC 3579 defines Message-Authenticator — an HMAC-MD5 signature over the entire packet. Required for EAP, recommended for all Access-Request packets to prevent spoofing.

```ts
// Option 1: enforce globally — every auth packet gets Message-Authenticator
const client = new Client({
  server: '192.168.1.1',
  secret: Buffer.from('testing123'),
  dict,
  enforceMA: true,
});

const req = client.createAuthPacket();
// Message-Authenticator is automatically added
req.addAttribute('User-Name', 'alice');
req.set('User-Password', [req.pwCrypt('password')]);
const reply = await client.sendPacket(req);

// Option 2: add per-packet
const req2 = client.createAuthPacket();
req2.addAttribute('User-Name', 'bob');
req2.set('User-Password', [req2.pwCrypt('password')]);
req2.addMessageAuthenticator();  // explicit
const reply2 = await client.sendPacket(req2);

client.close();
```

When `enforceMA` is enabled, replies must also contain a valid
Message-Authenticator or `sendPacket()` will reject them. For lower-level
verification, use `req.verifyReply(reply, rawReply, true)`.

On the server side, verify it:

```ts
handleAuthPacket(pkt: RadiusPacket) {
  if (pkt.messageAuthenticator) {
    if (!pkt.verifyMessageAuthenticator()) {
      console.error('Message-Authenticator verification failed');
      // Don't reply — silently drop the packet per RFC 3579
      return;
    }
  }
  // ... process the request
}
```

### Accounting

Accounting packets track session lifecycle: Start, Interim-Update, Stop. The authenticator is computed (not random), so the server can verify the packet wasn't tampered with.

```ts
import { Client, Dictionary, AccountingResponse } from 'tsrad';

const dict = new Dictionary('/usr/share/freeradius/dictionary');
const client = new Client({
  server: '192.168.1.1',
  secret: Buffer.from('testing123'),
  dict,
});

// --- Session Start ---
const start = client.createAcctPacket();
start.addAttribute('User-Name', 'alice@example.com');
start.addAttribute('Acct-Status-Type', 'Start');
start.addAttribute('Acct-Session-Id', 'sess-00a1b2c3');
start.addAttribute('NAS-IP-Address', '10.0.0.1');
start.addAttribute('NAS-Port', 1);
start.addAttribute('Framed-IP-Address', '10.10.0.50');
start.addAttribute('Service-Type', 'Framed-User');

const startReply = await client.sendPacket(start);
console.log('Start acked:', startReply.code === AccountingResponse);

// --- Interim Update (5 minutes in) ---
const interim = client.createAcctPacket();
interim.addAttribute('User-Name', 'alice@example.com');
interim.addAttribute('Acct-Status-Type', 'Interim-Update');
interim.addAttribute('Acct-Session-Id', 'sess-00a1b2c3');
interim.addAttribute('NAS-IP-Address', '10.0.0.1');
interim.addAttribute('Acct-Session-Time', 300);
interim.addAttribute('Acct-Input-Octets', 1048576);      // 1 MB downloaded
interim.addAttribute('Acct-Output-Octets', 524288);       // 512 KB uploaded

const interimReply = await client.sendPacket(interim);
console.log('Interim acked:', interimReply.code === AccountingResponse);

// --- Session Stop ---
const stop = client.createAcctPacket();
stop.addAttribute('User-Name', 'alice@example.com');
stop.addAttribute('Acct-Status-Type', 'Stop');
stop.addAttribute('Acct-Session-Id', 'sess-00a1b2c3');
stop.addAttribute('NAS-IP-Address', '10.0.0.1');
stop.addAttribute('Acct-Session-Time', 3600);
stop.addAttribute('Acct-Input-Octets', 52428800);         // 50 MB
stop.addAttribute('Acct-Output-Octets', 10485760);        // 10 MB
stop.addAttribute('Acct-Terminate-Cause', 'User-Request');

const stopReply = await client.sendPacket(stop);
console.log('Stop acked:', stopReply.code === AccountingResponse);

client.close();
```

The client automatically increments `Acct-Delay-Time` on retries, so the server knows how stale the data is.

### CoA (Change of Authorization)

CoA lets you push policy changes to a NAS for an active session — change bandwidth, apply filters, or update session parameters without disconnecting the user.

```ts
import { Client, Dictionary, CoAACK, CoANAK } from 'tsrad';

const dict = new Dictionary('/usr/share/freeradius/dictionary');
const client = new Client({
  server: '192.168.1.1',     // the NAS (not the RADIUS server)
  secret: Buffer.from('coa_secret'),
  dict,
  coaport: 3799,
});

const coa = client.createCoAPacket();
coa.addAttribute('User-Name', 'alice@example.com');
coa.addAttribute('Acct-Session-Id', 'sess-00a1b2c3');
// Push new bandwidth policy
coa.addAttribute('Filter-Id', 'premium-100mbps');

try {
  const reply = await client.sendPacket(coa);
  if (reply.code === CoAACK) {
    console.log('Policy change applied');
  } else if (reply.code === CoANAK) {
    console.log('NAS rejected the CoA');
    if (reply.has('Error-Cause')) {
      console.log('Error-Cause:', reply.getAttribute('Error-Cause')[0]);
    }
  }
} finally {
  client.close();
}
```

### Disconnect Request

Force-disconnect a session from the NAS. Uses the same CoA port (3799) with a different packet code.

```ts
import {
  Client, Dictionary, CoAPacket,
  DisconnectRequest, DisconnectACK, DisconnectNAK,
} from 'tsrad';

const dict = new Dictionary('/usr/share/freeradius/dictionary');
const client = new Client({
  server: '192.168.1.1',
  secret: Buffer.from('coa_secret'),
  dict,
});

// DisconnectRequest is sent via createCoAPacket with explicit code
const disc = client.createCoAPacket({ code: DisconnectRequest });
disc.addAttribute('User-Name', 'alice@example.com');
disc.addAttribute('Acct-Session-Id', 'sess-00a1b2c3');
disc.addAttribute('NAS-IP-Address', '10.0.0.1');

const reply = await client.sendPacket(disc);
if (reply.code === DisconnectACK) {
  console.log('Session terminated');
} else if (reply.code === DisconnectNAK) {
  console.log('Disconnect refused');
}
client.close();
```

### Vendor-Specific Attributes

Many network equipment vendors define their own RADIUS attributes inside the Vendor-Specific (type 26) wrapper. tsrad handles them transparently once the vendor is defined in the dictionary.

```ts
import { Client, Dictionary, AccessAccept } from 'tsrad';

// Dictionary with Mikrotik vendor definitions
const dict = new Dictionary('/path/to/dictionary.mikrotik');
const client = new Client({
  server: '192.168.1.1',
  secret: Buffer.from('testing123'),
  dict,
});

// Reading vendor attributes from a reply
const req = client.createAuthPacket();
req.addAttribute('User-Name', 'alice');
req.set('User-Password', [req.pwCrypt('password')]);

const reply = await client.sendPacket(req);
if (reply.code === AccessAccept) {
  // Vendor attributes are accessed by name, same as standard attributes
  if (reply.has('Mikrotik-Rate-Limit')) {
    console.log('Rate limit:', reply.getAttribute('Mikrotik-Rate-Limit')[0]);
    // e.g. '10M/10M' for 10 Mbps up/down
  }
}

client.close();
```

On the server side, set vendor attributes in replies:

```ts
handleAuthPacket(pkt: RadiusPacket) {
  const reply = this.createReplyPacket(pkt, { code: AccessAccept });

  // Standard attributes
  reply.addAttribute('Framed-IP-Address', '10.10.0.50');
  reply.addAttribute('Session-Timeout', 86400);

  // Mikrotik-specific rate limiting
  reply.addAttribute('Mikrotik-Rate-Limit', '50M/50M');
  reply.addAttribute('Mikrotik-Recv-Limit', 0);
  reply.addAttribute('Mikrotik-Xmit-Limit', 0);

  this.sendReply(reply);
}
```

### Named values

When the dictionary defines `VALUE` mappings, you can use symbolic names instead of raw integers. This makes code self-documenting and less error-prone.

```ts
// Dictionary defines:
//   VALUE  Service-Type  Login-User   1
//   VALUE  Service-Type  Framed-User  2

// Set by name
pkt.addAttribute('Service-Type', 'Framed-User');

// Read back — returns the name, not the number
pkt.getAttribute('Service-Type');  // ['Framed-User']

// You can also use the raw integer
pkt.addAttribute('Service-Type', 2);

// Dictionary VALUE mappings for common attributes:
//   VALUE Acct-Status-Type  Start          1
//   VALUE Acct-Status-Type  Stop           2
//   VALUE Acct-Status-Type  Interim-Update 3
pkt.addAttribute('Acct-Status-Type', 'Start');

//   VALUE Acct-Terminate-Cause  User-Request   1
//   VALUE Acct-Terminate-Cause  Lost-Carrier   2
//   VALUE Acct-Terminate-Cause  Idle-Timeout   4
//   VALUE Acct-Terminate-Cause  Session-Timeout 5
pkt.addAttribute('Acct-Terminate-Cause', 'User-Request');
```

### Tagged attributes (RFC 2868)

Tunnel attributes use tags to group related attributes. For example, a NAS can establish multiple tunnels — tag 1 for the first, tag 2 for the second.

```ts
// Set tagged attributes using "Attribute-Name:tag" syntax
pkt.addAttribute('Tunnel-Type:1', 'L2TP');
pkt.addAttribute('Tunnel-Medium-Type:1', 'IPv4');
pkt.addAttribute('Tunnel-Server-Endpoint:1', '10.0.0.1');

// Second tunnel
pkt.addAttribute('Tunnel-Type:2', 'GRE');
pkt.addAttribute('Tunnel-Medium-Type:2', 'IPv4');
pkt.addAttribute('Tunnel-Server-Endpoint:2', '10.0.0.2');
```

### Salt encryption (RFC 2868)

Tunnel-Password and similar sensitive attributes use salt encryption — a per-attribute random salt combined with MD5-based encryption. This is handled automatically for attributes with `encrypt=2` in the dictionary, but you can also use it manually:

```ts
// Manual salt encrypt/decrypt
const encrypted = pkt.saltCrypt('my-tunnel-password');
// encrypted = [2-byte salt] + [encrypted data]

const decrypted = pkt.saltDecrypt(encrypted);
// decrypted.toString() === 'my-tunnel-password'
```

### TLV (Type-Length-Value) sub-attributes

Some vendors use TLV nesting — a parent attribute that contains sub-attributes. This is common in WiMAX and some newer vendor extensions.

```ts
// Dictionary defines:
//   ATTRIBUTE WiMAX-Capability    1 tlv
//   ATTRIBUTE WiMAX-Release     1.1 string
//   ATTRIBUTE WiMAX-Accounting  1.2 integer

// Add sub-attributes — they auto-nest under the parent
pkt.addAttribute('WiMAX-Release', '2.1');
pkt.addAttribute('WiMAX-Accounting', 1);

// Read the parent TLV — returns a structured object
const tlv = pkt.getAttribute('WiMAX-Capability');
// [{
//   'WiMAX-Release': ['2.1'],
//   'WiMAX-Accounting': [1],
// }]
```

### Constructing packets with attributes inline

You can pass attributes directly in the packet constructor using underscore-separated names:

```ts
const pkt = new AuthPacket({
  secret: Buffer.from('testing123'),
  dict,
  User_Name: 'alice',
  NAS_IP_Address: '10.0.0.1',
  NAS_Port: 1,
  Service_Type: 'Framed-User',
});
```

Underscores in the key are converted to hyphens, so `User_Name` becomes `User-Name`.

### Low-level packet access

For attributes not in the dictionary, or when you need raw Buffer access:

```ts
// Get/set by numeric attribute code
pkt.set(1, [Buffer.from('alice')]);           // User-Name
const raw = pkt.get(1);                        // [Buffer<616c696365>]

// Vendor attributes use tuple keys: [vendorId, attrCode]
pkt.set([14988, 8] as [number, number], [Buffer.from('50M/50M')]);
const vraw = pkt.get([14988, 8] as [number, number]);

// List all attribute keys
pkt.keys();  // ['User-Name', 'NAS-IP-Address', ...]
```

### Password encryption internals

RFC 2865 section 5.2 defines User-Password encryption:

```
b1 = MD5(secret + authenticator)
c1 = p1 XOR b1

b2 = MD5(secret + c1)
c2 = p2 XOR b2
...
```

Where `p1, p2, ...` are 16-byte blocks of the password (zero-padded).

```ts
// Encrypt — requires authenticator to be set
const encrypted = pkt.pwCrypt('mypassword');
// Returns a Buffer that can be set as User-Password

// Decrypt — uses the same authenticator and secret
const password = pkt.pwDecrypt(encrypted);
// Returns the original string

// Long passwords (>16 bytes) are handled automatically
const longEncrypted = pkt.pwCrypt('this-is-a-very-long-password-that-spans-multiple-blocks');
const longDecrypted = pkt.pwDecrypt(longEncrypted);
```

### Verifying reply packets

When you receive a reply, verify the authenticator matches what you expect:

```ts
const req = client.createAuthPacket();
// ... add attributes ...
const reply = await client.sendPacket(req);

// sendPacket does this automatically, but for manual UDP:
const isValid = req.verifyReply(reply);
// Checks: MD5(reply.code + reply.id + reply.length + request.authenticator + reply.attrs + secret)
```

For accounting packets:

```ts
const acct = new AcctPacket({
  secret: Buffer.from('testing123'),
  packet: rawUdpData,
});
const isValid = acct.verifyAcctRequest();
// Checks: MD5(code + id + length + zeros + attrs + secret)
```

---

### Building a RADIUS server

The server uses a subclass pattern. Override handler methods to implement your authentication and accounting logic.

#### Minimal auth server

```ts
import {
  Server, RemoteHost, Dictionary,
  AccessAccept, AccessReject,
  type RadiusPacket,
} from 'tsrad';

const dict = new Dictionary('/usr/share/freeradius/dictionary');

class SimpleAuthServer extends Server {
  handleAuthPacket(pkt: RadiusPacket) {
    const username = pkt.getAttribute('User-Name')[0] as string;
    const encrypted = pkt.getAttribute('User-Password')[0] as Buffer;
    const password = pkt.pwDecrypt(encrypted);

    const code = (username === 'admin' && password === 'admin')
      ? AccessAccept
      : AccessReject;

    const reply = this.createReplyPacket(pkt, { code });
    this.sendReply(reply);
  }
}

const server = new SimpleAuthServer({
  addresses: ['0.0.0.0'],
  dict,
  hosts: new Map([
    ['0.0.0.0', new RemoteHost('0.0.0.0', Buffer.from('testing123'), 'any')],
  ]),
});

server.on('ready', () => console.log('Listening on :1812'));
server.on('error', (err) => console.error(err.message));
server.run();
```

#### ISP subscriber management server

A more realistic example with a user database, session tracking, and accounting:

```ts
import {
  Server, RemoteHost, Dictionary,
  AccessAccept, AccessReject, AccountingResponse,
  type RadiusPacket,
} from 'tsrad';

const dict = new Dictionary(
  '/usr/share/freeradius/dictionary.rfc2865',
  '/usr/share/freeradius/dictionary.rfc2866',
  '/usr/share/freeradius/dictionary.mikrotik',
);

// --- Subscriber database ---
interface Subscriber {
  password: string;
  plan: string;
  ip: string;
  rateLimit: string;
  sessionTimeout: number;
}

const subscribers = new Map<string, Subscriber>([
  ['alice@isp.net', {
    password: 'alice123',
    plan: 'home-50',
    ip: '10.10.1.10',
    rateLimit: '50M/50M',
    sessionTimeout: 86400,
  }],
  ['bob@isp.net', {
    password: 'bob456',
    plan: 'business-100',
    ip: '10.10.2.20',
    rateLimit: '100M/100M',
    sessionTimeout: 0,  // no timeout
  }],
]);

// --- Active sessions ---
interface Session {
  username: string;
  nasIp: string;
  nasPort: number;
  startTime: Date;
  inputOctets: number;
  outputOctets: number;
}

const sessions = new Map<string, Session>();

// --- Server ---
class ISPServer extends Server {
  handleAuthPacket(pkt: RadiusPacket) {
    const username = pkt.getAttribute('User-Name')[0] as string;
    const encrypted = pkt.getAttribute('User-Password')[0] as Buffer;
    const password = pkt.pwDecrypt(encrypted);
    const nasIp = pkt.source.address;

    console.log(`[AUTH] ${username} from NAS ${nasIp}`);

    const sub = subscribers.get(username);
    if (!sub || sub.password !== password) {
      console.log(`[AUTH] ${username} REJECTED`);
      const reply = this.createReplyPacket(pkt, { code: AccessReject });
      reply.addAttribute('Reply-Message', 'Invalid username or password');
      this.sendReply(reply);
      return;
    }

    console.log(`[AUTH] ${username} ACCEPTED (plan: ${sub.plan})`);
    const reply = this.createReplyPacket(pkt, { code: AccessAccept });
    reply.addAttribute('Framed-IP-Address', sub.ip);
    reply.addAttribute('Framed-IP-Netmask', '255.255.255.0');
    reply.addAttribute('Service-Type', 'Framed-User');
    reply.addAttribute('Framed-Protocol', 'PPP');

    if (sub.sessionTimeout > 0) {
      reply.addAttribute('Session-Timeout', sub.sessionTimeout);
    }

    // Mikrotik-specific rate limiting
    reply.addAttribute('Mikrotik-Rate-Limit', sub.rateLimit);

    this.sendReply(reply);
  }

  handleAcctPacket(pkt: RadiusPacket) {
    const username = pkt.getAttribute('User-Name')[0] as string;
    const statusType = pkt.getAttribute('Acct-Status-Type')[0] as string;
    const sessionId = pkt.getAttribute('Acct-Session-Id')[0] as string;

    console.log(`[ACCT] ${username} ${statusType} (session: ${sessionId})`);

    switch (statusType) {
      case 'Start': {
        sessions.set(sessionId, {
          username,
          nasIp: pkt.getAttribute('NAS-IP-Address')[0] as string,
          nasPort: pkt.getAttribute('NAS-Port')[0] as number,
          startTime: new Date(),
          inputOctets: 0,
          outputOctets: 0,
        });
        break;
      }

      case 'Interim-Update': {
        const session = sessions.get(sessionId);
        if (session) {
          session.inputOctets = pkt.getAttribute('Acct-Input-Octets')[0] as number;
          session.outputOctets = pkt.getAttribute('Acct-Output-Octets')[0] as number;
        }
        break;
      }

      case 'Stop': {
        const session = sessions.get(sessionId);
        if (session) {
          const duration = pkt.getAttribute('Acct-Session-Time')[0] as number;
          const input = pkt.getAttribute('Acct-Input-Octets')[0] as number;
          const output = pkt.getAttribute('Acct-Output-Octets')[0] as number;
          const cause = pkt.has('Acct-Terminate-Cause')
            ? pkt.getAttribute('Acct-Terminate-Cause')[0] as string
            : 'Unknown';

          console.log(
            `[ACCT] Session ended: ${username}, ` +
            `duration=${duration}s, ` +
            `in=${(input / 1048576).toFixed(1)}MB, ` +
            `out=${(output / 1048576).toFixed(1)}MB, ` +
            `cause=${cause}`
          );
          sessions.delete(sessionId);
        }
        break;
      }
    }

    // Always acknowledge accounting packets
    const reply = this.createReplyPacket(pkt, { code: AccountingResponse });
    this.sendReply(reply);
  }
}

// --- NAS definitions ---
const hosts = new Map<string, RemoteHost>([
  ['10.0.0.1', new RemoteHost('10.0.0.1', Buffer.from('nas1_secret'), 'core-router')],
  ['10.0.0.2', new RemoteHost('10.0.0.2', Buffer.from('nas2_secret'), 'access-switch')],
  // Wildcard fallback for development
  ['0.0.0.0', new RemoteHost('0.0.0.0', Buffer.from('testing123'), 'any')],
]);

const server = new ISPServer({
  addresses: ['0.0.0.0'],
  dict,
  hosts,
  authEnabled: true,
  acctEnabled: true,
  coaEnabled: false,
});

server.on('ready', () => {
  console.log('ISP RADIUS server running');
  console.log('  Auth: :1812');
  console.log('  Acct: :1813');
});

server.on('error', (err) => {
  console.error('[ERROR]', err.message);
});

server.run();
```

#### CoA/Disconnect server

To receive CoA and Disconnect-Request packets from a management system, enable `coaEnabled`:

```ts
import {
  Server, RemoteHost, Dictionary,
  CoAACK, CoANAK, DisconnectACK, DisconnectNAK,
  type RadiusPacket,
} from 'tsrad';

const dict = new Dictionary('/usr/share/freeradius/dictionary');

class CoAServer extends Server {
  handleCoaPacket(pkt: RadiusPacket) {
    const username = pkt.getAttribute('User-Name')[0] as string;
    const sessionId = pkt.getAttribute('Acct-Session-Id')[0] as string;

    console.log(`[CoA] Change request for ${username} (session: ${sessionId})`);

    // Apply the policy change (implementation depends on your NAS)
    const success = this.applyPolicyChange(username, sessionId, pkt);

    const code = success ? CoAACK : CoANAK;
    const reply = this.createReplyPacket(pkt, { code });
    this.sendReply(reply);
  }

  handleDisconnectPacket(pkt: RadiusPacket) {
    const username = pkt.getAttribute('User-Name')[0] as string;
    const sessionId = pkt.getAttribute('Acct-Session-Id')[0] as string;

    console.log(`[DISCONNECT] Terminating ${username} (session: ${sessionId})`);

    const success = this.terminateSession(username, sessionId);

    const code = success ? DisconnectACK : DisconnectNAK;
    const reply = this.createReplyPacket(pkt, { code });
    this.sendReply(reply);
  }

  private applyPolicyChange(username: string, sessionId: string, pkt: RadiusPacket): boolean {
    // Your NAS-specific logic here
    return true;
  }

  private terminateSession(username: string, sessionId: string): boolean {
    // Your session termination logic here
    return true;
  }
}

const server = new CoAServer({
  addresses: ['0.0.0.0'],
  dict,
  hosts: new Map([
    ['0.0.0.0', new RemoteHost('0.0.0.0', Buffer.from('coa_secret'), 'any')],
  ]),
  authEnabled: false,   // this server only handles CoA
  acctEnabled: false,
  coaEnabled: true,
});

server.on('ready', () => console.log('CoA server on :3799'));
server.run();
```

#### Multiple NAS with per-host secrets

In production, each NAS has its own shared secret. The server looks up the secret by the source IP of incoming packets.

```ts
const hosts = new Map<string, RemoteHost>([
  // Core routers
  ['10.0.0.1', new RemoteHost('10.0.0.1', Buffer.from('r1$ecret!'), 'core-router-1')],
  ['10.0.0.2', new RemoteHost('10.0.0.2', Buffer.from('r2$ecret!'), 'core-router-2')],

  // Access switches
  ['10.1.0.1', new RemoteHost('10.1.0.1', Buffer.from('sw1$ecret'), 'access-sw-1')],
  ['10.1.0.2', new RemoteHost('10.1.0.2', Buffer.from('sw2$ecret'), 'access-sw-2')],

  // Wireless controllers
  ['10.2.0.1', new RemoteHost('10.2.0.1', Buffer.from('wlc$ecret'), 'wireless-ctrl')],

  // NO wildcard 0.0.0.0 — reject packets from unknown sources
]);

const server = new MyServer({
  addresses: ['10.0.0.254'],  // bind to management VLAN IP
  dict,
  hosts,
});
```

When a packet arrives from an IP not in the hosts map and there's no `0.0.0.0` fallback, the server emits an `error` event and drops the packet.

### Database-backed auth and accounting

tsrad includes a database integration module that implements FreeRADIUS `rlm_sql` compatible schema. This lets you authenticate users and record accounting data in any SQL database supported by [knex](https://knexjs.org/) (PostgreSQL, MySQL, SQLite, MSSQL).

If you have an existing FreeRADIUS database, tsrad works with it out of the box — same tables, same schema.

#### Install dependencies

knex is a peer dependency. Install it along with your database driver:

```bash
# PostgreSQL
npm install knex pg

# MySQL
npm install knex mysql2

# SQLite (for development/testing)
npm install knex better-sqlite3
```

#### Initialize the database

```ts
import knex from 'knex';
import { createSchema, dropSchema } from 'tsrad/db';

const db = knex({
  client: 'pg',
  connection: {
    host: '127.0.0.1',
    port: 5432,
    user: 'radius',
    password: 'radpass',
    database: 'radius',
  },
});

// Create the FreeRADIUS-compatible schema (idempotent — safe to call multiple times)
await createSchema(db);

// Tables created:
//   radcheck        — per-user check attributes (password, auth conditions)
//   radreply        — per-user reply attributes (IP, timeout, etc.)
//   radusergroup    — user-to-group membership with priority
//   radgroupcheck   — per-group check attributes
//   radgroupreply   — per-group reply attributes
//   radacct         — accounting records (session start/stop/interim)
//   nas             — NAS client definitions
```

#### Seed users

For application setup, `seedUser()` provides a typed convenience wrapper:

```ts
import { seedUser } from 'tsrad/db';

await seedUser(db, 'alice@isp.net', 'secret123', {
  checks: { 'NAS-Port': 1 },
  replies: { 'Session-Timeout': 86400 },
});
```

```ts
// Add a user with cleartext password
await db('radcheck').insert({
  username: 'alice@isp.net',
  attribute: 'Cleartext-Password',
  op: ':=',
  value: 'secret123',
});

// Add reply attributes (returned in Access-Accept)
await db('radreply').insert([
  { username: 'alice@isp.net', attribute: 'Framed-IP-Address', op: ':=', value: '10.10.1.10' },
  { username: 'alice@isp.net', attribute: 'Session-Timeout', op: ':=', value: '86400' },
  { username: 'alice@isp.net', attribute: 'Reply-Message', op: ':=', value: 'Welcome Alice!' },
]);

// Add check conditions (beyond password)
await db('radcheck').insert({
  username: 'alice@isp.net',
  attribute: 'NAS-Port',
  op: '>=',
  value: '1',
});
```

#### Set up groups

```ts
// Create group membership
await db('radusergroup').insert([
  { username: 'alice@isp.net', groupname: 'residential', priority: 1 },
  { username: 'alice@isp.net', groupname: 'premium', priority: 2 },
]);

// Group check attributes (conditions all group members must pass)
await db('radgroupcheck').insert({
  groupname: 'premium',
  attribute: 'NAS-Port',
  op: '>=',
  value: '1',
});

// Group reply attributes (added to Access-Accept for group members)
await db('radgroupreply').insert([
  { groupname: 'residential', attribute: 'Filter-Id', op: ':=', value: 'std-50mbps' },
  { groupname: 'premium', attribute: 'Filter-Id', op: ':=', value: 'premium-100mbps' },
]);
```

#### Quick start: DatabaseServer

The simplest way to run a database-backed RADIUS server:

```ts
import knex from 'knex';
import { RemoteHost, Dictionary } from 'tsrad';
import { DatabaseServer, createSchema } from 'tsrad/db';

const dict = new Dictionary('/usr/share/freeradius/dictionary');
const db = knex({
  client: 'pg',
  connection: 'postgres://radius:radpass@localhost/radius',
});

await createSchema(db);

const server = new DatabaseServer({
  addresses: ['0.0.0.0'],
  dict,
  knex: db,
  groups: true,  // enable group-based auth (default: true)
  hosts: new Map([
    ['10.0.0.1', new RemoteHost('10.0.0.1', Buffer.from('nas1_secret'), 'core-router')],
    ['0.0.0.0', new RemoteHost('0.0.0.0', Buffer.from('testing123'), 'any')],
  ]),
});

server.on('ready', () => {
  console.log('Database RADIUS server running');
  console.log('  Auth: :1812');
  console.log('  Acct: :1813');
});
server.on('error', (err) => console.error(err.message));
server.run();
```

This gives you:
- **Auth**: PAP and CHAP verification against `radcheck`, reply attrs from `radreply`, group-based auth via `radusergroup`/`radgroupcheck`/`radgroupreply`
- **Acct**: Session tracking in `radacct` (Start inserts, Interim-Update updates counters, Stop records stop time and terminate cause)

#### Handler factories: composing with your own server

If you need more control, use the handler factories directly. They return functions compatible with the Server handler signature:

```ts
import { Server, RemoteHost, Dictionary } from 'tsrad';
import { createDbAuth, createDbAcct } from 'tsrad/db';
import type { RadiusPacket } from 'tsrad';

const dict = new Dictionary('/usr/share/freeradius/dictionary');

class MyServer extends Server {
  constructor(db: Knex) {
    super({
      addresses: ['0.0.0.0'],
      dict,
      hosts: new Map([
        ['0.0.0.0', new RemoteHost('0.0.0.0', Buffer.from('secret'), 'any')],
      ]),
    });

    // Wire up database handlers
    this.handleAuthPacket = createDbAuth({
      knex: db,
      groups: true,        // check radusergroup + radgroupcheck + radgroupreply
      // Optional: custom password verifier
      // verifyPassword: (pkt, dbPassword) => myCustomCheck(pkt, dbPassword),
    });

    this.handleAcctPacket = createDbAcct({
      knex: db,
    });
  }
}
```

You can combine this with middleware for cross-cutting concerns:

```ts
const server = new MyServer(db);

// Middleware runs before the DB handler
server.useAuth(async (ctx, next) => {
  console.log(`Auth request from ${ctx.source.address}`);
  const start = Date.now();
  await next(ctx);
  console.log(`Auth completed in ${Date.now() - start}ms`);
});

server.run();
```

#### Query helpers for custom handlers

All query functions are exported for building custom authentication logic:

```ts
import {
  findUser, findUserReply, findUserGroups,
  findGroupCheck, findGroupReply,
  evaluateOp,
} from 'tsrad/db';

// In a custom handler
async function myAuthHandler(this: Server, pkt: RadiusPacket) {
  const username = pkt.getAttribute('User-Name')[0] as string;

  // Get check attributes from radcheck
  const checks = await findUser(db, username);

  // Get reply attributes from radreply
  const replyAttrs = await findUserReply(db, username);

  // Get user's groups (ordered by priority)
  const groups = await findUserGroups(db, username);

  // For each group, get check and reply attributes
  for (const group of groups) {
    const groupChecks = await findGroupCheck(db, group.groupname);
    const groupReplies = await findGroupReply(db, group.groupname);
    // ... your custom logic
  }

  // Evaluate check operators
  evaluateOp(':=', 'alice', 'alice');     // true  (equals)
  evaluateOp('!=', 'alice', 'bob');       // true  (not equals)
  evaluateOp('>=', '10', '5');            // true  (numeric >=)
  evaluateOp('=~', 'alice', 'ali.*');     // true  (regex match)
  evaluateOp('+=', 'any', 'thing');       // true  (always passes — adds to reply)
}
```

#### Check attribute operators

The `op` column in `radcheck` and `radgroupcheck` controls how attribute values are compared:

| Operator | Meaning | Example |
|----------|---------|---------|
| `:=` | Set/equals (assign value, or match exactly) | `Cleartext-Password := secret` |
| `==` | Equals | `NAS-IP-Address == 10.0.0.1` |
| `!=` | Not equals | `NAS-Port != 0` |
| `>=` | Greater than or equal (numeric) | `NAS-Port >= 1` |
| `>` | Greater than (numeric) | `Session-Timeout > 0` |
| `<=` | Less than or equal (numeric) | `NAS-Port <= 48` |
| `<` | Less than (numeric) | `Acct-Session-Time < 86400` |
| `=~` | Regex match | `Calling-Station-Id =~ ^aa:bb:.*` |
| `!~` | Regex non-match | `User-Name !~ @banned.com$` |
| `+=` | Append (always passes as check, adds to reply) | `Reply-Message += Extra info` |

#### Auth flow (how createDbAuth works)

1. Extract `User-Name` from the incoming packet
2. Query `radcheck` for all rows matching this username
3. If no rows found → Access-Reject
4. Find the `Cleartext-Password` row (op `:=` or `==`) and verify:
   - **PAP**: decrypt `User-Password` attribute via `pwDecrypt()`, compare to DB value
   - **CHAP**: verify via `verifyChapPasswd()` using the DB password
5. Evaluate remaining check attributes using their operators
6. On pass: query `radreply` for reply attributes
7. If groups enabled: query `radusergroup` → for each group, check `radgroupcheck`, collect `radgroupreply`
8. Build Access-Accept with all collected reply attributes
9. On any failure: Access-Reject

#### Acct flow (how createDbAcct works)

1. Extract `Acct-Status-Type`, `Acct-Session-Id`, `User-Name` from packet
2. **Start** → INSERT new row into `radacct` with session start time, NAS info, etc.
3. **Interim-Update** → UPDATE `radacct` with current counters (`Acct-Input-Octets`, `Acct-Output-Octets`, `Acct-Session-Time`)
4. **Stop** → UPDATE `radacct` with stop time, final counters, and `Acct-Terminate-Cause`
5. Always send Accounting-Response

#### Using SQLite for development

SQLite is ideal for local development and testing:

```ts
import knex from 'knex';
import { RemoteHost, Dictionary } from 'tsrad';
import { DatabaseServer, createSchema } from 'tsrad/db';

const db = knex({
  client: 'better-sqlite3',
  connection: { filename: './radius.db' },
  useNullAsDefault: true,
});

await createSchema(db);

// Seed a test user
await db('radcheck').insert({
  username: 'test', attribute: 'Cleartext-Password', op: ':=', value: 'test',
});

const dict = new Dictionary('/usr/share/freeradius/dictionary');
const server = new DatabaseServer({
  addresses: ['127.0.0.1'],
  dict,
  knex: db,
  hosts: new Map([
    ['0.0.0.0', new RemoteHost('0.0.0.0', Buffer.from('testing123'), 'any')],
  ]),
});

server.on('ready', () => console.log('Dev server on :1812/:1813'));
server.run();

// Test with radtest or any RADIUS client:
//   radtest test test 127.0.0.1 0 testing123
```

#### Migrating from FreeRADIUS

If you already have a FreeRADIUS database with `rlm_sql`, tsrad works with it directly — no migration needed. Just point knex at the same database:

```ts
const db = knex({
  client: 'mysql2',
  connection: {
    host: 'db.example.com',
    user: 'radius',
    password: 'radpass',
    database: 'radius',
  },
});

// Don't call createSchema() — your tables already exist
const server = new DatabaseServer({
  addresses: ['0.0.0.0'],
  dict,
  knex: db,
  hosts: new Map([...]),
});
server.run();
```

### Timeout handling

```ts
import { Client, Timeout } from 'tsrad';

const client = new Client({
  server: '192.168.1.1',
  secret: Buffer.from('testing123'),
  dict,
  timeout: 2,    // 2 seconds per attempt
  retries: 3,    // 3 total attempts = up to 6 seconds at a 2-second timeout
});

try {
  const reply = await client.sendPacket(req);
} catch (err) {
  if (err instanceof Timeout) {
    console.error('RADIUS server unreachable after 3 attempts (6 seconds)');
  } else {
    throw err;  // unexpected error
  }
} finally {
  client.close();
}
```

### Migrating from pyrad

The core operations map directly to the TypeScript API:

| pyrad | tsrad |
|---|---|
| `CreateAuthPacket()` | `createAuthPacket()` |
| `CreateAcctPacket()` | `createAcctPacket()` |
| `CreateCoAPacket()` | `createCoAPacket()` |
| `SendPacket()` | `sendPacket()` |
| `PwCrypt()` | `pwCrypt()` |
| `PwDecrypt()` | `pwDecrypt()` |
| `ReplyPacket()` | `replyPacket()` |
| `VerifyReply()` | `verifyReply()` |
| `Run()` | `run()` or `listen()` |
| `BindToAddress()` | `bindToAddress()` |

Uppercase compatibility aliases are also available for gradual migrations.
Secrets are intentionally typed as `Buffer` values in tsrad.

### Security checklist

- Use a separate shared secret for every NAS.
- Keep secrets outside source control; use a secret manager or environment variables.
- Keep `verifyPackets` enabled on servers unless interoperability testing requires otherwise.
- Use `enforceMA: true` for EAP and deployments that require signed Access-Request and reply packets.
- Restrict `hosts` to known NAS addresses instead of using a wildcard in production.
- Use RadSec when traffic crosses untrusted networks.

### Complete client-server round-trip example

A self-contained example that starts a server and sends a request to it:

```ts
import {
  Server, Client, RemoteHost, Dictionary,
  AccessAccept, AccessReject, AccountingResponse,
  type RadiusPacket,
} from 'tsrad';

const dict = new Dictionary('/usr/share/freeradius/dictionary');

// --- Server ---
class TestServer extends Server {
  handleAuthPacket(pkt: RadiusPacket) {
    const username = pkt.getAttribute('User-Name')[0] as string;
    const password = pkt.pwDecrypt(pkt.getAttribute('User-Password')[0] as Buffer);

    const code = (username === 'test' && password === 'test')
      ? AccessAccept : AccessReject;

    const reply = this.createReplyPacket(pkt, { code });
    if (code === AccessAccept) {
      reply.addAttribute('Reply-Message', 'Welcome, ' + username);
      reply.addAttribute('Session-Timeout', 3600);
    }
    this.sendReply(reply);
  }

  handleAcctPacket(pkt: RadiusPacket) {
    const reply = this.createReplyPacket(pkt, { code: AccountingResponse });
    this.sendReply(reply);
  }
}

const server = new TestServer({
  addresses: ['127.0.0.1'],
  dict,
  hosts: new Map([
    ['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('secret'), 'localhost')],
  ]),
});

server.on('ready', async () => {
  console.log('Server ready');

  // --- Client ---
  const client = new Client({
    server: '127.0.0.1',
    secret: Buffer.from('secret'),
    dict,
    timeout: 2,
    retries: 1,
  });

  // Auth request
  const req = client.createAuthPacket();
  req.addAttribute('User-Name', 'test');
  req.set('User-Password', [req.pwCrypt('test')]);

  const reply = await client.sendPacket(req);
  console.log('Auth reply code:', reply.code, reply.code === AccessAccept ? '(Accept)' : '(Reject)');
  if (reply.has('Reply-Message')) {
    console.log('Reply-Message:', reply.getAttribute('Reply-Message')[0]);
  }
  if (reply.has('Session-Timeout')) {
    console.log('Session-Timeout:', reply.getAttribute('Session-Timeout')[0]);
  }

  // Accounting request
  const acct = client.createAcctPacket();
  acct.addAttribute('User-Name', 'test');
  acct.addAttribute('Acct-Status-Type', 'Start');
  acct.addAttribute('Acct-Session-Id', 'test-session-001');

  const acctReply = await client.sendPacket(acct);
  console.log('Acct reply code:', acctReply.code, '(AccountingResponse)');

  client.close();
  server.stop();
  console.log('Done');
});

server.run();
```

### Data type reference

Quick reference for encoding and decoding attribute values:

```ts
import {
  encodeAttr, decodeAttr,
  encodeString, encodeAddress, encodeInteger, encodeInteger64,
  encodeDate, encodeOctets, encodeIPv6Address, encodeIPv6Prefix,
  encodeAscendBinary,
} from 'tsrad';

// string
encodeAttr('string', 'hello');                    // Buffer<68656c6c6f>
decodeAttr('string', Buffer.from('hello'));        // 'hello'

// ipaddr (IPv4)
encodeAttr('ipaddr', '192.168.1.1');              // Buffer<c0a80101>
decodeAttr('ipaddr', Buffer.from([192,168,1,1])); // '192.168.1.1'

// integer (uint32)
encodeAttr('integer', 42);                        // Buffer<0000002a>
decodeAttr('integer', Buffer.from([0,0,0,42]));   // 42

// integer64 (uint64)
encodeAttr('integer64', 9007199254740993n);        // Buffer<0020000000000001>
decodeAttr('integer64', Buffer.alloc(8));           // 0n

// date (unix timestamp as uint32)
encodeAttr('date', 1700000000);                    // Buffer<6554b5c0> (approx)
decodeAttr('date', Buffer.from([0x65,0x54,0xb5,0xc0])); // 1700000000

// octets (raw bytes)
encodeAttr('octets', '0xdeadbeef');               // Buffer<deadbeef>
encodeAttr('octets', Buffer.from([0xca, 0xfe]));  // Buffer<cafe>

// ipv6addr
encodeAttr('ipv6addr', '2001:db8::1');            // 16-byte Buffer
decodeAttr('ipv6addr', Buffer.alloc(16));          // '0000:0000:...:0000'

// ipv6prefix
encodeAttr('ipv6prefix', '2001:db8::/32');         // 18-byte Buffer
decodeAttr('ipv6prefix', Buffer.alloc(18));         // 'addr/prefix'

// signed (int32)
encodeAttr('signed', -1);                          // Buffer<ffffffff>

// short (uint16)
encodeAttr('short', 1024);                         // Buffer<0400>

// byte (uint8)
encodeAttr('byte', 255);                           // Buffer<ff>

// abinary (Ascend filter)
encodeAttr('abinary', 'family=ipv4 action=accept direction=in src=10.0.0.0/24');
// 56-byte Ascend binary filter
```

---

## Supported RFCs

| RFC | Description | tsrad support |
|-----|-------------|---------------|
| RFC 2865 | RADIUS Authentication | Full: Access-Request/Accept/Reject/Challenge, User-Password encryption, CHAP verification |
| RFC 2866 | RADIUS Accounting | Full: Accounting-Request/Response, authenticator verification, Acct-Delay-Time |
| RFC 2868 | RADIUS Tunnel Attributes | Full: tagged attributes, salt encryption (encrypt=2) |
| RFC 3576 | Dynamic Authorization (CoA) | Full: CoA-Request/ACK/NAK, Disconnect-Request/ACK/NAK |
| RFC 3579 | RADIUS EAP / Message-Authenticator | Message-Authenticator generation and verification |
| RFC 6614 | RADIUS over TLS (RadSec) | Full |
| RFC 6929 | Extended Attributes | Full |

## License

BSD-3-Clause
