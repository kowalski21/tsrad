# API Reference

Complete API surface for tsrad.

---

## BiDict\<K, V\>

Bidirectional map with forward and backward lookups.

```ts
import { BiDict } from '@kowalski21/tsrad';
```

| Method | Returns | Description |
|--------|---------|-------------|
| `add(one: K, two: V)` | `void` | Add a bidirectional mapping |
| `get(key: K)` | `V` | Alias for `getForward` |
| `getForward(key: K)` | `V` | Look up by forward key (throws if missing) |
| `getBackward(key: V)` | `K` | Look up by backward key (throws if missing) |
| `hasForward(key: K)` | `boolean` | Check forward key exists |
| `hasBackward(key: V)` | `boolean` | Check backward key exists |
| `delete(key: K \| V)` | `void` | Delete from both directions |
| `length` | `number` | Number of entries |

---

## Dictionary

Parses and stores FreeRADIUS dictionary files.

```ts
import { Dictionary } from '@kowalski21/tsrad';
```

### Constructor

```ts
new Dictionary(...dicts: string[])
```

Accepts zero or more file paths. Each file is parsed immediately.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `vendors` | `BiDict<string, number>` | Vendor name ↔ vendor ID |
| `attrindex` | `BiDict<string, AttrKey>` | Attribute name ↔ numeric key |
| `attributes` | `Map<string, Attribute>` | Attribute name → definition |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `get(key: string)` | `Attribute \| undefined` | Get attribute by name |
| `has(key: string)` | `boolean` | Check if attribute exists |
| `readDictionary(file: string)` | `void` | Parse an additional dictionary file |

---

## Attribute

Represents a single RADIUS attribute definition.

```ts
import { Attribute } from '@kowalski21/tsrad';
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `name` | `string` | Attribute name |
| `code` | `number` | Numeric code |
| `type` | `RadiusDataType` | Data type |
| `vendor` | `string` | Vendor name (empty for standard attrs) |
| `encrypt` | `number` | Encryption method (0, 1, 2, 3) |
| `hasTag` | `boolean` | Supports RFC 2868 tags |
| `values` | `BiDict<string, Buffer>` | Named value mappings |
| `subAttributes` | `Map<number, string>` | TLV sub-attribute code → name |
| `parent` | `Attribute \| null` | Parent TLV attribute |
| `isSubAttribute` | `boolean` | Is a TLV sub-attribute |

---

## Packet

Base RADIUS packet class.

```ts
import { Packet } from '@kowalski21/tsrad';
```

### Constructor

```ts
new Packet(opts?: PacketOptions)
```

### PacketOptions

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `code` | `number` | `0` | Packet type code |
| `id` | `number` | auto | Packet identifier (0-255) |
| `secret` | `Buffer` | empty | Shared secret |
| `authenticator` | `Buffer \| null` | `null` | 16-byte authenticator |
| `dict` | `Dictionary` | — | RADIUS dictionary |
| `packet` | `Buffer` | — | Raw packet to decode |
| `messageAuthenticator` | `boolean` | — | Enable Message-Authenticator |

Named attributes can also be passed (underscores converted to hyphens):

```ts
new Packet({ dict, User_Name: 'alice' })
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `code` | `number` | Packet type code |
| `id` | `number` | Packet identifier |
| `secret` | `Buffer` | Shared secret |
| `authenticator` | `Buffer \| null` | 16-byte authenticator |
| `requestAuthenticator` | `Buffer \| null` | Original request authenticator (for reply verification) |
| `messageAuthenticator` | `boolean \| null` | Message-Authenticator present |
| `rawPacket` | `Buffer \| null` | Raw packet data (if decoded) |
| `dict` | `Dictionary` | RADIUS dictionary |

### Attribute Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `addAttribute(key: string, value: any)` | `void` | Add attribute by name (appends) |
| `getAttribute(key: string)` | `any[]` | Get decoded attribute values |
| `get(key: string \| number \| AttrKey)` | `AttrMapValue \| undefined` | Get raw attribute values |
| `set(key: string \| number \| AttrKey, value: AttrMapValue)` | `void` | Set/replace attribute values |
| `getStringAttribute(key, defaultValue?)` | `string \| undefined` | Read the first decoded string value |
| `getNumberAttribute(key, defaultValue?)` | `number \| undefined` | Read the first decoded numeric value |
| `getBufferAttribute(key, defaultValue?)` | `Buffer \| undefined` | Read the first decoded octet value |
| `setUserName(username)` | `void` | Convenience setter for `User-Name` |
| `setPassword(password)` | `void` | PAP-encrypt and set `User-Password` |
| `setNasIpAddress(address)` | `void` | Convenience setter for `NAS-IP-Address` |
| `has(key: string \| number)` | `boolean` | Check if attribute exists |
| `delete(key: string \| number)` | `void` | Remove attribute |
| `keys()` | `(string \| number)[]` | List all attribute names |

### Packet Encoding/Decoding

| Method | Returns | Description |
|--------|---------|-------------|
| `replyPacket()` | `Buffer` | Encode as reply packet |
| `decodePacket(packet: Buffer)` | `void` | Decode raw packet bytes |
| `createReply(opts?: PacketOptions)` | `Packet` | Create reply with same id/auth |
| `verifyReply(reply: Packet, rawReply?: Buffer)` | `boolean` | Verify reply authenticator |

### Static Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `Packet.createAuthenticator()` | `Buffer` | Generate random 16-byte authenticator |

### Password/Encryption

| Method | Returns | Description |
|--------|---------|-------------|
| `pwCrypt(password: string)` | `Buffer` | Encrypt password (RFC 2865) |
| `pwDecrypt(password: Buffer)` | `string` | Decrypt password |
| `saltCrypt(value: Buffer \| string)` | `Buffer` | Salt encrypt (RFC 2868) |
| `saltDecrypt(value: Buffer)` | `Buffer` | Salt decrypt |

### Message-Authenticator

| Method | Returns | Description |
|--------|---------|-------------|
| `addMessageAuthenticator()` | `void` | Add Message-Authenticator AVP |
| `verifyMessageAuthenticator(secret?, originalAuth?)` | `boolean` | Verify HMAC-MD5 |

### CHAP

| Method | Returns | Description |
|--------|---------|-------------|
| `verifyChapPasswd(userPwd: string)` | `boolean` | Verify CHAP-Password attribute |

---

## AuthPacket

Extends `Packet`. Default code: `AccessRequest` (1).

```ts
import { AuthPacket } from '@kowalski21/tsrad';
```

### Additional Properties

| Property | Type | Description |
|----------|------|-------------|
| `authType` | `string` | Authentication type (default `'pap'`) |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `requestPacket()` | `Buffer` | Encode as request (random authenticator) |
| `createReply(opts?)` | `AuthPacket` | Create reply (default code: AccessAccept) |
| `verifyAuthRequest()` | `boolean` | Verify request authenticator |

---

## AcctPacket

Extends `Packet`. Default code: `AccountingRequest` (4).

```ts
import { AcctPacket } from '@kowalski21/tsrad';
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `requestPacket()` | `Buffer` | Encode as request (computed authenticator) |
| `createReply(opts?)` | `AcctPacket` | Create reply (default code: AccountingResponse) |
| `verifyAcctRequest()` | `boolean` | Verify request authenticator |

---

## CoAPacket

Extends `Packet`. Default code: `CoARequest` (43).

```ts
import { CoAPacket } from '@kowalski21/tsrad';
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `requestPacket()` | `Buffer` | Encode as request (computed authenticator) |
| `createReply(opts?)` | `CoAPacket` | Create reply (default code: CoAACK) |
| `verifyCoARequest()` | `boolean` | Verify request authenticator |

---

## Host

Base class for RADIUS-capable hosts (Client and Server extend this).

```ts
import { Host } from '@kowalski21/tsrad';
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `dict` | `Dictionary` | RADIUS dictionary |
| `authport` | `number` | Auth port (default 1812) |
| `acctport` | `number` | Acct port (default 1813) |
| `coaport` | `number` | CoA port (default 3799) |

### Factory Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `createPacket(opts?)` | `Packet` | Create a generic packet |
| `createAuthPacket(opts?)` | `AuthPacket` | Create an auth packet |
| `createAcctPacket(opts?)` | `AcctPacket` | Create an accounting packet |
| `createCoAPacket(opts?)` | `CoAPacket` | Create a CoA packet |

### Send Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `sendPacketVia(socket, pkt, address, port)` | `void` | Send via a specific socket |
| `sendReplyVia(socket, pkt, address, port)` | `void` | Send reply via a specific socket |

---

## Client

RADIUS client. Extends `Host`.

```ts
import { Client } from '@kowalski21/tsrad';
```

### Constructor

```ts
new Client(opts: ClientOptions)
```

See [Client Guide](./client.md) for `ClientOptions`.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `server` | `string` | RADIUS server address |
| `secret` | `Buffer` | Shared secret |
| `retries` | `number` | Total send attempts, including the initial attempt |
| `timeout` | `number` | Timeout in seconds |
| `enforceMA` | `boolean` | Auto Message-Authenticator |
| `family` | `'udp4' \| 'udp6'` | UDP socket family |
| `localAddress` | `string` | Optional local bind address |
| `localPort` | `number` | Optional local bind port |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `createAuthPacket(opts?)` | `AuthPacket` | Create auth packet (with client secret) |
| `createAcctPacket(opts?)` | `AcctPacket` | Create acct packet (with client secret) |
| `createCoAPacket(opts?)` | `CoAPacket` | Create CoA packet (with client secret) |
| `sendPacket(pkt: Packet)` | `Promise<Packet>` | Send and wait for reply |
| `bind(address?)` | `void` | Bind the client socket to a local address/port |
| `close()` | `void` | Close UDP socket |

---

## Server

RADIUS server. Extends `Host`.

```ts
import { Server } from '@kowalski21/tsrad';
```

### Constructor

```ts
new Server(opts?: ServerOptions)
```

See [Server Guide](./server.md) for `ServerOptions`.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `hosts` | `Map<string, RemoteHost>` | Allowed NAS clients |
| `authEnabled` | `boolean` | Auth listener enabled |
| `acctEnabled` | `boolean` | Acct listener enabled |
| `coaEnabled` | `boolean` | CoA listener enabled |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `bindToAddress(addr: string)` | `void` | Bind to an IP address |
| `BindToAddress(addr: string)` | `void` | pyrad-compatible alias |
| `Run()` | `void` | pyrad-compatible alias for `run()` |
| `run()` | `void` | Start the server |
| `listen()` | `Promise<void>` | Start the server and yield after transport startup |
| `stop()` | `void` | Stop and close all sockets |
| `on(event, listener)` | `this` | Listen for events (`'ready'`, `'error'`) |

### Handler Methods (override in subclass)

| Method | Description |
|--------|-------------|
| `handleAuthPacket(pkt: RadiusPacket)` | Access-Request received |
| `handleAcctPacket(pkt: RadiusPacket)` | Accounting-Request received |
| `handleCoaPacket(pkt: RadiusPacket)` | CoA-Request received |
| `handleDisconnectPacket(pkt: RadiusPacket)` | Disconnect-Request received |

### Reply Helpers

| Method | Returns | Description |
|--------|---------|-------------|
| `createReplyPacket(pkt, opts?)` | `RadiusPacket` | Create reply preserving source info |
| `sendReply(pkt: RadiusPacket)` | `void` | Send reply to NAS |

---

## RemoteHost

Represents a NAS client allowed to connect to the server.

```ts
import { RemoteHost } from '@kowalski21/tsrad';
```

### Constructor

```ts
new RemoteHost(
  address: string,
  secret: Buffer,
  name: string,
  opts?: { authport?: number; acctport?: number; coaport?: number },
)
```

### Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `address` | `string` | — | IP address |
| `secret` | `Buffer` | — | Shared secret |
| `name` | `string` | — | Friendly name |
| `authport` | `number` | `1812` | Auth port |
| `acctport` | `number` | `1813` | Acct port |
| `coaport` | `number` | `3799` | CoA port |

---

## Error Classes

### PacketError

Thrown when decoding a malformed packet.

```ts
import { PacketError } from '@kowalski21/tsrad';
```

### ServerPacketError

Thrown when a server receives an unexpected packet (unknown host, wrong port, etc.).

```ts
import { ServerPacketError } from '@kowalski21/tsrad';
```

### Timeout

Thrown when a client doesn't receive a reply after all retries.

```ts
import { Timeout } from '@kowalski21/tsrad';
```

### ParseError

Thrown when a dictionary file has syntax errors.

```ts
import { ParseError } from '@kowalski21/tsrad';
// err.file — file name
// err.line — line number
```

---

## Encoding/Decoding Functions

Low-level functions for encoding and decoding RADIUS attribute values.

```ts
import {
  encodeString, decodeString,
  encodeOctets, decodeOctets,
  encodeAddress, decodeAddress,
  encodeIPv6Address, decodeIPv6Address,
  encodeIPv6Prefix, decodeIPv6Prefix,
  encodeAscendBinary, decodeAscendBinary,
  encodeInteger, decodeInteger,
  encodeInteger64, decodeInteger64,
  encodeDate, decodeDate,
  encodeAttr, decodeAttr,
} from '@kowalski21/tsrad';
```

### Dispatch

```ts
// Encode by type name
const buf = encodeAttr('ipaddr', '10.0.0.1');
const buf = encodeAttr('integer', 42);
const buf = encodeAttr('string', 'hello');

// Decode by type name
const ip = decodeAttr('ipaddr', buf);   // '10.0.0.1'
const num = decodeAttr('integer', buf); // 42
const str = decodeAttr('string', buf);  // 'hello'
```

---

## Utility Functions

### createID()

Generate a sequential packet ID (0-255, wrapping).

```ts
import { createID } from '@kowalski21/tsrad';
const id = createID(); // number 0-255
```

---

## Type Aliases

```ts
type AttrKey = number | [number, number] | [number, number, number];
type AttrValue = Buffer[];
type TlvValue = Map<number, Buffer[]>;
type AttrMapValue = AttrValue | TlvValue;
type RadiusDataType =
  | 'string' | 'octets' | 'integer' | 'ipaddr'
  | 'ipv6prefix' | 'ipv6addr' | 'abinary' | 'signed'
  | 'short' | 'byte' | 'date' | 'integer64' | 'tlv'
  | 'ifid' | 'ether';
```

### RadiusPacket (server-side)

```ts
interface RadiusPacket extends Packet {
  source: { address: string; port: number };
  fd: dgram.Socket;
}
```
