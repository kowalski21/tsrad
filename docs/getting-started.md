# Getting Started

## Installation

```bash
cd tsrad
npm install
npx tsc
```

This compiles the TypeScript source into `dist/` with type declarations.

## Quick Start

### 1. Load a RADIUS Dictionary

tsrad uses FreeRADIUS-format dictionary files to define attributes. You need at least one dictionary file.

```ts
import { Dictionary } from 'tsrad';

const dict = new Dictionary('/path/to/dictionary');
```

A typical FreeRADIUS dictionary file looks like:

```
# /etc/freeradius/dictionary
$INCLUDE /usr/share/freeradius/dictionary.rfc2865
$INCLUDE /usr/share/freeradius/dictionary.rfc2866

VENDOR    MyVendor  12345
BEGIN-VENDOR MyVendor
ATTRIBUTE My-Custom-Attr 1 string
END-VENDOR MyVendor
```

You can load multiple dictionaries at once:

```ts
const dict = new Dictionary(
  '/usr/share/freeradius/dictionary.rfc2865',
  '/usr/share/freeradius/dictionary.rfc2866',
);
```

### 2. Send an Authentication Request

```ts
import { Client, Dictionary, AccessAccept, AccessReject } from 'tsrad';

const dict = new Dictionary('/path/to/dictionary');
const client = new Client({
  server: '127.0.0.1',
  secret: Buffer.from('testing123'),
  dict,
});

const req = client.createAuthPacket();
req.addAttribute('User-Name', 'alice');
req.set('User-Password', [req.pwCrypt('password123')]);

const reply = await client.sendPacket(req);
if (reply.code === AccessAccept) {
  console.log('Authenticated!');
} else if (reply.code === AccessReject) {
  console.log('Rejected');
}

client.close();
```

### 3. Build a RADIUS Server

```ts
import {
  Server, RemoteHost, Dictionary,
  AccessAccept, type RadiusPacket,
} from 'tsrad';

const dict = new Dictionary('/path/to/dictionary');

class MyServer extends Server {
  handleAuthPacket(pkt: RadiusPacket) {
    const username = pkt.getAttribute('User-Name')[0];
    console.log('Auth request from:', username);

    const reply = this.createReplyPacket(pkt, { code: AccessAccept });
    this.sendReply(reply);
  }
}

const server = new MyServer({
  addresses: ['0.0.0.0'],
  dict,
  hosts: new Map([
    ['0.0.0.0', new RemoteHost('0.0.0.0', Buffer.from('testing123'), 'any')],
  ]),
});

server.on('ready', () => console.log('RADIUS server listening'));
server.on('error', (err) => console.error('Error:', err.message));
server.run();
```

## Project Structure

```
tsrad/
├── src/
│   ├── index.ts        # Barrel exports
│   ├── bidict.ts       # Bidirectional map utility
│   ├── tools.ts        # Attribute type encoding/decoding
│   ├── dictfile.ts     # Dictionary file parser ($INCLUDE support)
│   ├── dictionary.ts   # RADIUS dictionary (ATTRIBUTE, VALUE, VENDOR)
│   ├── packet.ts       # Core packet classes (Packet, AuthPacket, AcctPacket, CoAPacket)
│   ├── host.ts         # Base Host class
│   ├── client.ts       # RADIUS client with retry/timeout
│   └── server.ts       # RADIUS server with handler pattern
├── docs/               # This documentation
├── package.json
└── tsconfig.json
```

## Supported RFCs

| RFC | Description | Support |
|-----|-------------|---------|
| RFC 2865 | RADIUS Authentication | Full |
| RFC 2866 | RADIUS Accounting | Full |
| RFC 2868 | RADIUS Tunnel Attributes (salt encryption) | Full |
| RFC 3576 | Dynamic Authorization (CoA/Disconnect) | Full |

## Next Steps

- [Client Guide](./client.md) — sending auth, accounting, CoA, and disconnect requests
- [Server Guide](./server.md) — building a RADIUS server
- [Dictionary Guide](./dictionary.md) — loading and understanding dictionary files
- [Packets Guide](./packets.md) — working with packets and attributes
- [API Reference](./api-reference.md) — complete API surface
