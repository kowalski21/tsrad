# Server Guide

The `Server` class listens for incoming RADIUS packets on UDP and dispatches them to handler methods. Subclass `Server` and override the handlers to implement your RADIUS logic.

## Basic Server

```ts
import {
  Server, RemoteHost, Dictionary,
  AccessAccept, AccessReject,
  AccountingResponse,
  type RadiusPacket,
} from '@kowalski21/tsrad';

const dict = new Dictionary('/path/to/dictionary');

class MyServer extends Server {
  handleAuthPacket(pkt: RadiusPacket) {
    const username = pkt.getAttribute('User-Name')[0];
    const password = pkt.pwDecrypt(pkt.getAttribute('User-Password')[0]);

    let code = AccessReject;
    if (username === 'alice' && password === 'secret') {
      code = AccessAccept;
    }

    const reply = this.createReplyPacket(pkt, { code });
    if (code === AccessAccept) {
      reply.addAttribute('Framed-IP-Address', '10.0.0.100');
    }
    this.sendReply(reply);
  }

  handleAcctPacket(pkt: RadiusPacket) {
    const username = pkt.getAttribute('User-Name')[0];
    const statusType = pkt.getAttribute('Acct-Status-Type')[0];
    console.log(`Accounting: ${username} - ${statusType}`);

    const reply = this.createReplyPacket(pkt, { code: AccountingResponse });
    this.sendReply(reply);
  }
}
```

## Server Configuration

```ts
const server = new MyServer({
  addresses: ['0.0.0.0'],          // bind addresses
  authport: 1812,                   // default
  acctport: 1813,                   // default
  coaport: 3799,                    // default
  dict,
  authEnabled: true,                // default: true
  acctEnabled: true,                // default: true
  coaEnabled: false,                // default: false
  hosts: new Map([
    // Map of allowed NAS clients (by IP address)
    ['192.168.1.100', new RemoteHost(
      '192.168.1.100',
      Buffer.from('nas_secret'),
      'main-nas',
    )],
    // Wildcard: accept from any IP
    ['0.0.0.0', new RemoteHost(
      '0.0.0.0',
      Buffer.from('default_secret'),
      'any',
    )],
  ]),
});
```

### ServerOptions

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `addresses` | `string[]` | — | IP addresses to bind to |
| `authport` | `number` | `1812` | Authentication port |
| `acctport` | `number` | `1813` | Accounting port |
| `coaport` | `number` | `3799` | CoA/Disconnect port |
| `dict` | `Dictionary` | empty dict | RADIUS dictionary |
| `authEnabled` | `boolean` | `true` | Enable authentication listener |
| `acctEnabled` | `boolean` | `true` | Enable accounting listener |
| `coaEnabled` | `boolean` | `false` | Enable CoA/Disconnect listener |
| `hosts` | `Map<string, RemoteHost>` | empty map | Allowed NAS clients |
| `family` | `'udp4' \| 'udp6'` | inferred | UDP socket family; normally inferred from each address |
| `verifyPackets` | `boolean` | `true` | Verify accounting/CoA authenticators and Message-Authenticators |

## RemoteHost

Each allowed NAS client is defined as a `RemoteHost`:

```ts
import { RemoteHost } from '@kowalski21/tsrad';

const nas = new RemoteHost(
  '192.168.1.100',              // IP address
  Buffer.from('shared_secret'), // shared secret
  'my-nas',                     // friendly name
  {
    authport: 1812,             // optional overrides
    acctport: 1813,
    coaport: 3799,
  },
);
```

The server uses the source IP of incoming packets to look up the corresponding `RemoteHost` and its secret. If no match is found, it falls back to the `0.0.0.0` entry.

## Handler Methods

Override these methods in your subclass:

### handleAuthPacket(pkt)

Called when an Access-Request is received on the auth port.

```ts
handleAuthPacket(pkt: RadiusPacket) {
  // pkt.source.address — source IP of the NAS
  // pkt.source.port — source port
  // pkt.fd — the UDP socket (for advanced use)

  const reply = this.createReplyPacket(pkt, { code: AccessAccept });
  reply.addAttribute('Reply-Message', 'Welcome!');
  this.sendReply(reply);
}
```

### handleAcctPacket(pkt)

Called when an Accounting-Request or Accounting-Response is received on the acct port.

```ts
handleAcctPacket(pkt: RadiusPacket) {
  const reply = this.createReplyPacket(pkt, { code: AccountingResponse });
  this.sendReply(reply);
}
```

### handleCoaPacket(pkt)

Called when a CoA-Request is received on the CoA port. Requires `coaEnabled: true`.

```ts
handleCoaPacket(pkt: RadiusPacket) {
  const reply = this.createReplyPacket(pkt, { code: CoAACK });
  this.sendReply(reply);
}
```

### handleDisconnectPacket(pkt)

Called when a Disconnect-Request is received on the CoA port. Requires `coaEnabled: true`.

```ts
handleDisconnectPacket(pkt: RadiusPacket) {
  const reply = this.createReplyPacket(pkt, { code: DisconnectACK });
  this.sendReply(reply);
}
```

## Events

```ts
server.on('ready', () => {
  console.log('Server is listening');
});

server.on('error', (err) => {
  console.error('Server error:', err.message);
  // Errors include:
  // - Packets from unknown hosts
  // - Wrong packet type on port (e.g. acct packet on auth port)
  // - Malformed packets
});
```

## Starting and Stopping

```ts
// run() binds default 0.0.0.0 when no addresses were supplied,
// marks the server as active, and emits 'ready'
server.run();

// Stop: closes all sockets
server.stop();
```

## Binding to Multiple Addresses

```ts
const server = new MyServer({
  dict,
  hosts: new Map([...]),
});

// Bind manually to specific interfaces
server.bindToAddress('10.0.0.1');
server.bindToAddress('192.168.1.1');

server.run();
```

## Async server API

`Server` already supports Promise-returning handlers. `ServerAsync` provides
explicit async transport lifecycle methods:

```ts
import { ServerAsync } from '@kowalski21/tsrad';

const server = new ServerAsync({ dict, hosts });
await server.initializeTransports(['127.0.0.1']);
await server.deinitializeTransports();
```

Or pass addresses in the constructor:

```ts
const server = new MyServer({
  addresses: ['10.0.0.1', '192.168.1.1'],
  dict,
  hosts: new Map([...]),
});
server.run();
```

## Reply Helpers

### createReplyPacket(pkt, opts?)

Creates a reply packet that shares the same id, authenticator, and source info as the request. Pass `{ code: ... }` to set the response code.

```ts
const reply = this.createReplyPacket(pkt, { code: AccessAccept });
reply.addAttribute('Session-Timeout', 3600);
```

### sendReply(pkt)

Sends the reply back to the NAS that sent the original request.

```ts
this.sendReply(reply);
```

## Complete Example: ISP Auth Server

```ts
import {
  Server, RemoteHost, Dictionary,
  AccessAccept, AccessReject, AccountingResponse,
  type RadiusPacket,
} from '@kowalski21/tsrad';

const dict = new Dictionary('/usr/share/freeradius/dictionary');

// Simulated user database
const users = new Map([
  ['alice', { password: 'pass123', ip: '10.0.0.10', plan: '10mbps' }],
  ['bob',   { password: 'pass456', ip: '10.0.0.11', plan: '50mbps' }],
]);

class ISPServer extends Server {
  handleAuthPacket(pkt: RadiusPacket) {
    const username = pkt.getAttribute('User-Name')[0] as string;
    const encrypted = pkt.getAttribute('User-Password')[0] as Buffer;
    const password = pkt.pwDecrypt(encrypted);

    const user = users.get(username);
    if (!user || user.password !== password) {
      const reply = this.createReplyPacket(pkt, { code: AccessReject });
      reply.addAttribute('Reply-Message', 'Invalid credentials');
      this.sendReply(reply);
      return;
    }

    const reply = this.createReplyPacket(pkt, { code: AccessAccept });
    reply.addAttribute('Framed-IP-Address', user.ip);
    reply.addAttribute('Filter-Id', user.plan);
    reply.addAttribute('Session-Timeout', 86400);
    this.sendReply(reply);
  }

  handleAcctPacket(pkt: RadiusPacket) {
    const username = pkt.getAttribute('User-Name')[0];
    const status = pkt.getAttribute('Acct-Status-Type')[0];
    console.log(`[ACCT] ${username}: ${status}`);

    const reply = this.createReplyPacket(pkt, { code: AccountingResponse });
    this.sendReply(reply);
  }
}

const server = new ISPServer({
  addresses: ['0.0.0.0'],
  dict,
  hosts: new Map([
    ['0.0.0.0', new RemoteHost('0.0.0.0', Buffer.from('testing123'), 'any')],
  ]),
});

server.on('ready', () => console.log('ISP RADIUS server running on :1812/:1813'));
server.on('error', (err) => console.error('[ERROR]', err.message));
server.run();
```
