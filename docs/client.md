# Client Guide

The `Client` class sends RADIUS requests over UDP and waits for replies with configurable timeout and retries.

## Creating a Client

```ts
import { Client, Dictionary } from '@kowalski21/tsrad';

const dict = new Dictionary('/path/to/dictionary');
const client = new Client({
  server: '192.168.1.1',
  secret: Buffer.from('shared_secret'),
  dict,
  authport: 1812,   // default
  acctport: 1813,   // default
  coaport: 3799,    // default
  retries: 3,       // default
  timeout: 5,       // seconds, default
});
```

### ClientOptions

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `server` | `string` | *required* | RADIUS server hostname or IP |
| `secret` | `Buffer` | *required* | Shared secret |
| `dict` | `Dictionary` | empty dict | RADIUS dictionary |
| `authport` | `number` | `1812` | Authentication port |
| `acctport` | `number` | `1813` | Accounting port |
| `coaport` | `number` | `3799` | CoA/Disconnect port |
| `retries` | `number` | `3` | Total send attempts, including the initial attempt |
| `timeout` | `number` | `5` | Timeout per attempt in seconds |
| `enforceMA` | `boolean` | `false` | Add Message-Authenticator to auth packets and require it in replies |
| `family` | `'udp4' \| 'udp6'` | inferred | UDP socket family |
| `localAddress` | `string` | — | Local address to bind |
| `localPort` | `number` | — | Local port to bind |

## Authentication (Access-Request)

```ts
import { Client, AccessAccept, AccessReject, AccessChallenge } from '@kowalski21/tsrad';

const req = client.createAuthPacket();
req.addAttribute('User-Name', 'alice');
req.set('User-Password', [req.pwCrypt('secret123')]);

// Optional: add other attributes
req.addAttribute('NAS-IP-Address', '192.168.1.100');
req.addAttribute('NAS-Port', 1);

const reply = await client.sendPacket(req);

switch (reply.code) {
  case AccessAccept:
    console.log('Access accepted');
    // Read reply attributes
    if (reply.has('Framed-IP-Address')) {
      console.log('Assigned IP:', reply.getAttribute('Framed-IP-Address')[0]);
    }
    break;
  case AccessReject:
    console.log('Access rejected');
    if (reply.has('Reply-Message')) {
      console.log('Reason:', reply.getAttribute('Reply-Message')[0]);
    }
    break;
  case AccessChallenge:
    console.log('Challenge received');
    break;
}
```

### CHAP Authentication

```ts
import * as crypto from 'node:crypto';

const req = client.createAuthPacket();
req.addAttribute('User-Name', 'alice');

// CHAP: id + MD5(id + password + challenge)
const chapId = Buffer.from([crypto.randomInt(0, 256)]);
const challenge = crypto.randomBytes(16);
const chapHash = crypto.createHash('md5')
  .update(chapId)
  .update(Buffer.from('secret123'))
  .update(challenge)
  .digest();

req.set('CHAP-Password', [Buffer.concat([chapId, chapHash])]);
req.set('CHAP-Challenge', [challenge]);

const reply = await client.sendPacket(req);
```

### Message-Authenticator

For EAP and other protocols that require Message-Authenticator:

```ts
// Option 1: enable globally on the client
const client = new Client({
  server: '192.168.1.1',
  secret: Buffer.from('secret'),
  dict,
  enforceMA: true,  // all auth packets get Message-Authenticator
});

// Option 2: add manually per packet
const req = client.createAuthPacket();
req.addMessageAuthenticator();
```

## Accounting (Accounting-Request)

```ts
import { AccountingResponse } from '@kowalski21/tsrad';

const acct = client.createAcctPacket();
acct.addAttribute('User-Name', 'alice');
acct.addAttribute('Acct-Status-Type', 'Start');
acct.addAttribute('Acct-Session-Id', 'session-001');
acct.addAttribute('NAS-IP-Address', '192.168.1.100');
acct.addAttribute('NAS-Port', 1);

const reply = await client.sendPacket(acct);
if (reply.code === AccountingResponse) {
  console.log('Accounting acknowledged');
}
```

Accounting packets automatically:
- Compute the correct Request Authenticator (MD5 hash)
- Increment `Acct-Delay-Time` on retries

### Accounting Status Types

```ts
// Session start
acct.addAttribute('Acct-Status-Type', 'Start');

// Interim update
acct.addAttribute('Acct-Status-Type', 'Interim-Update');
acct.addAttribute('Acct-Input-Octets', 1048576);
acct.addAttribute('Acct-Output-Octets', 2097152);
acct.addAttribute('Acct-Session-Time', 3600);

// Session stop
acct.addAttribute('Acct-Status-Type', 'Stop');
acct.addAttribute('Acct-Terminate-Cause', 'User-Request');
```

## CoA (Change of Authorization)

```ts
import { CoAACK, CoANAK } from '@kowalski21/tsrad';

const coa = client.createCoAPacket();
coa.addAttribute('User-Name', 'alice');
coa.addAttribute('Acct-Session-Id', 'session-001');
// Change bandwidth
coa.addAttribute('Filter-Id', 'premium-plan');

const reply = await client.sendPacket(coa);
if (reply.code === CoAACK) {
  console.log('CoA accepted');
} else if (reply.code === CoANAK) {
  console.log('CoA rejected');
}
```

## Disconnect Request

```ts
import { CoAPacket, DisconnectRequest, DisconnectACK, DisconnectNAK } from '@kowalski21/tsrad';

const disc = client.createCoAPacket({ code: DisconnectRequest });
disc.addAttribute('User-Name', 'alice');
disc.addAttribute('Acct-Session-Id', 'session-001');
disc.addAttribute('NAS-IP-Address', '192.168.1.100');

const reply = await client.sendPacket(disc);
if (reply.code === DisconnectACK) {
  console.log('Session disconnected');
} else if (reply.code === DisconnectNAK) {
  console.log('Disconnect failed');
}
```

## Timeout Handling

```ts
import { Timeout } from '@kowalski21/tsrad';

try {
  const reply = await client.sendPacket(req);
} catch (err) {
  if (err instanceof Timeout) {
    console.error('RADIUS server did not reply after all retries');
  } else {
    throw err;
  }
}
```

## Closing the Client

Always close the client when done to release the UDP socket:

```ts
client.close();
```

## Local binding and IPv6

Use `bind()` when the client must use a specific local interface or port:

```ts
client.bind('192.168.1.20', 0);
```

IPv6 is supported through `udp6`:

```ts
const client = new Client({
  server: '2001:db8::10',
  family: 'udp6',
  secret: Buffer.from('secret'),
  dict,
});
```

## Port Selection

`sendPacket()` automatically selects the correct port based on packet type:

| Packet Type | Port Used |
|------------|-----------|
| `AuthPacket` | `authport` (1812) |
| `AcctPacket` | `acctport` (1813) |
| `CoAPacket` | `coaport` (3799) |
