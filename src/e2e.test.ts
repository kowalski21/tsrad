import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  Server, RemoteHost, type RadiusPacket,
  Client, FailoverClient,
  ProxyServer,
  RadSecClient, RadSecServer,
  Dictionary, AuthPacket,
  AccessAccept, AccountingResponse, CoAACK,
} from './index.js';

const dataDir = path.resolve(__dirname, '..', 'tests', 'data');

function loadDict(): Dictionary {
  return new Dictionary(path.join(dataDir, 'realistic'));
}

describe('UDP transport E2E', () => {
  it('rejects listen when a UDP port cannot be bound', async () => {
    const first = new Server({
      addresses: ['127.0.0.1'], authport: 30181,
      acctEnabled: false, dedupTtl: false, rateLimit: false,
    });
    const second = new Server({
      addresses: ['127.0.0.1'], authport: 30181,
      acctEnabled: false, dedupTtl: false, rateLimit: false,
    });
    // Bind errors are observable through both the event API and listen().
    second.on('error', () => {});

    try {
      await first.listen();
      await assert.rejects(second.listen(), (error: NodeJS.ErrnoException) => {
        return error.code === 'EADDRINUSE';
      });
    } finally {
      first.stop();
      second.stop();
    }
  });

  it('round-trips authentication, accounting, and CoA', async () => {
    const dict = loadDict();
    const secret = Buffer.from('e2e-secret');

    class E2EServer extends Server {
      handleAuthPacket(pkt: RadiusPacket): void {
        assert.equal(pkt.getStringAttribute('User-Name'), 'alice');
        const reply = this.createReplyPacket(pkt, { code: AccessAccept });
        reply.addAttribute('Reply-Message', 'welcome');
        this.sendReply(reply);
      }

      handleAcctPacket(pkt: RadiusPacket): void {
        assert.equal(pkt.getStringAttribute('User-Name'), 'alice');
        this.sendReply(this.createReplyPacket(pkt, { code: AccountingResponse }));
      }

      handleCoaPacket(pkt: RadiusPacket): void {
        assert.equal(pkt.getStringAttribute('User-Name'), 'alice');
        this.sendReply(this.createReplyPacket(pkt, { code: CoAACK }));
      }
    }

    const server = new E2EServer({
      addresses: ['127.0.0.1'],
      authport: 30182,
      acctport: 30183,
      coaport: 30379,
      coaEnabled: true,
      dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', secret, 'e2e')],
      ]),
      dedupTtl: false,
      rateLimit: false,
    });
    const client = new Client({
      server: '127.0.0.1',
      authport: 30182,
      acctport: 30183,
      coaport: 30379,
      secret,
      dict,
      timeout: 2,
      retries: 1,
    });

    try {
      await server.listen();

      const auth = client.createAuthPacket();
      auth.setUserName('alice');
      auth.setPassword('secret');
      const authReply = await client.sendPacket(auth);
      assert.equal(authReply.code, AccessAccept);
      assert.equal(authReply.getStringAttribute('Reply-Message'), 'welcome');

      const acct = client.createAcctPacket();
      acct.setUserName('alice');
      acct.addAttribute('Acct-Status-Type', 'Start');
      acct.addAttribute('Acct-Session-Id', 'e2e-session');
      assert.equal((await client.sendPacket(acct)).code, AccountingResponse);

      const coa = client.createCoAPacket();
      coa.setUserName('alice');
      assert.equal((await client.sendPacket(coa)).code, CoAACK);
    } finally {
      client.close();
      await server.gracefulStop();
    }
  });

  it('round-trips over IPv6 when loopback is available', async (t) => {
    const dict = loadDict();
    const secret = Buffer.from('ipv6-secret');

    class IPv6Server extends Server {
      handleAuthPacket(pkt: RadiusPacket): void {
        this.sendReply(this.createReplyPacket(pkt, { code: AccessAccept }));
      }
    }

    const server = new IPv6Server({
      addresses: ['::1'],
      authport: 31182,
      acctEnabled: false,
      dict,
      hosts: new Map([['::1', new RemoteHost('::1', secret, 'ipv6')]]),
      dedupTtl: false,
      rateLimit: false,
    });

    try {
      try {
        await server.listen();
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === 'EAFNOSUPPORT' || code === 'EADDRNOTAVAIL') {
          t.skip(`IPv6 loopback unavailable: ${code}`);
          return;
        }
        throw error;
      }

      const client = new Client({
        server: '::1', family: 'udp6', authport: 31182,
        secret, dict, timeout: 2, retries: 1,
      });
      try {
        const request = client.createAuthPacket();
        request.setUserName('ipv6-user');
        assert.equal((await client.sendPacket(request)).code, AccessAccept);
      } finally {
        client.close();
      }
    } finally {
      await server.gracefulStop();
    }
  });
});

describe('Secret-boundary E2E', () => {
  it('re-encrypts PAP passwords through a proxy and closes upstream clients', async () => {
    const dict = loadDict();
    const downstreamSecret = Buffer.from('downstream-secret');
    const upstreamSecret = Buffer.from('upstream-secret');
    let upstreamPassword = '';

    class Upstream extends Server {
      handleAuthPacket(pkt: RadiusPacket): void {
        const encrypted = pkt.get('User-Password');
        assert.ok(Array.isArray(encrypted) && Buffer.isBuffer(encrypted[0]));
        upstreamPassword = pkt.pwDecrypt(encrypted[0]);
        this.sendReply(this.createReplyPacket(pkt, { code: AccessAccept }));
      }
    }

    const upstream = new Upstream({
      addresses: ['127.0.0.1'], authport: 32182, acctEnabled: false, dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', upstreamSecret, 'proxy')],
      ]),
      dedupTtl: false, rateLimit: false,
    });
    const proxy = new ProxyServer({
      addresses: ['127.0.0.1'], authport: 32183, acctEnabled: false, dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', downstreamSecret, 'nas')],
      ]),
      routes: {
        'example.com': {
          servers: [{ server: '127.0.0.1', authport: 32182, secret: upstreamSecret }],
        },
      },
      dedupTtl: false, rateLimit: false,
    });
    const client = new Client({
      server: '127.0.0.1', authport: 32183,
      secret: downstreamSecret, dict, timeout: 2, retries: 1,
    });

    try {
      await upstream.listen();
      await proxy.listen();
      const request = client.createAuthPacket();
      request.setUserName('alice@example.com');
      request.setPassword('secret');
      assert.equal((await client.sendPacket(request)).code, AccessAccept);
      assert.equal(upstreamPassword, 'secret');
    } finally {
      client.close();
      await proxy.gracefulStop();
      await upstream.gracefulStop();
    }

    assert.equal((proxy as any).realmClients.size, 0);
  });

  it('re-encrypts PAP passwords while failing over to a different secret', async () => {
    const dict = loadDict();
    const firstSecret = Buffer.from('first-secret');
    const secondSecret = Buffer.from('second-secret');
    let receivedPassword = '';

    class Secondary extends Server {
      handleAuthPacket(pkt: RadiusPacket): void {
        const encrypted = pkt.get('User-Password');
        assert.ok(Array.isArray(encrypted) && Buffer.isBuffer(encrypted[0]));
        receivedPassword = pkt.pwDecrypt(encrypted[0]);
        this.sendReply(this.createReplyPacket(pkt, { code: AccessAccept }));
      }
    }

    const secondary = new Secondary({
      addresses: ['127.0.0.1'], authport: 33182, acctEnabled: false, dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', secondSecret, 'secondary')],
      ]),
      dedupTtl: false, rateLimit: false,
    });
    const client = new FailoverClient({
      servers: [
        { server: '127.0.0.1', authport: 33181, secret: firstSecret },
        { server: '127.0.0.1', authport: 33182, secret: secondSecret },
      ],
      dict, timeout: 0.1, retries: 1,
    });

    try {
      await secondary.listen();
      const request = client.createAuthPacket();
      request.setUserName('alice');
      request.setPassword('secret');
      assert.equal((await client.sendPacket(request)).code, AccessAccept);
      assert.equal(receivedPassword, 'secret');
    } finally {
      client.close();
      await secondary.gracefulStop();
    }
  });
});

describe('RadSec E2E', () => {
  it('round-trips an Access-Request over TLS', async (t) => {
    if (spawnSync('openssl', ['version']).status !== 0) {
      t.skip('openssl is unavailable');
      return;
    }

    const certDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tsrad-radsec-'));
    const certPath = path.join(certDir, 'cert.pem');
    const keyPath = path.join(certDir, 'key.pem');
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-subj', '/CN=localhost', '-days', '1',
      '-keyout', keyPath, '-out', certPath,
    ], { stdio: 'ignore' });

    const dict = loadDict();
    const server = new RadSecServer({
      address: '127.0.0.1', port: 34283,
      cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath),
      requestCert: false, rejectUnauthorized: false, dict,
    });
    server.on('packet', (packet, socket) => {
      server.sendReply(packet.createReply({ code: AccessAccept }), socket);
    });
    const client = new RadSecClient({
      host: '127.0.0.1', port: 34283,
      rejectUnauthorized: false, dict, timeout: 2000,
    });

    try {
      await server.listen();
      await client.connect();
      const request = new AuthPacket({ dict });
      request.setUserName('radsec-user');
      assert.equal((await client.sendPacket(request)).code, AccessAccept);
    } finally {
      client.close();
      await server.close();
      fs.rmSync(certDir, { recursive: true, force: true });
    }
  });
});
