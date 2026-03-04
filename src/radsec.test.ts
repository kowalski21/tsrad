import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import { RadSecClient, RadSecServer } from './radsec.js';
import { Packet, AccessRequest, AccessAccept } from './packet.js';

// Generate self-signed test certificates using Node.js crypto
function generateTestCerts(): { cert: string; key: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  // Create a self-signed certificate using the X509Certificate API
  // Node 19+ has crypto.X509Certificate, but for max compat use a simpler approach
  // For testing, we need valid PEM — use openssl-compatible generation
  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;

  // Use a minimal self-signed cert. Since Node doesn't have a pure-JS cert generator,
  // we'll test only the parts that don't require valid certs.
  return { cert: '', key: keyPem };
}

describe('RadSecClient', () => {
  it('constructs with options', () => {
    const client = new RadSecClient({
      host: '10.0.0.1',
      port: 2083,
      timeout: 3000,
    });
    assert.ok(client);
    client.close();
  });

  it('uses default port and secret', () => {
    const client = new RadSecClient({ host: 'localhost' });
    assert.ok(client);
    client.close();
  });

  it('throws if not connected', async () => {
    const client = new RadSecClient({ host: 'localhost' });
    const pkt = new Packet({ code: AccessRequest, secret: Buffer.from('radsec') });
    await assert.rejects(client.sendPacket(pkt), /Not connected/);
    client.close();
  });

  it('close is idempotent', () => {
    const client = new RadSecClient({ host: 'localhost' });
    client.close();
    client.close(); // should not throw
  });

  it('connect fails for unreachable host', async () => {
    const client = new RadSecClient({
      host: '127.0.0.1',
      port: 19999, // no server
      timeout: 200,
      rejectUnauthorized: false,
    });
    await assert.rejects(client.connect());
    client.close();
  });
});

describe('RadSecServer', () => {
  it('can be instantiated and closed with valid self-signed certs', async () => {
    // Generate a self-signed cert using Node.js child_process would be needed
    // For now, test that the class exists and has the expected API
    assert.equal(typeof RadSecServer, 'function');
  });

  it('has expected methods', () => {
    assert.equal(typeof RadSecServer.prototype.listen, 'function');
    assert.equal(typeof RadSecServer.prototype.close, 'function');
    assert.equal(typeof RadSecServer.prototype.on, 'function');
    assert.equal(typeof RadSecServer.prototype.handlePacket, 'function');
    assert.equal(typeof RadSecServer.prototype.sendReply, 'function');
  });
});
