const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const projectDir = path.resolve(__dirname, '..');
const packageJson = require(path.join(projectDir, 'package.json'));
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tsrad-package-e2e-'));
const consumerDir = path.join(tempDir, 'consumer');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

async function main() {
  try {
    execFileSync(npm, ['pack', '--pack-destination', tempDir], {
      cwd: projectDir,
      stdio: 'ignore',
    });
    const tarball = path.join(tempDir, `${packageJson.name}-${packageJson.version}.tgz`);
    execFileSync(npm, ['install', '--prefix', consumerDir, tarball, '--ignore-scripts'], {
      stdio: 'ignore',
    });

    const tsrad = require(path.join(consumerDir, 'node_modules', 'tsrad'));
    const {
      Server, Client, RemoteHost, Dictionary,
      AccessAccept, AccountingResponse, CoAACK,
    } = tsrad;
    const secret = Buffer.from('package-e2e-secret');
    const dict = new Dictionary(path.join(projectDir, 'tests', 'data', 'realistic'));

    class PackageServer extends Server {
      handleAuthPacket(packet) {
        this.sendReply(this.createReplyPacket(packet, { code: AccessAccept }));
      }
      handleAcctPacket(packet) {
        this.sendReply(this.createReplyPacket(packet, { code: AccountingResponse }));
      }
      handleCoaPacket(packet) {
        this.sendReply(this.createReplyPacket(packet, { code: CoAACK }));
      }
    }

    const server = new PackageServer({
      addresses: ['127.0.0.1'],
      authport: 35182,
      acctport: 35183,
      coaport: 35379,
      coaEnabled: true,
      dict,
      hosts: new Map([
        ['127.0.0.1', new RemoteHost('127.0.0.1', secret, 'package-e2e')],
      ]),
      dedupTtl: false,
      rateLimit: false,
    });
    const client = new Client({
      server: '127.0.0.1',
      authport: 35182,
      acctport: 35183,
      coaport: 35379,
      secret,
      dict,
      timeout: 2,
      retries: 1,
    });

    try {
      await server.listen();

      const auth = client.createAuthPacket();
      auth.setUserName('package-user');
      auth.setPassword('package-password');
      assert.equal((await client.sendPacket(auth)).code, AccessAccept);

      const acct = client.createAcctPacket();
      acct.setUserName('package-user');
      acct.addAttribute('Acct-Status-Type', 'Start');
      acct.addAttribute('Acct-Session-Id', 'package-session');
      assert.equal((await client.sendPacket(acct)).code, AccountingResponse);

      const coa = client.createCoAPacket();
      coa.setUserName('package-user');
      assert.equal((await client.sendPacket(coa)).code, CoAACK);
    } finally {
      client.close();
      await server.gracefulStop();
    }

    console.log('packed-package auth/accounting/CoA E2E passed');
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
