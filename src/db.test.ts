import { describe, it, beforeEach, afterEach } from 'node:test';
import * as assert from 'node:assert/strict';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import knexLib, { type Knex } from 'knex';
import {
  createSchema, dropSchema,
  findUser, findUserReply, findUserGroups, findGroupCheck, findGroupReply,
  evaluateOp,
  createDbAuth, createDbAcct,
  DatabaseServer,
} from './db.js';
import { Dictionary } from './dictionary.js';
import { Server, RemoteHost, type RadiusPacket } from './server.js';
import { Client } from './client.js';
import {
  AccessAccept, AccessReject,
  AccountingResponse,
} from './packet.js';

const dataDir = path.resolve(__dirname, '..', 'tests', 'data');
const dict = new Dictionary(path.join(dataDir, 'db'));

function createTestDb(): Knex {
  return knexLib({
    client: 'better-sqlite3',
    connection: { filename: ':memory:' },
    useNullAsDefault: true,
  });
}

// ---- Schema tests ----

describe('createSchema / dropSchema', () => {
  let db: Knex;

  beforeEach(async () => {
    db = createTestDb();
  });

  afterEach(async () => {
    await db.destroy();
  });

  it('creates all tables', async () => {
    await createSchema(db);
    for (const table of ['radcheck', 'radreply', 'radusergroup', 'radgroupcheck', 'radgroupreply', 'radacct', 'nas']) {
      assert.equal(await db.schema.hasTable(table), true, `${table} should exist`);
    }
  });

  it('is idempotent', async () => {
    await createSchema(db);
    await createSchema(db); // should not throw
    assert.equal(await db.schema.hasTable('radcheck'), true);
  });

  it('dropSchema removes all tables', async () => {
    await createSchema(db);
    await dropSchema(db);
    for (const table of ['radcheck', 'radreply', 'radusergroup', 'radgroupcheck', 'radgroupreply', 'radacct', 'nas']) {
      assert.equal(await db.schema.hasTable(table), false, `${table} should not exist`);
    }
  });

  it('dropSchema is idempotent', async () => {
    await dropSchema(db); // nothing to drop, should not throw
    await createSchema(db);
    await dropSchema(db);
    await dropSchema(db); // already dropped, should not throw
  });
});

// ---- Operator tests ----

describe('evaluateOp', () => {
  it(':= equals', () => {
    assert.equal(evaluateOp(':=', 'foo', 'foo'), true);
    assert.equal(evaluateOp(':=', 'foo', 'bar'), false);
  });

  it('== equals', () => {
    assert.equal(evaluateOp('==', 'abc', 'abc'), true);
    assert.equal(evaluateOp('==', 'abc', 'xyz'), false);
  });

  it('!= not equals', () => {
    assert.equal(evaluateOp('!=', 'a', 'b'), true);
    assert.equal(evaluateOp('!=', 'a', 'a'), false);
  });

  it('>= numeric', () => {
    assert.equal(evaluateOp('>=', '10', '5'), true);
    assert.equal(evaluateOp('>=', '5', '5'), true);
    assert.equal(evaluateOp('>=', '3', '5'), false);
  });

  it('> numeric', () => {
    assert.equal(evaluateOp('>', '10', '5'), true);
    assert.equal(evaluateOp('>', '5', '5'), false);
  });

  it('<= numeric', () => {
    assert.equal(evaluateOp('<=', '3', '5'), true);
    assert.equal(evaluateOp('<=', '5', '5'), true);
    assert.equal(evaluateOp('<=', '10', '5'), false);
  });

  it('< numeric', () => {
    assert.equal(evaluateOp('<', '3', '5'), true);
    assert.equal(evaluateOp('<', '5', '5'), false);
  });

  it('=~ regex match', () => {
    assert.equal(evaluateOp('=~', 'foobar', 'foo.*'), true);
    assert.equal(evaluateOp('=~', 'baz', 'foo.*'), false);
  });

  it('!~ regex non-match', () => {
    assert.equal(evaluateOp('!~', 'baz', 'foo.*'), true);
    assert.equal(evaluateOp('!~', 'foobar', 'foo.*'), false);
  });

  it('+= always passes', () => {
    assert.equal(evaluateOp('+=', 'anything', 'whatever'), true);
  });

  it('unknown op returns false', () => {
    assert.equal(evaluateOp('??', 'a', 'b'), false);
  });
});

// ---- Query helper tests ----

describe('query helpers', () => {
  let db: Knex;

  beforeEach(async () => {
    db = createTestDb();
    await createSchema(db);
  });

  afterEach(async () => {
    await db.destroy();
  });

  it('findUser returns check rows', async () => {
    await db('radcheck').insert([
      { username: 'alice', attribute: 'Cleartext-Password', op: ':=', value: 'secret' },
      { username: 'alice', attribute: 'Service-Type', op: '==', value: 'Framed-User' },
      { username: 'bob', attribute: 'Cleartext-Password', op: ':=', value: 'other' },
    ]);

    const rows = await findUser(db, 'alice');
    assert.equal(rows.length, 2);
    assert.equal(rows[0].attribute, 'Cleartext-Password');
    assert.equal(rows[1].attribute, 'Service-Type');
  });

  it('findUser returns empty for unknown user', async () => {
    const rows = await findUser(db, 'nobody');
    assert.equal(rows.length, 0);
  });

  it('findUserReply returns reply rows', async () => {
    await db('radreply').insert([
      { username: 'alice', attribute: 'Reply-Message', op: ':=', value: 'Welcome' },
      { username: 'alice', attribute: 'Session-Timeout', op: ':=', value: '3600' },
    ]);

    const rows = await findUserReply(db, 'alice');
    assert.equal(rows.length, 2);
    assert.equal(rows[0].value, 'Welcome');
  });

  it('findUserGroups returns groups ordered by priority', async () => {
    await db('radusergroup').insert([
      { username: 'alice', groupname: 'premium', priority: 2 },
      { username: 'alice', groupname: 'users', priority: 1 },
    ]);

    const rows = await findUserGroups(db, 'alice');
    assert.equal(rows.length, 2);
    assert.equal(rows[0].groupname, 'users');
    assert.equal(rows[1].groupname, 'premium');
  });

  it('findGroupCheck / findGroupReply', async () => {
    await db('radgroupcheck').insert([
      { groupname: 'users', attribute: 'NAS-Port', op: '>=', value: '1' },
    ]);
    await db('radgroupreply').insert([
      { groupname: 'users', attribute: 'Reply-Message', op: ':=', value: 'Group hello' },
    ]);

    const checks = await findGroupCheck(db, 'users');
    assert.equal(checks.length, 1);
    assert.equal(checks[0].attribute, 'NAS-Port');

    const replies = await findGroupReply(db, 'users');
    assert.equal(replies.length, 1);
    assert.equal(replies[0].value, 'Group hello');
  });
});

// ---- Auth handler tests ----

describe('createDbAuth handler', () => {
  let db: Knex;
  const basePort = 19200 + Math.floor(Math.random() * 800);

  beforeEach(async () => {
    db = createTestDb();
    await createSchema(db);
  });

  afterEach(async () => {
    await db.destroy();
  });

  it('PAP accept', async () => {
    await db('radcheck').insert({
      username: 'alice', attribute: 'Cleartext-Password', op: ':=', value: 'secret123',
    });

    const authPort = basePort;
    class TestServer extends Server {
      constructor() {
        super({
          addresses: ['127.0.0.1'],
          authport: authPort,
          acctEnabled: false,
          dedupTtl: false,
          rateLimit: false,
          dict,
          hosts: new Map([['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('testing'), 'test')]]),
        });
        this.handleAuthPacket = createDbAuth({ knex: db, groups: false });
      }
    }

    const server = new TestServer();
    await new Promise<void>((r) => { server.on('ready', r); server.run(); });

    const client = new Client({ server: '127.0.0.1', authport: authPort, secret: Buffer.from('testing'), dict, timeout: 2, retries: 1 });
    const req = client.createAuthPacket();
    req.addAttribute('User-Name', 'alice');
    req.set('User-Password', [req.pwCrypt('secret123')]);

    const reply = await client.sendPacket(req);
    assert.equal(reply.code, AccessAccept);

    client.close();
    server.stop();
  });

  it('PAP reject — wrong password', async () => {
    await db('radcheck').insert({
      username: 'alice', attribute: 'Cleartext-Password', op: ':=', value: 'secret123',
    });

    const authPort = basePort + 1;
    class TestServer extends Server {
      constructor() {
        super({
          addresses: ['127.0.0.1'],
          authport: authPort,
          acctEnabled: false,
          dedupTtl: false,
          rateLimit: false,
          dict,
          hosts: new Map([['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('testing'), 'test')]]),
        });
        this.handleAuthPacket = createDbAuth({ knex: db, groups: false });
      }
    }

    const server = new TestServer();
    await new Promise<void>((r) => { server.on('ready', r); server.run(); });

    const client = new Client({ server: '127.0.0.1', authport: authPort, secret: Buffer.from('testing'), dict, timeout: 2, retries: 1 });
    const req = client.createAuthPacket();
    req.addAttribute('User-Name', 'alice');
    req.set('User-Password', [req.pwCrypt('wrongpass')]);

    const reply = await client.sendPacket(req);
    assert.equal(reply.code, AccessReject);

    client.close();
    server.stop();
  });

  it('user not found — reject', async () => {
    const authPort = basePort + 2;
    class TestServer extends Server {
      constructor() {
        super({
          addresses: ['127.0.0.1'],
          authport: authPort,
          acctEnabled: false,
          dedupTtl: false,
          rateLimit: false,
          dict,
          hosts: new Map([['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('testing'), 'test')]]),
        });
        this.handleAuthPacket = createDbAuth({ knex: db, groups: false });
      }
    }

    const server = new TestServer();
    await new Promise<void>((r) => { server.on('ready', r); server.run(); });

    const client = new Client({ server: '127.0.0.1', authport: authPort, secret: Buffer.from('testing'), dict, timeout: 2, retries: 1 });
    const req = client.createAuthPacket();
    req.addAttribute('User-Name', 'nobody');
    req.set('User-Password', [req.pwCrypt('anything')]);

    const reply = await client.sendPacket(req);
    assert.equal(reply.code, AccessReject);

    client.close();
    server.stop();
  });

  it('check attributes with operators', async () => {
    await db('radcheck').insert([
      { username: 'alice', attribute: 'Cleartext-Password', op: ':=', value: 'pass' },
      { username: 'alice', attribute: 'NAS-Port', op: '>=', value: '1' },
    ]);

    const authPort = basePort + 3;
    class TestServer extends Server {
      constructor() {
        super({
          addresses: ['127.0.0.1'],
          authport: authPort,
          acctEnabled: false,
          dedupTtl: false,
          rateLimit: false,
          dict,
          hosts: new Map([['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('testing'), 'test')]]),
        });
        this.handleAuthPacket = createDbAuth({ knex: db, groups: false });
      }
    }

    const server = new TestServer();
    await new Promise<void>((r) => { server.on('ready', r); server.run(); });

    const client = new Client({ server: '127.0.0.1', authport: authPort, secret: Buffer.from('testing'), dict, timeout: 2, retries: 1 });

    // Request with NAS-Port = 5 (passes >= 1 check)
    const req1 = client.createAuthPacket();
    req1.addAttribute('User-Name', 'alice');
    req1.set('User-Password', [req1.pwCrypt('pass')]);
    req1.addAttribute('NAS-Port', 5);
    const reply1 = await client.sendPacket(req1);
    assert.equal(reply1.code, AccessAccept);

    // Request with NAS-Port = 0 (fails >= 1 check)
    const req2 = client.createAuthPacket();
    req2.addAttribute('User-Name', 'alice');
    req2.set('User-Password', [req2.pwCrypt('pass')]);
    req2.addAttribute('NAS-Port', 0);
    const reply2 = await client.sendPacket(req2);
    assert.equal(reply2.code, AccessReject);

    client.close();
    server.stop();
  });

  it('reply attributes from radreply', async () => {
    await db('radcheck').insert({
      username: 'alice', attribute: 'Cleartext-Password', op: ':=', value: 'pass',
    });
    await db('radreply').insert([
      { username: 'alice', attribute: 'Reply-Message', op: ':=', value: 'Hello Alice' },
      { username: 'alice', attribute: 'Session-Timeout', op: ':=', value: '3600' },
    ]);

    const authPort = basePort + 4;
    class TestServer extends Server {
      constructor() {
        super({
          addresses: ['127.0.0.1'],
          authport: authPort,
          acctEnabled: false,
          dedupTtl: false,
          rateLimit: false,
          dict,
          hosts: new Map([['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('testing'), 'test')]]),
        });
        this.handleAuthPacket = createDbAuth({ knex: db, groups: false });
      }
    }

    const server = new TestServer();
    await new Promise<void>((r) => { server.on('ready', r); server.run(); });

    const client = new Client({ server: '127.0.0.1', authport: authPort, secret: Buffer.from('testing'), dict, timeout: 2, retries: 1 });
    const req = client.createAuthPacket();
    req.addAttribute('User-Name', 'alice');
    req.set('User-Password', [req.pwCrypt('pass')]);

    const reply = await client.sendPacket(req);
    assert.equal(reply.code, AccessAccept);
    assert.equal(reply.getAttribute('Reply-Message')[0], 'Hello Alice');

    client.close();
    server.stop();
  });

  it('group auth with radgroupcheck and radgroupreply', async () => {
    await db('radcheck').insert({
      username: 'bob', attribute: 'Cleartext-Password', op: ':=', value: 'pass',
    });
    await db('radusergroup').insert({
      username: 'bob', groupname: 'vip', priority: 1,
    });
    await db('radgroupreply').insert({
      groupname: 'vip', attribute: 'Reply-Message', op: ':=', value: 'VIP access',
    });

    const authPort = basePort + 5;
    class TestServer extends Server {
      constructor() {
        super({
          addresses: ['127.0.0.1'],
          authport: authPort,
          acctEnabled: false,
          dedupTtl: false,
          rateLimit: false,
          dict,
          hosts: new Map([['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('testing'), 'test')]]),
        });
        this.handleAuthPacket = createDbAuth({ knex: db, groups: true });
      }
    }

    const server = new TestServer();
    await new Promise<void>((r) => { server.on('ready', r); server.run(); });

    const client = new Client({ server: '127.0.0.1', authport: authPort, secret: Buffer.from('testing'), dict, timeout: 2, retries: 1 });
    const req = client.createAuthPacket();
    req.addAttribute('User-Name', 'bob');
    req.set('User-Password', [req.pwCrypt('pass')]);

    const reply = await client.sendPacket(req);
    assert.equal(reply.code, AccessAccept);
    assert.equal(reply.getAttribute('Reply-Message')[0], 'VIP access');

    client.close();
    server.stop();
  });

  it('CHAP auth with verifyChapPasswd', async () => {
    await db('radcheck').insert({
      username: 'charlie', attribute: 'Cleartext-Password', op: ':=', value: 'chappass',
    });

    const authPort = basePort + 6;
    class TestServer extends Server {
      constructor() {
        super({
          addresses: ['127.0.0.1'],
          authport: authPort,
          acctEnabled: false,
          dedupTtl: false,
          rateLimit: false,
          dict,
          hosts: new Map([['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('testing'), 'test')]]),
        });
        this.handleAuthPacket = createDbAuth({ knex: db, groups: false });
      }
    }

    const server = new TestServer();
    await new Promise<void>((r) => { server.on('ready', r); server.run(); });

    const client = new Client({ server: '127.0.0.1', authport: authPort, secret: Buffer.from('testing'), dict, timeout: 2, retries: 1 });
    const req = client.createAuthPacket();
    req.addAttribute('User-Name', 'charlie');

    // Build CHAP-Password: chapId(1) + MD5(chapId + password + authenticator)
    const chapId = Buffer.from([42]);
    if (!req.authenticator) req.authenticator = crypto.randomBytes(16);
    const chapHash = crypto.createHash('md5')
      .update(chapId)
      .update(Buffer.from('chappass', 'utf-8'))
      .update(req.authenticator)
      .digest();
    req.set('CHAP-Password', [Buffer.concat([chapId, chapHash])]);

    const reply = await client.sendPacket(req);
    assert.equal(reply.code, AccessAccept);

    client.close();
    server.stop();
  });
});

// ---- Acct handler tests ----

describe('createDbAcct handler', () => {
  let db: Knex;
  const basePort = 19300 + Math.floor(Math.random() * 600);

  beforeEach(async () => {
    db = createTestDb();
    await createSchema(db);
  });

  afterEach(async () => {
    await db.destroy();
  });

  it('Start inserts into radacct', async () => {
    const acctPort = basePort;
    class TestServer extends Server {
      constructor() {
        super({
          addresses: ['127.0.0.1'],
          acctport: acctPort,
          authEnabled: false,
          dedupTtl: false,
          rateLimit: false,
          dict,
          hosts: new Map([['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('testing'), 'test')]]),
        });
        this.handleAcctPacket = createDbAcct({ knex: db });
      }
    }

    const server = new TestServer();
    await new Promise<void>((r) => { server.on('ready', r); server.run(); });

    const client = new Client({ server: '127.0.0.1', acctport: acctPort, secret: Buffer.from('testing'), dict, timeout: 2, retries: 1 });
    const req = client.createAcctPacket();
    req.addAttribute('User-Name', 'alice');
    req.addAttribute('Acct-Session-Id', 'sess-001');
    req.addAttribute('Acct-Status-Type', 'Start');
    req.addAttribute('NAS-IP-Address', '10.0.0.1');
    req.addAttribute('Calling-Station-Id', 'aa:bb:cc:dd:ee:ff');

    const reply = await client.sendPacket(req);
    assert.equal(reply.code, AccountingResponse);

    const rows = await db('radacct').select('*');
    assert.equal(rows.length, 1);
    assert.equal(rows[0].username, 'alice');
    assert.equal(rows[0].acctsessionid, 'sess-001');
    assert.equal(rows[0].nasipaddress, '10.0.0.1');
    assert.equal(rows[0].callingstationid, 'aa:bb:cc:dd:ee:ff');
    assert.ok(rows[0].acctstarttime);

    client.close();
    server.stop();
  });

  it('Interim-Update updates radacct', async () => {
    const acctPort = basePort + 1;
    class TestServer extends Server {
      constructor() {
        super({
          addresses: ['127.0.0.1'],
          acctport: acctPort,
          authEnabled: false,
          dedupTtl: false,
          rateLimit: false,
          dict,
          hosts: new Map([['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('testing'), 'test')]]),
        });
        this.handleAcctPacket = createDbAcct({ knex: db });
      }
    }

    // Pre-insert a session
    await db('radacct').insert({
      acctsessionid: 'sess-002', username: 'bob', nasipaddress: '10.0.0.1',
      acctstarttime: new Date().toISOString(),
    });

    const server = new TestServer();
    await new Promise<void>((r) => { server.on('ready', r); server.run(); });

    const client = new Client({ server: '127.0.0.1', acctport: acctPort, secret: Buffer.from('testing'), dict, timeout: 2, retries: 1 });
    const req = client.createAcctPacket();
    req.addAttribute('User-Name', 'bob');
    req.addAttribute('Acct-Session-Id', 'sess-002');
    req.addAttribute('Acct-Status-Type', 'Interim-Update');
    req.addAttribute('Acct-Input-Octets', 1000);
    req.addAttribute('Acct-Output-Octets', 2000);
    req.addAttribute('Acct-Session-Time', 300);

    const reply = await client.sendPacket(req);
    assert.equal(reply.code, AccountingResponse);

    const rows = await db('radacct').where({ acctsessionid: 'sess-002' }).select('*');
    assert.equal(rows.length, 1);
    assert.equal(Number(rows[0].acctinputoctets), 1000);
    assert.equal(Number(rows[0].acctoutputoctets), 2000);
    assert.equal(rows[0].acctsessiontime, 300);
    assert.ok(rows[0].acctupdatetime);

    client.close();
    server.stop();
  });

  it('Stop updates radacct with stop time and cause', async () => {
    const acctPort = basePort + 2;
    class TestServer extends Server {
      constructor() {
        super({
          addresses: ['127.0.0.1'],
          acctport: acctPort,
          authEnabled: false,
          dedupTtl: false,
          rateLimit: false,
          dict,
          hosts: new Map([['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('testing'), 'test')]]),
        });
        this.handleAcctPacket = createDbAcct({ knex: db });
      }
    }

    // Pre-insert a session
    await db('radacct').insert({
      acctsessionid: 'sess-003', username: 'charlie', nasipaddress: '10.0.0.1',
      acctstarttime: new Date().toISOString(),
    });

    const server = new TestServer();
    await new Promise<void>((r) => { server.on('ready', r); server.run(); });

    const client = new Client({ server: '127.0.0.1', acctport: acctPort, secret: Buffer.from('testing'), dict, timeout: 2, retries: 1 });
    const req = client.createAcctPacket();
    req.addAttribute('User-Name', 'charlie');
    req.addAttribute('Acct-Session-Id', 'sess-003');
    req.addAttribute('Acct-Status-Type', 'Stop');
    req.addAttribute('Acct-Input-Octets', 5000);
    req.addAttribute('Acct-Output-Octets', 10000);
    req.addAttribute('Acct-Session-Time', 600);
    req.addAttribute('Acct-Terminate-Cause', 'User-Request');

    const reply = await client.sendPacket(req);
    assert.equal(reply.code, AccountingResponse);

    const rows = await db('radacct').where({ acctsessionid: 'sess-003' }).select('*');
    assert.equal(rows.length, 1);
    assert.ok(rows[0].acctstoptime);
    assert.equal(Number(rows[0].acctinputoctets), 5000);
    assert.equal(Number(rows[0].acctoutputoctets), 10000);
    assert.equal(rows[0].acctsessiontime, 600);
    assert.equal(rows[0].acctterminatecause, 'User-Request');

    client.close();
    server.stop();
  });
});

// ---- DatabaseServer integration ----

describe('DatabaseServer', () => {
  let db: Knex;
  const basePort = 19400 + Math.floor(Math.random() * 500);

  beforeEach(async () => {
    db = createTestDb();
    await createSchema(db);
  });

  afterEach(async () => {
    await db.destroy();
  });

  it('full auth + acct round-trip', async () => {
    // Seed user
    await db('radcheck').insert({
      username: 'testuser', attribute: 'Cleartext-Password', op: ':=', value: 'testpass',
    });
    await db('radreply').insert({
      username: 'testuser', attribute: 'Reply-Message', op: ':=', value: 'Welcome!',
    });

    const authPort = basePort;
    const acctPort = basePort + 1;

    const server = new DatabaseServer({
      addresses: ['127.0.0.1'],
      authport: authPort,
      acctport: acctPort,
      dedupTtl: false,
      rateLimit: false,
      dict,
      knex: db,
      hosts: new Map([['127.0.0.1', new RemoteHost('127.0.0.1', Buffer.from('testing'), 'test')]]),
    });

    await new Promise<void>((r) => { server.on('ready', r); server.run(); });

    const client = new Client({
      server: '127.0.0.1',
      authport: authPort,
      acctport: acctPort,
      secret: Buffer.from('testing'),
      dict,
      timeout: 2,
      retries: 1,
    });

    // Auth
    const authReq = client.createAuthPacket();
    authReq.addAttribute('User-Name', 'testuser');
    authReq.set('User-Password', [authReq.pwCrypt('testpass')]);
    const authReply = await client.sendPacket(authReq);
    assert.equal(authReply.code, AccessAccept);
    assert.equal(authReply.getAttribute('Reply-Message')[0], 'Welcome!');

    // Acct Start
    const acctStart = client.createAcctPacket();
    acctStart.addAttribute('User-Name', 'testuser');
    acctStart.addAttribute('Acct-Session-Id', 'int-001');
    acctStart.addAttribute('Acct-Status-Type', 'Start');
    const startReply = await client.sendPacket(acctStart);
    assert.equal(startReply.code, AccountingResponse);

    // Acct Stop
    const acctStop = client.createAcctPacket();
    acctStop.addAttribute('User-Name', 'testuser');
    acctStop.addAttribute('Acct-Session-Id', 'int-001');
    acctStop.addAttribute('Acct-Status-Type', 'Stop');
    acctStop.addAttribute('Acct-Session-Time', 120);
    acctStop.addAttribute('Acct-Input-Octets', 1024);
    acctStop.addAttribute('Acct-Output-Octets', 2048);
    acctStop.addAttribute('Acct-Terminate-Cause', 'User-Request');
    const stopReply = await client.sendPacket(acctStop);
    assert.equal(stopReply.code, AccountingResponse);

    // Verify DB state
    const acctRows = await db('radacct').where({ acctsessionid: 'int-001' }).select('*');
    assert.equal(acctRows.length, 1);
    assert.ok(acctRows[0].acctstoptime);
    assert.equal(acctRows[0].acctsessiontime, 120);

    client.close();
    server.stop();
  });
});
