/**
 * db.ts — Database integration for RADIUS auth/acct
 *
 * FreeRADIUS rlm_sql compatible schema and query helpers.
 * Uses knex for database abstraction.
 */

import type { Knex } from 'knex';
import {
  Server, RemoteHost,
  type ServerOptions, type RadiusPacket,
} from './server.js';
import {
  AccessAccept, AccessReject, AccountingResponse,
} from './packet.js';
import type { Logger } from './logger.js';

// ---- Types (FreeRADIUS rlm_sql compatible) ----

export interface CheckRow {
  id: number;
  username: string;
  attribute: string;
  op: string;
  value: string;
}

export interface ReplyRow {
  id: number;
  username: string;
  attribute: string;
  op: string;
  value: string;
}

export interface UserGroupRow {
  username: string;
  groupname: string;
  priority: number;
}

export interface GroupCheckRow {
  id: number;
  groupname: string;
  attribute: string;
  op: string;
  value: string;
}

export interface GroupReplyRow {
  id: number;
  groupname: string;
  attribute: string;
  op: string;
  value: string;
}

export interface AcctRow {
  radacctid: number;
  acctsessionid: string;
  acctuniqueid: string;
  username: string;
  nasipaddress: string;
  nasportid: string;
  nasporttype: string;
  acctstarttime: string | null;
  acctupdatetime: string | null;
  acctstoptime: string | null;
  acctsessiontime: number;
  acctauthentic: string;
  connectinfo_start: string;
  connectinfo_stop: string;
  acctinputoctets: number;
  acctoutputoctets: number;
  calledstationid: string;
  callingstationid: string;
  acctterminatecause: string;
  servicetype: string;
  framedprotocol: string;
  framedipaddress: string;
}

export interface NasRow {
  id: number;
  nasname: string;
  shortname: string;
  type: string;
  ports: number;
  secret: string;
  server: string;
  community: string;
  description: string;
}

// ---- Schema ----

export async function createSchema(knex: Knex): Promise<void> {
  if (!(await knex.schema.hasTable('radcheck'))) {
    await knex.schema.createTable('radcheck', (t) => {
      t.increments('id');
      t.string('username').notNullable().defaultTo('');
      t.string('attribute').notNullable().defaultTo('');
      t.string('op', 2).notNullable().defaultTo(':=');
      t.string('value').notNullable().defaultTo('');
      t.index('username');
    });
  }

  if (!(await knex.schema.hasTable('radreply'))) {
    await knex.schema.createTable('radreply', (t) => {
      t.increments('id');
      t.string('username').notNullable().defaultTo('');
      t.string('attribute').notNullable().defaultTo('');
      t.string('op', 2).notNullable().defaultTo(':=');
      t.string('value').notNullable().defaultTo('');
      t.index('username');
    });
  }

  if (!(await knex.schema.hasTable('radusergroup'))) {
    await knex.schema.createTable('radusergroup', (t) => {
      t.string('username').notNullable().defaultTo('');
      t.string('groupname').notNullable().defaultTo('');
      t.integer('priority').notNullable().defaultTo(1);
      t.index('username');
    });
  }

  if (!(await knex.schema.hasTable('radgroupcheck'))) {
    await knex.schema.createTable('radgroupcheck', (t) => {
      t.increments('id');
      t.string('groupname').notNullable().defaultTo('');
      t.string('attribute').notNullable().defaultTo('');
      t.string('op', 2).notNullable().defaultTo(':=');
      t.string('value').notNullable().defaultTo('');
      t.index('groupname');
    });
  }

  if (!(await knex.schema.hasTable('radgroupreply'))) {
    await knex.schema.createTable('radgroupreply', (t) => {
      t.increments('id');
      t.string('groupname').notNullable().defaultTo('');
      t.string('attribute').notNullable().defaultTo('');
      t.string('op', 2).notNullable().defaultTo(':=');
      t.string('value').notNullable().defaultTo('');
      t.index('groupname');
    });
  }

  if (!(await knex.schema.hasTable('radacct'))) {
    await knex.schema.createTable('radacct', (t) => {
      t.increments('radacctid');
      t.string('acctsessionid').notNullable().defaultTo('');
      t.string('acctuniqueid').notNullable().defaultTo('');
      t.string('username').notNullable().defaultTo('');
      t.string('nasipaddress').notNullable().defaultTo('');
      t.string('nasportid').notNullable().defaultTo('');
      t.string('nasporttype').notNullable().defaultTo('');
      t.string('acctstarttime').nullable();
      t.string('acctupdatetime').nullable();
      t.string('acctstoptime').nullable();
      t.integer('acctsessiontime').notNullable().defaultTo(0);
      t.string('acctauthentic').notNullable().defaultTo('');
      t.string('connectinfo_start').notNullable().defaultTo('');
      t.string('connectinfo_stop').notNullable().defaultTo('');
      t.bigInteger('acctinputoctets').notNullable().defaultTo(0);
      t.bigInteger('acctoutputoctets').notNullable().defaultTo(0);
      t.string('calledstationid').notNullable().defaultTo('');
      t.string('callingstationid').notNullable().defaultTo('');
      t.string('acctterminatecause').notNullable().defaultTo('');
      t.string('servicetype').notNullable().defaultTo('');
      t.string('framedprotocol').notNullable().defaultTo('');
      t.string('framedipaddress').notNullable().defaultTo('');
      t.index('acctsessionid');
      t.index('username');
    });
  }

  if (!(await knex.schema.hasTable('nas'))) {
    await knex.schema.createTable('nas', (t) => {
      t.increments('id');
      t.string('nasname').notNullable();
      t.string('shortname').notNullable().defaultTo('');
      t.string('type').notNullable().defaultTo('other');
      t.integer('ports').notNullable().defaultTo(0);
      t.string('secret').notNullable().defaultTo('');
      t.string('server').notNullable().defaultTo('');
      t.string('community').notNullable().defaultTo('');
      t.string('description').notNullable().defaultTo('');
    });
  }
}

export async function dropSchema(knex: Knex): Promise<void> {
  for (const table of ['radcheck', 'radreply', 'radusergroup', 'radgroupcheck', 'radgroupreply', 'radacct', 'nas']) {
    if (await knex.schema.hasTable(table)) {
      await knex.schema.dropTable(table);
    }
  }
}

// ---- Query helpers ----

export async function findUser(db: Knex, username: string): Promise<CheckRow[]> {
  return db('radcheck').where({ username }).select('*');
}

export async function findUserReply(db: Knex, username: string): Promise<ReplyRow[]> {
  return db('radreply').where({ username }).select('*');
}

export async function findUserGroups(db: Knex, username: string): Promise<UserGroupRow[]> {
  return db('radusergroup').where({ username }).orderBy('priority', 'asc').select('*');
}

export async function findGroupCheck(db: Knex, groupname: string): Promise<GroupCheckRow[]> {
  return db('radgroupcheck').where({ groupname }).select('*');
}

export async function findGroupReply(db: Knex, groupname: string): Promise<GroupReplyRow[]> {
  return db('radgroupreply').where({ groupname }).select('*');
}

/** Seed a user using the standard rlm_sql tables. Useful for local setup/tests. */
export async function seedUser(
  db: Knex,
  username: string,
  password: string,
  options?: {
    checks?: Record<string, string | number>;
    replies?: Record<string, string | number>;
  },
): Promise<void> {
  await db('radcheck').insert({
    username,
    attribute: 'Cleartext-Password',
    op: ':=',
    value: password,
  });
  for (const [attribute, value] of Object.entries(options?.checks ?? {})) {
    await db('radcheck').insert({ username, attribute, op: ':=', value: String(value) });
  }
  for (const [attribute, value] of Object.entries(options?.replies ?? {})) {
    await db('radreply').insert({ username, attribute, op: ':=', value: String(value) });
  }
}

// ---- Operator evaluation ----

export function evaluateOp(op: string, requestValue: string, checkValue: string): boolean {
  switch (op) {
    case ':=':
    case '==':
      return requestValue === checkValue;
    case '!=':
      return requestValue !== checkValue;
    case '>=':
      return Number(requestValue) >= Number(checkValue);
    case '>':
      return Number(requestValue) > Number(checkValue);
    case '<=':
      return Number(requestValue) <= Number(checkValue);
    case '<':
      return Number(requestValue) < Number(checkValue);
    case '=~':
      return new RegExp(checkValue).test(requestValue);
    case '!~':
      return !new RegExp(checkValue).test(requestValue);
    case '+=':
      return true; // += adds to reply, always passes as check
    default:
      return false;
  }
}

// ---- Handler factories ----

export interface DbAuthOptions {
  knex: Knex;
  logger?: Logger;
  groups?: boolean;
  verifyPassword?: (pkt: RadiusPacket, password: string) => boolean;
}

export interface DbAcctOptions {
  knex: Knex;
  logger?: Logger;
}

export function createDbAuth(opts: DbAuthOptions): (this: Server, pkt: RadiusPacket) => Promise<void> {
  const { knex: db, logger, groups = true } = opts;

  return async function dbAuthHandler(this: Server, pkt: RadiusPacket): Promise<void> {
    const username = pkt.getAttribute('User-Name')[0] as string;

    logger?.debug('Auth request', { username });

    // Query radcheck for this user
    const checks = await findUser(db, username);
    if (checks.length === 0) {
      logger?.info('User not found, rejecting', { username });
      const reply = this.createReplyPacket(pkt, { code: AccessReject });
      this.sendReply(reply);
      return;
    }

    // Find and verify password
    const pwRow = checks.find(
      (r) => r.attribute === 'Cleartext-Password' && (r.op === ':=' || r.op === '=='),
    );

    if (pwRow) {
      let verified = false;

      if (opts.verifyPassword) {
        verified = opts.verifyPassword(pkt, pwRow.value);
      } else if (pkt.has('CHAP-Password')) {
        verified = pkt.verifyChapPasswd(pwRow.value);
      } else {
        // PAP: get raw encrypted buffer and decrypt
        const pwBufs = pkt.get('User-Password') as Buffer[] | undefined;
        if (pwBufs && pwBufs.length > 0) {
          const cleartext = pkt.pwDecrypt(pwBufs[0]);
          verified = cleartext === pwRow.value;
        }
      }

      if (!verified) {
        logger?.info('Password mismatch, rejecting', { username });
        const reply = this.createReplyPacket(pkt, { code: AccessReject });
        this.sendReply(reply);
        return;
      }
    }

    // Evaluate remaining check attributes (non-password)
    const otherChecks = checks.filter((r) => r.attribute !== 'Cleartext-Password');
    for (const check of otherChecks) {
      let reqValue = '';
      try {
        reqValue = String(pkt.getAttribute(check.attribute)[0]);
      } catch {
        // attribute not in packet
      }
      if (!evaluateOp(check.op, reqValue, check.value)) {
        logger?.info('Check attribute failed', { username, attribute: check.attribute, op: check.op });
        const reply = this.createReplyPacket(pkt, { code: AccessReject });
        this.sendReply(reply);
        return;
      }
    }

    // Collect reply attributes from radreply
    const replyAttrs = await findUserReply(db, username);

    // Collect group reply attributes
    const allReplyAttrs: Array<{ attribute: string; value: string }> = [...replyAttrs];

    if (groups) {
      const userGroups = await findUserGroups(db, username);
      for (const group of userGroups) {
        const groupChecks = await findGroupCheck(db, group.groupname);
        let groupPass = true;
        for (const check of groupChecks) {
          let reqValue = '';
          try {
            reqValue = String(pkt.getAttribute(check.attribute)[0]);
          } catch {
            // attribute not in packet
          }
          if (!evaluateOp(check.op, reqValue, check.value)) {
            groupPass = false;
            break;
          }
        }
        if (groupPass) {
          const gReply = await findGroupReply(db, group.groupname);
          allReplyAttrs.push(...gReply);
        }
      }
    }

    // Build and send Access-Accept
    logger?.info('Auth accept', { username });
    const reply = this.createReplyPacket(pkt, { code: AccessAccept });
    for (const attr of allReplyAttrs) {
      try {
        reply.addAttribute(attr.attribute, attr.value);
      } catch {
        logger?.warn('Could not add reply attribute', { attribute: attr.attribute, value: attr.value });
      }
    }
    this.sendReply(reply);
  };
}

export function createDbAcct(opts: DbAcctOptions): (this: Server, pkt: RadiusPacket) => Promise<void> {
  const { knex: db, logger } = opts;

  return async function dbAcctHandler(this: Server, pkt: RadiusPacket): Promise<void> {
    const statusType = pkt.getAttribute('Acct-Status-Type')[0];
    const sessionId = pkt.getAttribute('Acct-Session-Id')[0] as string;
    const username = pkt.getAttribute('User-Name')[0] as string;

    const getAttr = (name: string): string => {
      try { return String(pkt.getAttribute(name)[0]); } catch { return ''; }
    };
    const getAttrInt = (name: string): number => {
      try { return Number(pkt.getAttribute(name)[0]); } catch { return 0; }
    };

    // statusType may be a named string ("Start") or a number (1),
    // depending on whether the dictionary has VALUE mappings.
    const isStart = statusType === 'Start' || statusType === 1;
    const isInterim = statusType === 'Interim-Update' || statusType === 3;
    const isStop = statusType === 'Stop' || statusType === 2;

    logger?.debug('Acct request', { username, statusType: String(statusType), sessionId });

    if (isStart) {
      await db('radacct').insert({
        acctsessionid: sessionId,
        acctuniqueid: sessionId,
        username,
        nasipaddress: getAttr('NAS-IP-Address'),
        nasportid: getAttr('NAS-Port-Id'),
        nasporttype: '',
        acctstarttime: new Date().toISOString(),
        acctupdatetime: new Date().toISOString(),
        acctsessiontime: 0,
        acctauthentic: '',
        connectinfo_start: '',
        connectinfo_stop: '',
        acctinputoctets: 0,
        acctoutputoctets: 0,
        calledstationid: getAttr('Called-Station-Id'),
        callingstationid: getAttr('Calling-Station-Id'),
        acctterminatecause: '',
        servicetype: getAttr('Service-Type'),
        framedprotocol: getAttr('Framed-Protocol'),
        framedipaddress: getAttr('Framed-IP-Address'),
      });
    } else if (isInterim) {
      await db('radacct')
        .where({ acctsessionid: sessionId, username })
        .update({
          acctupdatetime: new Date().toISOString(),
          acctinputoctets: getAttrInt('Acct-Input-Octets'),
          acctoutputoctets: getAttrInt('Acct-Output-Octets'),
          acctsessiontime: getAttrInt('Acct-Session-Time'),
        });
    } else if (isStop) {
      await db('radacct')
        .where({ acctsessionid: sessionId, username })
        .update({
          acctstoptime: new Date().toISOString(),
          acctupdatetime: new Date().toISOString(),
          acctinputoctets: getAttrInt('Acct-Input-Octets'),
          acctoutputoctets: getAttrInt('Acct-Output-Octets'),
          acctsessiontime: getAttrInt('Acct-Session-Time'),
          acctterminatecause: getAttr('Acct-Terminate-Cause'),
        });
    }

    // Always send Accounting-Response
    const reply = this.createReplyPacket(pkt, { code: AccountingResponse });
    this.sendReply(reply);
  };
}

// ---- Convenience class ----

export interface DatabaseServerOptions extends ServerOptions {
  knex: Knex;
  groups?: boolean;
}

export class DatabaseServer extends Server {
  private db: Knex;

  constructor(opts: DatabaseServerOptions) {
    super(opts);
    this.db = opts.knex;

    this.handleAuthPacket = createDbAuth({
      knex: opts.knex,
      logger: opts.logger,
      groups: opts.groups ?? true,
    });

    this.handleAcctPacket = createDbAcct({
      knex: opts.knex,
      logger: opts.logger,
    });
  }

  async initSchema(): Promise<void> {
    await createSchema(this.db);
  }

  async destroyDb(): Promise<void> {
    await this.db.destroy();
  }
}
