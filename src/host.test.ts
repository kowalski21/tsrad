import { describe, it, beforeEach } from 'node:test';
import * as assert from 'node:assert/strict';
import { Host } from './host.js';
import { Packet, AuthPacket, AcctPacket, CoAPacket } from './packet.js';
import { Dictionary } from './dictionary.js';

describe('Host - construction', () => {
  it('default ports', () => {
    const host = new Host();
    assert.equal(host.authport, 1812);
    assert.equal(host.acctport, 1813);
    assert.equal(host.coaport, 3799);
    assert.ok(host.dict instanceof Dictionary);
  });

  it('custom ports', () => {
    const host = new Host({ authport: 123, acctport: 456, coaport: 789 });
    assert.equal(host.authport, 123);
    assert.equal(host.acctport, 456);
    assert.equal(host.coaport, 789);
  });

  it('custom dictionary', () => {
    const dict = new Dictionary();
    const host = new Host({ dict });
    assert.equal(host.dict, dict);
  });
});

describe('Host - packet creation', () => {
  let host: Host;

  beforeEach(() => {
    host = new Host();
  });

  it('createPacket', () => {
    const pkt = host.createPacket({ id: 15 });
    assert.ok(pkt instanceof Packet);
    assert.equal(pkt.dict, host.dict);
    assert.equal(pkt.id, 15);
  });

  it('createAuthPacket', () => {
    const pkt = host.createAuthPacket({ id: 15 });
    assert.ok(pkt instanceof AuthPacket);
    assert.equal(pkt.dict, host.dict);
    assert.equal(pkt.id, 15);
  });

  it('createAcctPacket', () => {
    const pkt = host.createAcctPacket({ id: 15 });
    assert.ok(pkt instanceof AcctPacket);
    assert.equal(pkt.dict, host.dict);
    assert.equal(pkt.id, 15);
  });

  it('createCoAPacket', () => {
    const pkt = host.createCoAPacket({ id: 15 });
    assert.ok(pkt instanceof CoAPacket);
    assert.equal(pkt.dict, host.dict);
    assert.equal(pkt.id, 15);
  });
});
