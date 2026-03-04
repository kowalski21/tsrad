import { describe, it, beforeEach } from 'node:test';
import * as assert from 'node:assert/strict';
import { BiDict } from './bidict.js';

describe('BiDict', () => {
  let bd: BiDict<string, string>;

  beforeEach(() => {
    bd = new BiDict();
  });

  it('starts empty', () => {
    assert.equal(bd.length, 0);
  });

  it('tracks length', () => {
    assert.equal(bd.length, 0);
    bd.add('from', 'to');
    assert.equal(bd.length, 1);
    bd.delete('from');
    assert.equal(bd.length, 0);
  });

  it('forward access', () => {
    bd.add('shake', 'vanilla');
    bd.add('pie', 'custard');

    assert.equal(bd.hasForward('shake'), true);
    assert.equal(bd.getForward('shake'), 'vanilla');
    assert.equal(bd.hasForward('pie'), true);
    assert.equal(bd.getForward('pie'), 'custard');
    assert.equal(bd.hasForward('missing'), false);
    assert.throws(() => bd.getForward('missing'));
  });

  it('backward access', () => {
    bd.add('shake', 'vanilla');
    bd.add('pie', 'custard');

    assert.equal(bd.hasBackward('vanilla'), true);
    assert.equal(bd.getBackward('vanilla'), 'shake');
    assert.equal(bd.hasBackward('missing'), false);
    assert.throws(() => bd.getBackward('missing'));
  });

  it('get() is alias for getForward()', () => {
    bd.add('shake', 'vanilla');
    assert.equal(bd.get('shake'), 'vanilla');
    assert.throws(() => bd.get('missing'));
  });

  it('forward deletion', () => {
    bd.add('missing', 'present');
    bd.delete('missing');
    assert.equal(bd.hasForward('missing'), false);
    assert.equal(bd.hasBackward('present'), false);
    assert.equal(bd.length, 0);
  });

  it('backward deletion', () => {
    bd.add('missing', 'present');
    bd.delete('present');
    assert.equal(bd.hasForward('missing'), false);
    assert.equal(bd.hasBackward('present'), false);
    assert.equal(bd.length, 0);
  });

  it('works with number values', () => {
    const bd2 = new BiDict<string, number>();
    bd2.add('one', 1);
    bd2.add('two', 2);
    assert.equal(bd2.getForward('one'), 1);
    assert.equal(bd2.getBackward(1), 'one');
    assert.equal(bd2.getForward('two'), 2);
    assert.equal(bd2.getBackward(2), 'two');
  });
});
