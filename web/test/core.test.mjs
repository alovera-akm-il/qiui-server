import test from 'node:test';
import assert from 'node:assert/strict';
import { ServerClock, ago, deriveView, describeActivity, formatMinSec, splitDuration, timerRemaining } from '../core.js';

const H = 3600_000;

const state = (over = {}) => ({
  server_time_ms: 1_000_000,
  lock: 'locked',
  approval_expires_ms: null,
  timer: { kind: 'idle' },
  unread_messages: 0,
  queued_command: null,
  pod: null,
  ...over,
});

test('durations split into zero-padded parts', () => {
  assert.deepEqual(splitDuration(13 * 86400_000 + 51 * 60_000 + 12_000), { d: '13', h: '00', m: '51', s: '12' });
  assert.deepEqual(splitDuration(-5), { d: '00', h: '00', m: '00', s: '00' });
  assert.equal(formatMinSec(14 * 60_000 + 59_000), '14:59');
});

test('"ago" reads naturally', () => {
  assert.equal(ago(100_000, 95_000), 'just now');
  assert.equal(ago(10 * 60_000, 60_000), '9 min ago');
  assert.equal(ago(5 * H, 0), '5 h ago');
});

test('the countdown follows the server clock and ignores the phone clock being changed', () => {
  let mono = 0;
  let wall = 1_700_000_000_000;
  const clock = new ServerClock({ mono: () => mono, wall: () => wall });
  clock.sync(5_000_000);
  mono += 10_000;
  wall += 10_000;
  assert.equal(clock.now(), 5_010_000);

  // Someone sets the phone's clock back a day: the countdown does not move backwards.
  wall -= 86400_000;
  mono += 1_000;
  assert.equal(clock.now(), 5_011_000);
});

test('moving the wall clock forward can only finish a countdown early, which enables nothing by itself', () => {
  let mono = 0;
  let wall = 0;
  const clock = new ServerClock({ mono: () => mono, wall: () => wall });
  clock.sync(0);
  wall += 5 * H; // phone clock jumped forward, or the phone slept
  assert.equal(clock.now(), 5 * H);
});

test('restoring from storage carries the elapsed time forward', () => {
  let wall = 2_000_000;
  const clock = new ServerClock({ mono: () => 0, wall: () => wall });
  clock.restore(10_000_000, 1_990_000); // read 10 s ago
  assert.equal(clock.now(), 10_010_000);
  assert.equal(new ServerClock().now(), null, 'never synced: no time to show');
});

test('timer remaining time for each kind', () => {
  assert.equal(timerRemaining({ kind: 'running', ends_at_ms: 5000 }, 2000), 3000);
  assert.equal(timerRemaining({ kind: 'running', ends_at_ms: 5000 }, 9000), 0);
  assert.equal(timerRemaining({ kind: 'paused', remaining_ms: 7000 }, 999999), 7000);
  assert.equal(timerRemaining({ kind: 'ended' }, 1), 0);
  assert.equal(timerRemaining({ kind: 'idle' }, 1), null);
});

test('locked with no timer: the wearer can ask', () => {
  const v = deriveView(state(), { nowMs: 1_000_000, online: true });
  assert.deepEqual([v.title, v.primary.label, v.primary.action, v.primary.disabled], ['Locked', 'Request unlock', 'request', false]);
  assert.equal(v.timer, null);
});

test('a running timer closes requests and shows the countdown', () => {
  const s = state({ timer: { kind: 'running', ends_at_ms: 1_000_000 + 2 * H, remaining_ms: 2 * H } });
  const v = deriveView(s, { nowMs: 1_000_000, online: true });
  assert.equal(v.primary.disabled, true);
  assert.equal(v.primary.action, null, 'there is nothing to click');
  assert.equal(v.primary.label, 'Unlock requests closed');
  assert.deepEqual(v.timer.digits, { d: '00', h: '02', m: '00', s: '00' });
  assert.equal(v.timer.label, 'Running');
});

test('a paused timer also closes requests, with its own wording', () => {
  const v = deriveView(state({ timer: { kind: 'paused', remaining_ms: 6 * H } }), { nowMs: 1, online: true });
  assert.equal(v.primary.disabled, true);
  assert.match(v.primary.hint, /paused/);
  assert.equal(v.timer.label, 'Paused');
});

test('when the timer ends the request button returns, but nothing is unlocked', () => {
  const v = deriveView(state({ timer: { kind: 'ended' } }), { nowMs: 1, online: true });
  assert.deepEqual([v.primary.action, v.primary.disabled, v.lock], ['request', false, 'locked']);
  assert.match(v.primary.hint, /approval/);
});

test('a countdown that reaches zero while offline is marked unconfirmed', () => {
  const s = state({ timer: { kind: 'running', ends_at_ms: 500, remaining_ms: 500 } });
  const offline = deriveView(s, { nowMs: 900, online: false });
  assert.equal(offline.timer.unconfirmed, true);
  assert.equal(offline.timer.label, 'Ended · unconfirmed');
  assert.equal(offline.primary.action, 'request');
  assert.match(offline.primary.hint, /offline/i);

  // Online, the same reading is just the timer having ended; the server confirms on the next sync.
  const online = deriveView(s, { nowMs: 900, online: true });
  assert.equal(online.timer.unconfirmed, false);
});

test('a request that is waiting can be withdrawn', () => {
  const v = deriveView(state({ lock: 'requested' }), { nowMs: 1, online: true });
  assert.deepEqual([v.tone, v.primary.disabled, v.secondary.action], ['pending', true, 'cancel']);
});

test('once approved the button becomes Unlock, with the approval running down', () => {
  const v = deriveView(state({ lock: 'approved', approval_expires_ms: 1_000_000 + 899_000 }), { nowMs: 1_000_000, online: true });
  assert.deepEqual([v.tone, v.primary.label, v.primary.action], ['open', 'Unlock', 'unlock']);
  assert.equal(v.approvalMs, 899_000);
});

test('once unlocked the button becomes Lock', () => {
  const v = deriveView(state({ lock: 'unlocked' }), { nowMs: 1, online: true });
  assert.deepEqual([v.title, v.primary.label, v.primary.action], ['Unlocked', 'Lock', 'lock']);
});

test('a queued keyholder command is surfaced whatever the lock state', () => {
  for (const lock of ['locked', 'unlocked']) {
    const v = deriveView(state({ lock, queued_command: { command: 'lock', queued_ms: 1 } }), { nowMs: 1, online: true });
    assert.deepEqual(v.queued, { command: 'lock' });
  }
});

test('activity wording names who did what', () => {
  assert.equal(describeActivity({ kind: 'unlocked', by: 'wearer', via: 'phone' }), 'You unlocked the pod from this phone');
  assert.equal(describeActivity({ kind: 'locked', by: 'keyholder', via: 'server' }), 'Your keyholder locked the pod');
  assert.equal(describeActivity({ kind: 'timer_extended', by: 'keyholder' }), 'Time added to the timer by your keyholder');
  assert.equal(describeActivity({ kind: 'timer_extension_rolled', by: 'keyholder' }), 'Time added to the timer by your keyholder');
  assert.equal(describeActivity({ kind: 'something_new', by: 'system' }), 'something new');
});
