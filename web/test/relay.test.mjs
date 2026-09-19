import test from 'node:test';
import assert from 'node:assert/strict';
import { WebBluetoothLink, bluetoothSupported, fromHex, runRelay, toHex } from '../relay.js';

/** A stand-in for the server and the pod link that records what happened, in order. */
function rig({ replies = [{ done: false, cmd: 'UNLOCK' }, { done: true, lock: 'unlocked' }], failAt = null } = {}) {
  const log = [];
  let n = 0;
  const api = async (path, body) => {
    log.push(`api:${path.split('/').pop()}`);
    if (failAt === path) throw new Error('refused');
    if (path.endsWith('/start')) return { session_id: 'S1', cmd: 'TOKEN' };
    return replies[n++];
  };
  const link = {
    async connect() { log.push('connect'); },
    async exchange(hex) { log.push(`write:${hex}`); return `reply-to-${hex}`; },
    async disconnect() { log.push('disconnect'); },
  };
  return { api, link, log };
}

test('the phone connects first, then the server drives: token, then the command', async () => {
  const { api, link, log } = rig();
  const steps = [];
  const result = await runRelay('unlock', api, link, (s) => steps.push(s));
  assert.equal(result.lock, 'unlocked');
  assert.deepEqual(log, ['connect', 'api:start', 'write:TOKEN', 'api:reply', 'write:UNLOCK', 'api:reply', 'disconnect']);
  assert.deepEqual(steps, ['connecting', 'handshake', 'command', 'done']);
});

test('what the pod said is what gets sent back to the server', async () => {
  const seen = [];
  const { link } = rig();
  const api = async (path, body) => {
    if (path.endsWith('/start')) return { session_id: 'S1', cmd: 'TOKEN' };
    seen.push(body);
    return seen.length === 1 ? { done: false, cmd: 'LOCK' } : { done: true };
  };
  await runRelay('lock', api, link);
  assert.deepEqual(seen, [
    { session_id: 'S1', hex: 'reply-to-TOKEN' },
    { session_id: 'S1', hex: 'reply-to-LOCK' },
  ]);
});

test('the phone always disconnects: on success, refusal, timeout and a runaway server', async () => {
  // Server refuses to start.
  let r = rig({ failAt: '/api/wearer/relay/start' });
  await assert.rejects(runRelay('unlock', r.api, r.link), /refused/);
  assert.equal(r.log.filter((l) => l === 'disconnect').length, 1);

  // Server fails mid-way.
  r = rig({ failAt: '/api/wearer/relay/reply' });
  await assert.rejects(runRelay('unlock', r.api, r.link), /refused/);
  assert.equal(r.log.at(-1), 'disconnect');

  // The pod never answers.
  r = rig();
  r.link.exchange = async () => { throw new Error('The lock did not answer.'); };
  await assert.rejects(runRelay('unlock', r.api, r.link), /did not answer/);
  assert.equal(r.log.at(-1), 'disconnect');

  // The server keeps asking for more: give up rather than loop.
  r = rig({ replies: Array(10).fill({ done: false, cmd: 'MORE' }) });
  await assert.rejects(runRelay('unlock', r.api, r.link), /more steps/);
  assert.equal(r.log.at(-1), 'disconnect');
});

test('a failed disconnect does not hide the real result', async () => {
  const r = rig();
  r.link.disconnect = async () => { throw new Error('already gone'); };
  const result = await runRelay('unlock', r.api, r.link);
  assert.equal(result.done, true);
});

test('hex conversion round-trips', () => {
  assert.equal(toHex(fromHex('00ff7A')), '00ff7a');
  assert.deepEqual([...fromHex('0aff')], [10, 255]);
});

test('Bluetooth support needs the API and a secure page', () => {
  assert.equal(bluetoothSupported({ bluetooth: {} }, true), true);
  assert.equal(bluetoothSupported({ bluetooth: {} }, false), false);
  assert.equal(bluetoothSupported({}, true), false, 'iPhone browsers have no Web Bluetooth');
});

/** A minimal Web Bluetooth device whose pod echoes "ack:<command>" as a notification. */
function fakeBluetooth({ failFirstConnect = false } = {}) {
  const listeners = new Set();
  let connects = 0;
  const notifyChar = {
    addEventListener: (_, fn) => listeners.add(fn),
    removeEventListener: (_, fn) => listeners.delete(fn),
    startNotifications: async () => {},
  };
  const writeChar = {
    properties: { writeWithoutResponse: true },
    writeValueWithoutResponse: async (bytes) => {
      const reply = new TextEncoder().encode(`ack:${toHex(bytes)}`);
      queueMicrotask(() => listeners.forEach((fn) => fn({ target: { value: reply } })));
    },
  };
  const device = {
    gatt: {
      connected: false,
      connect: async () => {
        connects += 1;
        if (failFirstConnect && connects === 1) throw new Error('dropped');
        device.gatt.connected = true;
        return { getPrimaryService: async () => ({ getCharacteristic: async (u) => (u.includes('fff1') ? writeChar : notifyChar) }) };
      },
      disconnect: () => { device.gatt.connected = false; },
    },
  };
  return { nav: { bluetooth: { requestDevice: async () => device } }, listeners, device, connects: () => connects };
}

test('the Web Bluetooth link writes a command and returns the pod reply', async () => {
  const { nav, device } = fakeBluetooth();
  const link = new WebBluetoothLink(nav);
  await link.connect();
  const reply = await link.exchange('0a0b');
  assert.equal(new TextDecoder().decode(fromHex(toHex(new TextEncoder().encode(`ack:0a0b`)))), 'ack:0a0b');
  assert.equal(reply, toHex(new TextEncoder().encode('ack:0a0b')));
  await link.disconnect();
  assert.equal(device.gatt.connected, false, 'disconnect really disconnects');
});

test('a first connection that drops is retried once, without doubling the reply listener', async () => {
  const { nav, listeners, connects } = fakeBluetooth({ failFirstConnect: true });
  const link = new WebBluetoothLink(nav);
  await link.connect();
  assert.equal(connects(), 2);
  assert.equal(listeners.size, 1);
  // A reconnect must not stack another listener either.
  await link.open();
  assert.equal(listeners.size, 1);
  await link.disconnect();
  assert.equal(listeners.size, 0);
});
