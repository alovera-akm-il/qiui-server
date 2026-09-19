// End-to-end check of the wearer's app: a real browser against the real server binary in demo mode.
// It also takes the screenshots used in docs/images.
//
//   cargo build
//   npm i playwright-core                    (anywhere; point PLAYWRIGHT_CORE at its index.mjs if not here)
//   CHROME=/path/to/chrome node scripts/e2e.mjs
//
// Environment: BIN (server binary, default target/debug/qiui-server), CHROME (browser executable),
// SHOTS_DIR (where screenshots go, default target/e2e-shots).
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const { chromium } = await import(process.env.PLAYWRIGHT_CORE || 'playwright-core');
const BIN = process.env.BIN || 'target/debug/qiui-server';
const SHOTS = process.env.SHOTS_DIR || 'target/e2e-shots';
mkdirSync(SHOTS, { recursive: true });

const PASSWORD = 'correct horse battery';
const freePort = () => new Promise((resolve, reject) => {
  const s = createServer();
  s.on('error', reject);
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});
const running = new Set();
// Servers are stopped however the script ends, so a failed check leaves nothing behind.
process.on('exit', () => running.forEach((stop) => stop()));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- a throwaway server ----------

async function startServer({ outOfRange = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'tether-e2e-'));
  const env = { ...process.env, QIUI_DATA_DIR: dir, QIUI_KEYHOLDER_PASSWORD: PASSWORD, QIUI_RECOVERY_PIN: '482913' };
  execFileSync(BIN, ['init'], { env, stdio: 'ignore' });
  const port = await freePort();
  const args = ['serve', '--simulate-pod', '--bind', `127.0.0.1:${port}`, ...(outOfRange ? ['--simulate-out-of-range'] : [])];
  const proc = spawn(BIN, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('server did not start')), 15000);
    proc.stdout.on('data', (d) => { if (String(d).includes('Listening')) { clearTimeout(t); resolve(); } });
    proc.on('exit', (c) => reject(new Error(`server exited with ${c}`)));
  });
  const base = `http://127.0.0.1:${port}`;
  const call = async (method, path, token, body) => {
    const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${JSON.stringify(j)}`);
    return j;
  };
  const kh = (await call('POST', '/api/keyholder/login', null, { password: PASSWORD })).token;
  const stop = () => { running.delete(stop); proc.removeAllListeners('exit'); proc.kill(); rmSync(dir, { recursive: true, force: true }); };
  running.add(stop);
  return {
    base,
    k: (method, path, body) => call(method, `/api/keyholder${path}`, kh, body),
    pairingCode: async () => (await call('POST', '/api/keyholder/pairing-code', kh, {})).code,
    stop,
  };
}

// ---------- browser ----------

const browser = await chromium.launch({ executablePath: process.env.CHROME, args: ['--no-sandbox'] });

const HIDE_NOTIFICATION_PROMPT = `Object.defineProperty(Notification, 'permission', { get: () => 'denied' });`;

// A Web Bluetooth stand-in whose "pod" answers a command 53xx with a reply starting xx.
const FAKE_BLUETOOTH = `(() => {
  const listeners = new Set();
  const notifyChar = { addEventListener: (_, f) => listeners.add(f), removeEventListener: (_, f) => listeners.delete(f), startNotifications: async () => {} };
  const writeChar = { properties: { writeWithoutResponse: true }, writeValueWithoutResponse: async (bytes) => {
    const r = new Uint8Array([bytes[1], 0xaa]);
    setTimeout(() => listeners.forEach((f) => f({ target: { value: new DataView(r.buffer) } })), 900);
  } };
  const device = { gatt: { connected: false, connect: async () => {
      await new Promise((r) => setTimeout(r, 700));
      device.gatt.connected = true;
      return { getPrimaryService: async () => ({ getCharacteristic: async (u) => (u.includes('fff1') ? writeChar : notifyChar) }) };
    }, disconnect: () => { device.gatt.connected = false; window.__disconnects = (window.__disconnects || 0) + 1; } } };
  Object.defineProperty(navigator, 'bluetooth', { value: { requestDevice: async () => device }, configurable: true });
})();`;
const NO_BLUETOOTH = `Object.defineProperty(navigator, 'bluetooth', { value: undefined, configurable: true });`;

async function newPage(init = [HIDE_NOTIFICATION_PROMPT]) {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, colorScheme: 'dark', locale: 'en-GB', timezoneId: 'Europe/London' });
  for (const script of init) await context.addInitScript(script);
  const page = await context.newPage();
  page.setDefaultTimeout(12000);
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => { if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) errors.push(m.text()); });
  return { context, page, errors };
}

const shot = (page, name) => page.screenshot({ path: join(SHOTS, `${name}.png`) });
// Exact match: a substring match would treat "Unlocked" as "Locked".
const title = (page, text) => page.locator('.title').filter({ hasText: new RegExp(`^${text}$`) }).waitFor();
// The main area only: the tab bar also has a button called "Lock".
const button = (page, text) => page.locator('main').getByRole('button', { name: text, exact: true });
const tab = (page, name) => page.locator('nav').getByRole('button', { name });
const step = (msg) => console.log(`  ✔ ${msg}`);

async function pair(page, server) {
  await page.goto(server.base);
  await page.locator('#pair-code').waitFor();
  return async () => {
    await page.fill('#pair-code', await server.pairingCode());
    await button(page, 'Pair').click();
    await title(page, 'Locked');
  };
}

// ---------- flow A: the pod is in the server's range ----------

console.log('Flow A: server in range');
{
  const server = await startServer();
  const { context, page, errors } = await newPage();
  const doPair = await pair(page, server);
  await shot(page, 'app-pair');
  step('the pairing screen loads');

  // A wrong code is refused with a message, not a crash.
  await page.fill('#pair-code', 'AAAA-AAAA');
  await button(page, 'Pair').click();
  await page.getByRole('alert').waitFor();
  step('a wrong pairing code is refused');

  await doPair();
  await page.getByText('Pod not checked yet').waitFor();
  assert.equal(await button(page, 'Request unlock').isEnabled(), true);
  await shot(page, 'app-locked');
  step('paired through the real screen; locked, and the wearer may ask');

  await page.getByRole('button', { name: 'Sync now' }).click();
  await page.getByText(/Pod checked/).waitFor();
  step('Sync reaches the (simulated) pod and says so');

  // The keyholder rolls a random timer: the wearer sees a countdown and a closed door.
  await server.k('POST', '/timer/roll', { min_secs: 3 * 86400, max_secs: 5 * 86400 });
  await page.getByRole('button', { name: 'Sync now' }).click();
  await page.getByText('Unlock requests closed').waitFor();
  assert.equal(await page.getByText('Unlock requests closed').isEnabled(), false);
  const days = Number(await page.locator('[data-live="d"]').innerText());
  assert.ok(days >= 2 && days <= 5, `countdown days ${days}`);
  const wearerHtml = await page.content();
  assert.ok(!wearerHtml.includes('rolled_secs'), 'the roll must not reach the wearer');
  await shot(page, 'app-timer-running');
  step('a rolled timer shows a countdown and closes requests');

  await server.k('POST', '/timer/pause');
  await page.getByRole('button', { name: 'Sync now' }).click();
  await page.getByText('Paused', { exact: true }).waitFor();
  await page.getByText(/timer is paused/).waitFor();
  await shot(page, 'app-timer-paused');
  step('a paused timer still blocks, with its own wording');

  await server.k('POST', '/timer/clear');
  await page.getByRole('button', { name: 'Sync now' }).click();
  await button(page, 'Request unlock').waitFor();
  await button(page, 'Request unlock').click();
  await title(page, 'Request sent');
  assert.equal(await button(page, 'Waiting for approval').isDisabled(), true);
  await shot(page, 'app-request-sent');
  step('requesting works, and the button waits');

  await server.k('POST', '/approve', { ttl_minutes: 15 });
  await page.reload();
  await title(page, 'Approved');
  await button(page, 'Unlock').waitFor();
  await page.getByText(/Approval expires in/).waitFor();
  await shot(page, 'app-approved');
  step('after approval the button becomes Unlock');

  await button(page, 'Unlock').click();
  await title(page, 'Unlocked');
  await button(page, 'Lock').waitFor();
  await shot(page, 'app-unlocked');
  const state = await server.k('GET', '/state');
  assert.equal(state.lock, 'unlocked');
  step('Unlock went through the server, and the button became Lock');

  await button(page, 'Lock').click();
  await title(page, 'Locked');
  await button(page, 'Request unlock').waitFor();
  step('Lock returns to Locked, where the cycle starts again');

  await server.k('POST', '/messages', { body: 'Good work today. Back at six.' });
  await tab(page, /Messages/).click();
  await page.getByText('Good work today. Back at six.').waitFor();
  await shot(page, 'app-messages');
  step('a keyholder message appears');

  await tab(page, /Activity/).click();
  await page.getByText('You unlocked the pod').waitFor();
  const activity = await page.locator('.msgs').innerText();
  assert.ok(!/secs|rolled_secs|\b(3|4|5) days\b/i.test(activity), 'activity must not reveal timer details');
  await shot(page, 'app-activity');
  step('the activity feed tells the story without leaking internals');

  await tab(page, 'Lock').click();
  await server.k('POST', '/queue', { command: 'lock' });
  await page.getByRole('button', { name: 'Sync now' }).click();
  await page.getByText('Your keyholder queued: Lock').waitFor();
  await shot(page, 'app-queued');
  await server.k('POST', '/queue/cancel');
  step('a queued keyholder command shows as a card');

  // A timer that finishes only reopens requests; it unlocks nothing.
  await server.k('POST', '/timer', { duration_secs: 3 });
  await page.getByRole('button', { name: 'Sync now' }).click();
  await page.getByText('Unlock requests closed').waitFor();
  await sleep(3500);
  await page.getByRole('button', { name: 'Sync now' }).click();
  await page.getByText('Ended', { exact: true }).waitFor();
  await button(page, 'Request unlock').waitFor();
  assert.equal((await server.k('GET', '/state')).lock, 'locked');
  await shot(page, 'app-timer-ended');
  step('when the timer ends the request button returns, and the lock stays locked');

  // Offline: the countdown keeps running from the last reading and is honest about it.
  await page.getByRole('button', { name: 'Sync now' }).click();
  await server.k('POST', '/timer', { duration_secs: 4 });
  await page.getByRole('button', { name: 'Sync now' }).click();
  await page.getByText('Unlock requests closed').waitFor();
  await context.setOffline(true);
  await page.getByText(/^Offline/).waitFor();
  await page.getByText('Ended · unconfirmed').waitFor({ timeout: 10000 });
  await button(page, 'Request unlock').waitFor();
  await shot(page, 'app-offline');
  await button(page, 'Request unlock').click();
  await page.getByText(/sent as soon as you are back online/).waitFor();
  step('offline: the countdown ends as "unconfirmed" and a request is held');

  await context.setOffline(false);
  await title(page, 'Request sent');
  const after = await server.k('GET', '/state');
  assert.equal(after.lock, 'requested');
  step('back online: the held request is sent, and the server accepts it because the timer really ended');

  assert.deepEqual(errors, [], `browser errors: ${errors.join('; ')}`);
  await context.close();
  server.stop();
}

// ---------- flow B: the pod is out of the server's range; the phone relays Bluetooth ----------

console.log('Flow B: out of range, phone relay');
{
  const server = await startServer({ outOfRange: true });
  const { context, page, errors } = await newPage([HIDE_NOTIFICATION_PROMPT, FAKE_BLUETOOTH]);
  await (await pair(page, server))();
  await button(page, 'Request unlock').click();
  await title(page, 'Request sent');
  await server.k('POST', '/approve', { ttl_minutes: 15 });
  await page.reload();
  await button(page, 'Unlock').click();
  await page.getByText("The server can't reach the lock").waitFor();
  await shot(page, 'app-relay-offer');
  step("out of range: the app offers this phone's Bluetooth");

  await button(page, 'Connect over Bluetooth').click();
  await page.getByText('Keep this screen open').waitFor();
  await sleep(1300);
  await shot(page, 'app-relay-progress');
  await title(page, 'Unlocked');
  const state = await server.k('GET', '/state');
  assert.equal(state.lock, 'unlocked');
  assert.equal(state.pod.via, 'phone');
  const audit = await server.k('GET', '/audit?limit=50');
  const kinds = audit.entries.map((e) => e.kind);
  assert.ok(kinds.includes('relay_unlock_issued'), 'handing unlock bytes to the phone must be logged');
  const unlocked = audit.entries.find((e) => e.kind === 'unlocked');
  assert.equal(unlocked.detail.via, 'phone');
  assert.ok((await page.evaluate(() => window.__disconnects || 0)) >= 1, 'the phone must disconnect from the pod when done');
  step('the relay ran end to end in the browser, was logged, and the phone disconnected');

  // A keyholder-queued lock is applied from the phone.
  await server.k('POST', '/queue', { command: 'lock' });
  await page.getByRole('button', { name: 'Sync now' }).click();
  await page.getByText('Your keyholder queued: Lock').waitFor();
  await button(page, 'Connect and apply').click();
  await title(page, 'Locked');
  const queued = await server.k('GET', '/state');
  assert.equal(queued.lock, 'locked');
  assert.equal(queued.queued_command, null);
  step('a queued keyholder command is applied from the phone');
  assert.deepEqual(errors, [], `browser errors: ${errors.join('; ')}`);
  await context.close();
  server.stop();
}

// ---------- flow C: a browser without Bluetooth (iPhone) ----------

console.log('Flow C: no Web Bluetooth');
{
  const server = await startServer({ outOfRange: true });
  const { context, page } = await newPage([HIDE_NOTIFICATION_PROMPT, NO_BLUETOOTH]);
  await (await pair(page, server))();
  await button(page, 'Request unlock').click();
  await title(page, 'Request sent');
  await server.k('POST', '/approve', { ttl_minutes: 15 });
  await page.reload();
  await button(page, 'Unlock').click();
  await page.getByText("This browser can't use Bluetooth").waitFor();
  await shot(page, 'app-no-bluetooth');
  step('without Web Bluetooth the app says so plainly');
  await context.close();
  server.stop();
}

// ---------- flow D: notifications card ----------

console.log('Flow D: notifications offer');
{
  const server = await startServer();
  const { context, page } = await newPage([]);
  await (await pair(page, server))();
  await page.getByRole('button', { name: 'Turn on notifications' }).waitFor();
  await shot(page, 'app-notifications');
  step('the app offers notifications when the server has them set up');
  await context.close();
  server.stop();
}

await browser.close();
console.log('\nAll end-to-end checks passed.');
