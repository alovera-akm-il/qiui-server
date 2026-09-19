// The wearer's app. All the rules live on the server: this only shows what the
// server says and asks it for things. Anything that decides what a button does
// is in core.js, where it is tested.
import { RELAY_STEPS, ServerClock, ago, deriveView, describeActivity, formatMinSec } from './core.js';
import { WebBluetoothLink, bluetoothSupported, runRelay } from './relay.js';

const KEY_TOKEN = 'tether.token';
const KEY_STATE = 'tether.state';
const KEY_PENDING = 'tether.pendingRequest';
const POLL_MS = 20_000;

const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
  del(k) { try { localStorage.removeItem(k); } catch { /* private mode */ } },
};

const clock = new ServerClock();
const app = {
  token: store.get(KEY_TOKEN),
  state: null,
  syncedAt: null,      // wall-clock time of the last reading from the server
  tab: 'home',
  online: navigator.onLine !== false,
  syncing: false,
  busy: null,          // name of the action in flight
  notice: null,        // { tone: 'error' | 'info', text }
  needRelay: null,     // { intent } — the server could not reach the pod; offer the phone's Bluetooth
  relay: null,         // { intent, step, error } while a phone-relayed session runs
  messages: null,
  activity: null,
  push: { supported: 'serviceWorker' in navigator && 'PushManager' in window, on: false, available: null },
  bluetooth: bluetoothSupported(),
};

const root = document.getElementById('app');

// ---------- helpers ----------

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const fmtTime = (ms) => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const fmtDay = (ms) => new Date(ms).toLocaleString([], { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });

const ICON = {
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
  open: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 7.6-1.7"/></svg>',
  hourglass: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M7 4h10M7 20h10M8 4c0 5 8 5 8 8s-8 3-8 8M16 4c0 5-8 5-8 8"/></svg>',
  chat: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M4 5h16v11H10l-4 4v-4H4z"/></svg>',
  list: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M8 7h12M8 12h12M8 17h12M4 7h.01M4 12h.01M4 17h.01"/></svg>',
  sync: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 11a8 8 0 0 0-14-4L4 9M4 4v5h5M4 13a8 8 0 0 0 14 4l2-2M20 20v-5h-5"/></svg>',
  spinner: '<svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 3a9 9 0 1 0 9 9"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
};

// ---------- talking to the server ----------

async function api(path, body) {
  const opts = { method: body === undefined ? 'GET' : 'POST', headers: {}, credentials: 'omit' };
  if (app.token) opts.headers.Authorization = `Bearer ${app.token}`;
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  let resp;
  try {
    resp = await fetch(path, opts);
  } catch {
    app.online = false;
    const err = new Error('offline');
    err.offline = true;
    throw err;
  }
  app.online = true;
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    if (resp.status === 401 && app.token) signOut();
    const err = new Error(data.error || 'Something went wrong.');
    err.status = resp.status;
    err.code = data.code;
    throw err;
  }
  return data;
}

function setState(s) {
  app.state = s;
  app.syncedAt = Date.now();
  clock.sync(s.server_time_ms);
  store.set(KEY_STATE, JSON.stringify({ state: s, savedAt: app.syncedAt }));
}

function restoreState() {
  try {
    const saved = JSON.parse(store.get(KEY_STATE) || 'null');
    if (!saved?.state) return;
    app.state = saved.state;
    app.syncedAt = saved.savedAt;
    clock.restore(saved.state.server_time_ms, saved.savedAt);
  } catch { /* nothing usable stored */ }
}

async function refresh({ quiet = true } = {}) {
  if (!app.token) return;
  try {
    setState(await api('/api/wearer/state'));
    if (store.get(KEY_PENDING)) await sendPendingRequest();
    if (app.tab === 'messages') await loadMessages();
    if (app.tab === 'activity') await loadActivity();
  } catch (e) {
    if (!e.offline && !quiet) app.notice = { tone: 'error', text: e.message };
  }
  render();
}

async function sendPendingRequest() {
  store.del(KEY_PENDING);
  try {
    setState(await api('/api/wearer/request-unlock', {}));
  } catch (e) {
    if (!e.offline) app.notice = { tone: 'info', text: `Your request could not be sent: ${e.message}` };
  }
}

function signOut() {
  store.del(KEY_TOKEN);
  store.del(KEY_STATE);
  app.token = null;
  app.state = null;
  render();
}

// ---------- actions ----------

async function act(name, fn) {
  if (app.busy) return;
  app.busy = name;
  app.notice = null;
  render();
  try {
    await fn();
  } catch (e) {
    if (e.offline) app.notice = { tone: 'error', text: "You're offline. Try again when you have a connection." };
    else if (e.code === 'out_of_range') app.needRelay = { intent: name };
    else app.notice = { tone: 'error', text: e.message };
  }
  app.busy = null;
  render();
}

const actions = {
  request: () => {
    if (!app.online) {
      store.set(KEY_PENDING, '1');
      app.notice = { tone: 'info', text: 'Saved. Your request is sent as soon as you are back online.' };
      return render();
    }
    return act('request', async () => setState(await api('/api/wearer/request-unlock', {})));
  },
  cancel: () => act('cancel', async () => {
    store.del(KEY_PENDING);
    setState(await api('/api/wearer/cancel-request', {}));
  }),
  unlock: () => act('unlock', async () => setState(await api('/api/wearer/unlock', {}))),
  lock: () => act('lock', async () => setState(await api('/api/wearer/lock', {}))),
  // The tap on "Connect and apply" is itself the gesture the Bluetooth chooser needs: start at once.
  queued: () => startRelay('queued'),
  sync: async () => {
    if (app.syncing) return;
    app.syncing = true;
    render();
    try {
      const v = await api('/api/wearer/sync', {});
      setState(v);
      if (v.in_range === false) app.notice = { tone: 'info', text: "The server can't reach the pod right now, so its state is as last checked." };
    } catch (e) {
      if (!e.offline) app.notice = { tone: 'error', text: e.message };
    }
    app.syncing = false;
    render();
  },
  'use-bluetooth': () => startRelay((app.needRelay ?? app.relay).intent),
  'dismiss-relay': () => { app.needRelay = null; app.relay = null; render(); },
  tab: (el) => switchTab(el.dataset.tab),
  'enable-push': enablePush,
  'sign-out': signOut,
};

async function startRelay(intent) {
  if (app.relay?.step && !app.relay.error) return;
  app.needRelay = null;
  app.relay = { intent, step: 'connecting', error: null };
  render();
  try {
    const result = await runRelay(
      intent,
      (path, body) => api(path, body),
      new WebBluetoothLink(),
      (step) => { app.relay.step = step; render(); },
    );
    const { done, ...state } = result;
    setState(state);
    app.relay = null;
  } catch (e) {
    // The chooser being dismissed is not an error worth shouting about.
    const cancelled = e.name === 'NotFoundError' || /cancel/i.test(e.message);
    app.relay = cancelled ? null : { intent, step: null, error: e.offline ? "You're offline." : e.message || 'Bluetooth failed.' };
    if (cancelled) app.needRelay = { intent };
  }
  render();
}

async function switchTab(tab) {
  app.tab = tab;
  app.notice = null;
  render();
  if (tab === 'messages') { await loadMessages(); await refresh(); }
  if (tab === 'activity') await loadActivity();
}

async function loadMessages() {
  try { app.messages = (await api('/api/wearer/messages')).messages; } catch { /* keep what we have */ }
  render();
}

async function loadActivity() {
  try { app.activity = (await api('/api/wearer/activity')).activity; } catch { /* keep what we have */ }
  render();
}

// ---------- notifications ----------

const b64urlToBytes = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const bytesToB64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function detectPush() {
  if (!app.push.supported || !app.token || Notification.permission === 'denied') return;
  try {
    const reg = await navigator.serviceWorker.ready;
    app.push.on = Boolean(await reg.pushManager.getSubscription());
    if (!app.push.on) {
      // Only offer notifications if the server has them set up.
      await api('/api/wearer/push/key');
      app.push.available = true;
    }
  } catch { app.push.available = false; }
  render();
}

async function enablePush() {
  try {
    const { public_key } = await api('/api/wearer/push/key');
    if ((await Notification.requestPermission()) !== 'granted') {
      app.notice = { tone: 'info', text: 'Notifications are blocked. You can allow them in your browser settings.' };
      return render();
    }
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64urlToBytes(public_key) });
    const json = sub.toJSON();
    await api('/api/wearer/push/subscribe', {
      endpoint: json.endpoint,
      keys: { p256dh: json.keys?.p256dh ?? bytesToB64url(sub.getKey('p256dh')), auth: json.keys?.auth ?? bytesToB64url(sub.getKey('auth')) },
    });
    app.push.on = true;
    app.notice = { tone: 'info', text: "Notifications are on. You'll hear when your keyholder acts." };
  } catch (e) {
    app.notice = { tone: 'error', text: `Notifications could not be turned on: ${e.message}` };
  }
  render();
}

// ---------- views ----------

function shell(inner, { tabs = true } = {}) {
  const s = app.state;
  let link;
  if (!app.online) link = `<i class="dot warn"></i><span>Offline${s && app.syncedAt ? ` · synced ${fmtTime(app.syncedAt)}` : ''}</span>`;
  else if (s?.pod) link = `<i class="dot"></i><span>Pod checked ${ago(clock.now() ?? Date.now(), s.pod.checked_ms)}</span>`;
  else link = '<i class="dot off"></i><span>Pod not checked yet</span>';
  const unread = s?.unread_messages || 0;
  const tab = (id, icon, label, badge = '') =>
    `<button class="tab ${app.tab === id ? 'on' : ''}" data-action="tab" data-tab="${id}">${ICON[icon]}${label}${badge}</button>`;
  return `<div class="shell">
    <header class="hd"><span class="name">Tether</span>
      <span class="link">${link}<button class="icon-btn ${app.syncing ? 'busy' : ''}" data-action="sync" aria-label="Sync now">${ICON.sync}</button></span>
    </header>
    <main class="main">${inner}</main>
    ${tabs ? `<nav class="tabs">${tab('home', 'lock', 'Lock')}${tab('messages', 'chat', 'Messages', unread ? `<span class="n">${unread}</span>` : '')}${tab('activity', 'list', 'Activity')}</nav>` : ''}
  </div>`;
}

function noticeHtml() {
  if (!app.notice) return '';
  return app.notice.tone === 'error' ? `<p class="error" role="alert">${esc(app.notice.text)}</p>` : `<div class="card note info"><span>${esc(app.notice.text)}</span></div>`;
}

function viewPair() {
  return `<div class="shell pair"><header class="hd"><span class="name">Tether</span></header>
    <main class="main">
      <div class="hero"><h1 class="title">Pair this device</h1>
      <p class="sub">Ask your keyholder for a one-time pairing code. It expires after 10 minutes.</p></div>
      <form id="pair-form" autocomplete="off">
        <input class="code" id="pair-code" name="code" inputmode="text" autocapitalize="characters" autocomplete="off" spellcheck="false" maxlength="9" placeholder="XXXX-XXXX" aria-label="Pairing code" required>
        <div class="actions">${noticeHtml()}<button class="btn request" type="submit" ${app.busy ? 'disabled' : ''}>${app.busy ? 'Pairing…' : 'Pair'}</button></div>
      </form>
      <div class="install"><b>Install it first.</b> In your browser's menu choose “Add to Home Screen”, so notifications and Bluetooth unlock work from the app icon.</div>
    </main></div>`;
}

function timerCard(t) {
  const d = t.digits;
  const foot = { running: 'Set by your keyholder. Only they can change it.', paused: 'Paused by your keyholder.', ended: t.unconfirmed ? 'Counted from your last sync. Your keyholder may have changed it since.' : 'The timer has finished.' }[t.kind];
  return `<section class="card timer ${t.kind}" aria-label="Timer">
    <div class="lab"><span>Time remaining</span><span class="tag ${t.kind}">${esc(t.label)}</span></div>
    <div class="digits" role="timer"><div data-live="d">${d.d}</div><div data-live="h">${d.h}</div><div data-live="m">${d.m}</div><div data-live="s">${d.s}</div>
      <small>DAYS</small><small>HRS</small><small>MIN</small><small>SEC</small></div>
    <div class="foot">${esc(foot)}</div></section>`;
}

function relayView() {
  const r = app.relay;
  const idx = RELAY_STEPS.findIndex((s) => s.id === r.step);
  const steps = RELAY_STEPS.map((s, i) => {
    const cls = idx > i || r.step === 'done' ? 'done' : idx === i ? 'now' : '';
    return `<li class="${cls}"><span class="n">${cls === 'done' ? ICON.check : i + 1}</span>${esc(s.label)}</li>`;
  }).join('');
  const failed = Boolean(r.error);
  return shell(`<div class="hero"><div class="badge c-pending">${failed ? ICON.lock : ICON.spinner}</div>
      <h1 class="title">${failed ? 'That did not work' : r.intent === 'lock' ? 'Locking…' : r.intent === 'queued' ? 'Applying…' : 'Unlocking…'}</h1>
      <p class="sub">${failed ? esc(r.error) : "Using this phone's Bluetooth."}</p></div>
    ${failed ? '' : `<ul class="steps">${steps}</ul>`}
    <div class="spacer"></div>
    <div class="actions">${failed ? `<button class="btn request" data-action="use-bluetooth">Try again</button><button class="linkbtn" data-action="dismiss-relay">Cancel</button>` : `<button class="btn off" disabled>Keep this screen open</button><p class="hint">Hold the phone within a metre or two of the lock.</p>`}</div>`, { tabs: false });
}

function relayOffer() {
  const n = app.needRelay;
  const what = n.intent === 'lock' ? 'lock' : n.intent === 'queued' ? 'apply the queued command' : 'unlock';
  if (!app.bluetooth) {
    return `<div class="card note warn"><i class="dot warn"></i><div><b>This browser can't use Bluetooth</b><span>The lock is out of the server's range. Open Tether in a browser with Web Bluetooth (Chrome on Android), or come within range of the server.</span></div></div>
      <div class="spacer"></div><div class="actions"><button class="btn off" disabled>${esc(what[0].toUpperCase() + what.slice(1))}</button><button class="linkbtn" data-action="dismiss-relay">Back</button></div>`;
  }
  return `<div class="card note warn"><i class="dot warn"></i><div><b>The server can't reach the lock</b><span>Use this phone's Bluetooth to ${esc(what)}. Hold the phone within a metre or two of the lock.</span></div></div>
    <div class="spacer"></div><div class="actions"><button class="btn request" data-action="use-bluetooth">Connect over Bluetooth</button><button class="linkbtn" data-action="dismiss-relay">Cancel</button></div>`;
}

function viewHome() {
  const s = app.state;
  if (!s) return shell('<div class="empty">Loading…</div>');
  if (app.relay) return relayView();
  const v = deriveView(s, { nowMs: clock.now() ?? s.server_time_ms, online: app.online });
  if (app.needRelay) {
    const icon = v.tone === 'open' ? ICON.open : ICON.lock;
    return shell(`<div class="hero"><div class="badge c-${v.tone}">${icon}</div><h1 class="title">${esc(v.title)}</h1></div>${relayOffer()}`);
  }
  const icon = v.tone === 'pending' ? ICON.hourglass : v.tone === 'open' ? ICON.open : ICON.lock;
  const busy = app.busy && v.primary.action === app.busy;
  const p = v.primary;
  const btnClass = p.disabled ? 'off' : p.action === 'unlock' ? 'unlock' : p.action === 'lock' ? 'lock' : 'request';
  const approval = v.approvalMs == null ? '' : `<p class="sub">Approval expires in <span data-live="approval">${formatMinSec(v.approvalMs)}</span>.</p>`;
  const queued = v.queued
    ? `<div class="card note info"><i class="dot"></i><div><b>Your keyholder queued: ${esc(v.queued.command === 'lock' ? 'Lock' : 'Unlock')}</b><span>It runs when the pod is in range of the server, or you can apply it over Bluetooth now.</span>
       ${app.bluetooth ? '<button class="btn request" data-action="queued">Connect and apply</button>' : ''}</div></div>`
    : '';
  const pushCard = app.push.supported && app.push.available && !app.push.on
    ? `<div class="card note"><div><b>Get notified</b><span>Hear when your keyholder approves, sends a message or changes the timer.</span><button class="btn quiet" data-action="enable-push">Turn on notifications</button></div></div>` : '';
  return shell(`<div class="hero"><div class="badge c-${v.tone}">${icon}</div><h1 class="title">${esc(v.title)}</h1>${v.subtitle ? `<p class="sub">${esc(v.subtitle)}</p>` : ''}${approval}</div>
    ${v.timer ? timerCard(v.timer) : ''}${queued}${noticeHtml()}${pushCard}
    <div class="spacer"></div>
    <div class="actions"><button class="btn ${btnClass}" ${p.action && !busy ? `data-action="${p.action}"` : 'disabled'}>${busy ? 'Working…' : esc(p.label)}</button>
      ${p.hint ? `<p class="hint">${esc(p.hint)}</p>` : ''}${v.secondary ? `<button class="linkbtn" data-action="${v.secondary.action}">${esc(v.secondary.label)}</button>` : ''}</div>`);
}

function viewMessages() {
  const list = app.messages;
  let inner = '<h2 class="section">Messages</h2>';
  if (list === null) inner += '<div class="empty">Loading…</div>';
  else if (!list.length) inner += '<div class="empty">No messages yet.</div>';
  else inner += `<div class="msgs">${[...list].reverse().map((m) => `<div><p class="who">Keyholder</p><div class="bubble">${esc(m.body)}<time>${esc(fmtDay(m.ts_ms))}</time></div></div>`).join('')}</div>`;
  return shell(inner);
}

function viewActivity() {
  const list = app.activity;
  let inner = '<h2 class="section">Activity</h2>';
  if (list === null) inner += '<div class="empty">Loading…</div>';
  else if (!list.length) inner += '<div class="empty">Nothing yet.</div>';
  else inner += `<div class="msgs">${list.map((e) => `<div class="evt">${esc(describeActivity(e))}<time>${esc(fmtDay(e.ts_ms))}</time></div>`).join('')}</div>`;
  inner += '<div class="foot-link"><button class="linkbtn" data-action="sign-out">Sign out of this phone</button></div>';
  return shell(inner);
}

function render() {
  const focusedId = document.activeElement?.id;
  root.innerHTML = !app.token ? viewPair() : app.tab === 'messages' ? viewMessages() : app.tab === 'activity' ? viewActivity() : viewHome();
  lastSignature = signature();
  const form = document.getElementById('pair-form');
  if (form) {
    form.addEventListener('submit', onPair);
    if (focusedId === 'pair-code') document.getElementById('pair-code').focus();
  }
}

// ---------- pairing ----------

async function onPair(event) {
  event.preventDefault();
  const code = document.getElementById('pair-code').value.trim();
  if (!code || app.busy) return;
  app.busy = 'pair';
  app.notice = null;
  render();
  try {
    const name = /android/i.test(navigator.userAgent) ? 'Android phone' : /iphone|ipad/i.test(navigator.userAgent) ? 'iPhone' : 'Web browser';
    const { token } = await api('/api/wearer/pair', { code, device_name: name });
    app.token = token;
    store.set(KEY_TOKEN, token);
    app.busy = null;
    await refresh({ quiet: false });
    detectPush();
    return;
  } catch (e) {
    app.notice = { tone: 'error', text: e.offline ? "You're offline." : e.message };
  }
  app.busy = null;
  render();
}

// ---------- live countdown ----------

let lastSignature = '';

/** What must be redrawn if it changes: the buttons and which timer card shows. */
function signature() {
  if (!app.state || app.tab !== 'home') return '';
  const v = deriveView(app.state, { nowMs: clock.now() ?? app.state.server_time_ms, online: app.online });
  return JSON.stringify([v.lock, v.primary, v.timer?.kind, v.timer?.label, Boolean(v.approvalMs), v.title]);
}

function tick() {
  if (!app.state || app.tab !== 'home' || app.relay || app.needRelay) return;
  const v = deriveView(app.state, { nowMs: clock.now() ?? app.state.server_time_ms, online: app.online });
  if (signature() !== lastSignature) return render();
  if (v.timer) for (const k of ['d', 'h', 'm', 's']) {
    const el = root.querySelector(`[data-live="${k}"]`);
    if (el) el.textContent = v.timer.digits[k];
  }
  const ap = root.querySelector('[data-live="approval"]');
  if (ap && v.approvalMs != null) ap.textContent = formatMinSec(v.approvalMs);
}

// ---------- wiring ----------

root.addEventListener('click', (event) => {
  const el = event.target.closest('[data-action]');
  if (!el || el.disabled) return;
  actions[el.dataset.action]?.(el);
});

window.addEventListener('online', () => { app.online = true; refresh(); });
window.addEventListener('offline', () => { app.online = false; render(); });
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') refresh(); });
setInterval(tick, 1000);
setInterval(() => { if (document.visibilityState === 'visible' && !app.relay) refresh(); }, POLL_MS);

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});

restoreState();
render();
refresh({ quiet: true }).then(detectPush);
