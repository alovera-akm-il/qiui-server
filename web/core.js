// Pure logic for the wearer's app: no DOM, no network. Everything here is
// covered by `node --test web/test`, so the rules the screen follows are checked
// without a browser.

export const SERVICE_UUID = '0000fff0-0000-1000-8000-00805f9b34fb';
export const WRITE_UUID = '0000fff1-0000-1000-8000-00805f9b34fb';
export const NOTIFY_UUID = '0000fff2-0000-1000-8000-00805f9b34fb';

const pad2 = (n) => String(n).padStart(2, '0');

/** Milliseconds to days / hours / minutes / seconds, zero-padded for display. */
export function splitDuration(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  return {
    d: pad2(Math.floor(s / 86400)),
    h: pad2(Math.floor((s % 86400) / 3600)),
    m: pad2(Math.floor((s % 3600) / 60)),
    s: pad2(s % 60),
  };
}

/** "14:59" style, for the approval countdown. */
export function formatMinSec(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  return `${pad2(Math.floor(s / 60))}:${pad2(s % 60)}`;
}

/** "2 min ago" style. */
export function ago(nowMs, thenMs) {
  const s = Math.max(0, Math.floor((nowMs - thenMs) / 1000));
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

/**
 * The server's clock, as this device can best tell it. A countdown is drawn from
 * the server's time, never the phone's, so changing the phone's clock does not
 * change the timer. Between syncs it advances by the larger of the monotonic and
 * wall-clock elapsed time: the monotonic clock can stall while a phone sleeps,
 * and moving the wall clock forward only ever makes the display finish early,
 * which enables nothing (the server checks every request itself).
 */
export class ServerClock {
  constructor({ mono = () => performance.now(), wall = () => Date.now() } = {}) {
    this.mono = mono;
    this.wall = wall;
    this.baseServer = null;
    this.baseMono = 0;
    this.baseWall = 0;
  }

  /** A fresh reading straight from the server. */
  sync(serverMs) {
    this.baseServer = serverMs;
    this.baseMono = this.mono();
    this.baseWall = this.wall();
  }

  /** Restore from storage: `savedWallMs` is when `serverMs` was read. */
  restore(serverMs, savedWallMs) {
    this.baseServer = serverMs + Math.max(0, this.wall() - savedWallMs);
    this.baseMono = this.mono();
    this.baseWall = this.wall();
  }

  now() {
    if (this.baseServer === null) return null;
    const elapsed = Math.max(this.mono() - this.baseMono, this.wall() - this.baseWall, 0);
    return this.baseServer + elapsed;
  }
}

/** Milliseconds left on the timer, or null when there is none. */
export function timerRemaining(timer, nowMs) {
  switch (timer?.kind) {
    case 'running': return Math.max(0, timer.ends_at_ms - nowMs);
    case 'paused': return timer.remaining_ms;
    case 'ended': return 0;
    default: return null;
  }
}

const HINT = {
  request: 'Your keyholder gets a notification.',
  timerRunning: 'Opens when the timer ends. Only your keyholder can change it.',
  timerPaused: 'The timer is paused. It resumes when your keyholder restarts it.',
  timerEnded: "The timer is done. Opening still needs your keyholder's approval.",
  approved: 'After unlocking, opening it again needs a fresh approval.',
  unlocked: 'The pod locks itself soon after opening. Lock ends this unlock; reopening needs a new approval.',
  offlineEnded: "You're offline. The request is sent when you reconnect, and the server checks the timer itself.",
};

/**
 * Everything the home screen shows, decided from the server's state alone.
 * `ctx`: { nowMs, online }.
 */
export function deriveView(state, ctx) {
  const { nowMs, online } = ctx;
  const remaining = timerRemaining(state.timer, nowMs);
  // A running timer whose end has passed here reads as ended; offline it is only a guess.
  const endedLocally = state.timer.kind === 'running' && remaining === 0;
  const timerKind = endedLocally ? 'ended' : state.timer.kind;
  const blocking = timerKind === 'running' || timerKind === 'paused';

  const view = {
    lock: state.lock,
    tone: 'locked',
    title: 'Locked',
    subtitle: null,
    timer: null,
    approvalMs: null,
    primary: { label: 'Request unlock', action: 'request', disabled: false, hint: HINT.request },
    secondary: null,
    queued: state.queued_command ? { command: state.queued_command.command } : null,
  };

  if (timerKind !== 'idle') {
    view.timer = {
      kind: timerKind,
      label: timerKind === 'running' ? 'Running' : timerKind === 'paused' ? 'Paused' : online ? 'Ended' : 'Ended · unconfirmed',
      digits: splitDuration(timerKind === 'ended' ? 0 : remaining),
      unconfirmed: endedLocally && !online,
    };
  }

  switch (state.lock) {
    case 'locked':
      if (blocking) {
        view.primary = {
          label: 'Unlock requests closed',
          action: null,
          disabled: true,
          hint: timerKind === 'paused' ? HINT.timerPaused : HINT.timerRunning,
        };
      } else if (timerKind === 'ended') {
        view.primary.hint = endedLocally && !online ? HINT.offlineEnded : HINT.timerEnded;
      }
      break;
    case 'requested':
      view.tone = 'pending';
      view.title = 'Request sent';
      view.subtitle = 'Waiting for your keyholder.';
      view.primary = { label: 'Waiting for approval', action: null, disabled: true, hint: null };
      view.secondary = { label: 'Cancel request', action: 'cancel' };
      break;
    case 'approved': {
      view.tone = 'open';
      view.title = 'Approved';
      view.approvalMs = state.approval_expires_ms == null ? null : Math.max(0, state.approval_expires_ms - nowMs);
      view.primary = { label: 'Unlock', action: 'unlock', disabled: false, hint: HINT.approved };
      view.secondary = { label: 'Cancel', action: 'cancel' };
      break;
    }
    case 'unlocked':
      view.tone = 'open';
      view.title = 'Unlocked';
      view.primary = { label: 'Lock', action: 'lock', disabled: false, hint: HINT.unlocked };
      break;
  }
  return view;
}

/** Copy for each stage of a phone-relayed unlock or lock. */
export const RELAY_STEPS = [
  { id: 'connecting', label: 'Connecting to the lock' },
  { id: 'handshake', label: 'Saying hello to the lock' },
  { id: 'command', label: 'Sending the command' },
];

/** Human wording for the activity feed. */
export function describeActivity(e) {
  const who = e.by === 'keyholder' ? 'Your keyholder' : e.by === 'wearer' ? 'You' : 'Tether';
  const via = e.via === 'phone' ? ' from this phone' : '';
  switch (e.kind) {
    case 'unlock_requested': return 'You asked to be unlocked';
    case 'request_cancelled': return 'You withdrew your request';
    case 'request_denied': return 'Your keyholder turned down the request';
    case 'unlock_approved': return 'Your keyholder approved the request';
    case 'approval_revoked': return 'The approval was withdrawn';
    case 'approval_expired': return 'The approval expired';
    case 'unlocked': return `${who} unlocked the pod${via}`;
    case 'locked': return `${who} locked the pod${via}`;
    case 'timer_set': return 'Timer set by your keyholder';
    case 'timer_rolled': return 'Random timer rolled by your keyholder';
    case 'timer_extended':
    case 'timer_extension_rolled': return 'Time added to the timer by your keyholder';
    case 'timer_paused': return 'Timer paused by your keyholder';
    case 'timer_resumed': return 'Timer restarted by your keyholder';
    case 'timer_cleared': return 'Timer cleared by your keyholder';
    case 'timer_ended': return 'Timer ended';
    case 'command_queued': return 'Your keyholder queued a command';
    case 'command_cancelled': return 'The queued command was cancelled';
    case 'queued_command_done': return 'The queued command was carried out';
    case 'queued_command_dropped': return 'The queued command was dropped';
    case 'message_sent': return 'Message from your keyholder';
    default: return e.kind.replaceAll('_', ' ');
  }
}
