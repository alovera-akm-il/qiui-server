// Phone-relayed Bluetooth. The phone only carries bytes: the server says what to
// write next and decides when an unlock or lock command may exist at all.
//
// Every session ends with a disconnect, on success, failure or timeout.
import { NOTIFY_UUID, SERVICE_UUID, WRITE_UUID } from './core.js';

const REPLY_TIMEOUT_MS = 8000;

export const toHex = (bytes) => [...new Uint8Array(bytes.buffer ?? bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
export const fromHex = (hex) => Uint8Array.from(hex.match(/../g).map((x) => parseInt(x, 16)));

/** Web Bluetooth needs a secure page and a browser that has it (not iPhone Safari or Chrome). */
export function bluetoothSupported(nav = globalThis.navigator, secure = globalThis.isSecureContext) {
  return Boolean(nav?.bluetooth) && Boolean(secure);
}

/**
 * Drive one relay session. `api(path, body)` posts to the server and returns its JSON;
 * `link` has connect(), exchange(hex) -> reply hex, and disconnect().
 *
 * The phone connects first, so the server's handshake token is fresh when it is written.
 */
export async function runRelay(intent, api, link, onStep = () => {}) {
  try {
    onStep('connecting');
    await link.connect();
    const start = await api('/api/wearer/relay/start', { intent });
    let next = start.cmd;
    let stage = 'handshake';
    // Handshake, then at most one command: anything longer means the server is confused.
    for (let round = 0; round < 3; round++) {
      onStep(stage);
      const hex = await link.exchange(next);
      const reply = await api('/api/wearer/relay/reply', { session_id: start.session_id, hex });
      if (reply.done) {
        onStep('done');
        return reply;
      }
      next = reply.cmd;
      stage = 'command';
    }
    throw new Error('The server asked for more steps than expected.');
  } finally {
    await link.disconnect().catch(() => {});
  }
}

/** The real thing, over Web Bluetooth. Must be started from a tap (the chooser needs one). */
export class WebBluetoothLink {
  constructor(nav = navigator) {
    this.nav = nav;
    this.device = null;
    this.writeChar = null;
    this.notifyChar = null;
    this.inbox = [];
    this.waiter = null;
    this.onNotify = (e) => {
      const hex = toHex(e.target.value);
      if (this.waiter) {
        const w = this.waiter;
        this.waiter = null;
        w(hex);
      } else {
        this.inbox.push(hex);
      }
    };
  }

  async connect() {
    this.device = await this.nav.bluetooth.requestDevice({ filters: [{ services: [SERVICE_UUID] }], optionalServices: [SERVICE_UUID] });
    try {
      await this.open();
    } catch {
      // The first connection after the pod wakes often drops within seconds. Once more.
      await new Promise((r) => setTimeout(r, 1500));
      await this.open();
    }
  }

  async open() {
    // Drop the old listener first, or every reconnect would deliver each reply once more.
    this.notifyChar?.removeEventListener('characteristicvaluechanged', this.onNotify);
    const server = await this.device.gatt.connect();
    const service = await server.getPrimaryService(SERVICE_UUID);
    this.writeChar = await service.getCharacteristic(WRITE_UUID);
    this.notifyChar = await service.getCharacteristic(NOTIFY_UUID);
    this.notifyChar.addEventListener('characteristicvaluechanged', this.onNotify);
    await this.notifyChar.startNotifications();
  }

  async exchange(hex) {
    this.inbox = [];
    const bytes = fromHex(hex);
    if (this.writeChar.properties.writeWithoutResponse && this.writeChar.writeValueWithoutResponse) {
      await this.writeChar.writeValueWithoutResponse(bytes);
    } else {
      await this.writeChar.writeValue(bytes);
    }
    if (this.inbox.length) return this.inbox.shift();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiter = null;
        reject(new Error('The lock did not answer. Hold the phone closer and try again.'));
      }, REPLY_TIMEOUT_MS);
      this.waiter = (hex2) => {
        clearTimeout(timer);
        resolve(hex2);
      };
    });
  }

  async disconnect() {
    this.notifyChar?.removeEventListener('characteristicvaluechanged', this.onNotify);
    if (this.device?.gatt?.connected) this.device.gatt.disconnect();
  }
}
