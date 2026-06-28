/**
 * junctek-shunt-ble.js
 *
 * Web Bluetooth client for JuncTek KM-F series battery shunts (confirmed against KMF230001).
 *
 * Protocol reverse-engineered via static analysis of the Junce Home app (com.juntek.platform
 * v1.6.8), which ships its logic as readable JavaScript (DCloud/uni-app framework) rather than
 * compiled native code. See JuncTek_KMF_BLE_Protocol.md alongside this file for the full writeup.
 *
 * Unlike the MICTUNING panel, this is a plain ASCII text protocol -- frames look like
 * ":A1234,567,...,8901\r\n" sent/received as literal ASCII bytes, no binary packing.
 *
 * Requires a browser with navigator.bluetooth -- on iPad/iPhone this means the Bluefy browser
 * (Safari has no Web Bluetooth support).
 *
 * Usage:
 *   const shunt = new JuncTekShunt();
 *   await shunt.connect();              // prompts the OS BLE device picker
 *   shunt.onReading((data) => {
 *     console.log(data.voltage, data.current, data.power, data.socPercent);
 *   });
 *   // device starts streaming automatically after the initial handshake command
 */

const DEFAULT_PASSWORD = '11223344';

class JuncTekShunt {
  constructor(opts = {}) {
    this.password = opts.password || DEFAULT_PASSWORD;
    this.batteryCapacityAh = opts.batteryCapacityAh || null; // overrides C[4] if you want to set it client-side

    this.device = null;
    this.server = null;
    this.service = null;
    this.writeChar = null;
    this.notifyChar = null;

    this._rxBuffer = '';
    this._readingListeners = [];
    this._rawFrameListeners = [];
    this._connectionListeners = [];
    this.lastFrames = {}; // { A: [...], C: [...], E: [...], ... } most recent parsed registers

    // --- Auto-reconnect state ---
    this._autoReconnect = opts.autoReconnect !== false; // on by default
    this._reconnecting = false;
    this._wantConnected = false;
    this._reconnectDelayMs = 1500;
    this._maxReconnectDelayMs = 15000;

    if (this._autoReconnect && typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') this._attemptReconnectIfNeeded();
      });
    }
  }

  /** Opens the OS Bluetooth device picker. No service filter -- JuncTek doesn't expose a fixed
   *  service UUID, so we have to let the user pick from all nearby BLE devices.
   *  This is the only step that needs a fresh user gesture -- reconnects happen silently. */
  async connect() {
    if (!navigator.bluetooth) {
      throw new Error(
        'Web Bluetooth is not available. On iPad/iPhone, open this page inside the ' +
        'Bluefy browser app (Safari does not support Web Bluetooth).'
      );
    }

    this.device = await navigator.bluetooth.requestDevice({
      acceptAllDevices: true,
      optionalServices: [], // unknown ahead of time; we discover after connecting
    });

    this.device.addEventListener('gattserverdisconnected', () => this._onDisconnected());

    await this._setupConnection();
    this._wantConnected = true;

    return this.device.name || 'JuncTek shunt';
  }

  /** Internal: does the actual GATT connect + service/characteristic discovery + handshake.
   *  Shared between the initial connect() and silent auto-reconnect attempts. */
  async _setupConnection() {
    this.server = await this.device.gatt.connect();

    const services = await this.server.getPrimaryServices();
    if (!services.length) throw new Error('No BLE services found on this device.');

    // Junce Home always picks the LAST discovered service -- replicate that.
    this.service = services[services.length - 1];

    const characteristics = await this.service.getCharacteristics();
    if (characteristics.length < 2) {
      throw new Error(
        `Expected at least 2 characteristics on service ${this.service.uuid}, found ${characteristics.length}.`
      );
    }

    // Junce Home convention: characteristics[0] = notify/read, characteristics[1] = write.
    this.notifyChar = characteristics[0];
    this.writeChar = characteristics[1];

    await this.notifyChar.startNotifications();
    this.notifyChar.addEventListener('characteristicvaluechanged', (event) =>
      this._handleNotify(event.target.value)
    );

    // TEMP DEBUG: auto-handshake disabled for diagnosis -- send ':r00=86.' manually via the
    // test page's Send button instead, to isolate whether the handshake write itself is what
    // triggers the page reload/raw-HTML symptom.
    // await this._delay(300);
    // await this.sendRaw(':r00=86.');

    this._connectionListeners.forEach((cb) => cb({ connected: true, reconnected: this._reconnecting }));
  }

  /** Call this to intentionally disconnect and stop auto-reconnecting. */
  disconnect() {
    this._wantConnected = false;
    if (this.device && this.device.gatt.connected) {
      this.device.gatt.disconnect();
    }
  }

  _onDisconnected() {
    console.warn('JuncTek shunt disconnected.');
    this._readingListeners.forEach((cb) => cb({ connected: false }));
    this._connectionListeners.forEach((cb) => cb({ connected: false }));

    if (this._autoReconnect && this._wantConnected) {
      this._scheduleReconnect();
    }
  }

  _scheduleReconnect(delay = this._reconnectDelayMs) {
    if (this._reconnecting) return;
    this._reconnecting = true;
    setTimeout(() => this._attemptReconnectIfNeeded(delay), delay);
  }

  async _attemptReconnectIfNeeded(lastDelay = this._reconnectDelayMs) {
    if (!this._wantConnected) {
      this._reconnecting = false;
      return;
    }
    if (this.device && this.device.gatt.connected) {
      this._reconnecting = false;
      return;
    }
    if (!this.device) {
      this._reconnecting = false;
      return;
    }

    try {
      await this._setupConnection();
      console.log('JuncTek shunt: reconnected.');
      this._reconnecting = false;
    } catch (err) {
      console.warn('JuncTek shunt: reconnect attempt failed, will retry.', err);
      const nextDelay = Math.min(lastDelay * 1.6, this._maxReconnectDelayMs);
      setTimeout(() => this._attemptReconnectIfNeeded(nextDelay), nextDelay);
    }
  }

  /** Register a callback for connection state changes: cb({ connected, reconnected }) */
  onConnectionChange(callback) {
    this._connectionListeners.push(callback);
  }

  /** Register a callback for parsed live readings: cb({ voltage, current, power, socPercent, raw }) */
  onReading(callback) {
    this._readingListeners.push(callback);
  }

  /** Register a callback for every raw parsed frame: cb({ letter, values, raw }) -- useful for
   *  exploring registers this client doesn't decode yet (D, F, etc). */
  onRawFrame(callback) {
    this._rawFrameListeners.push(callback);
  }

  /** Sends a raw command string as literal ASCII bytes (e.g. ":r00=86."). */
  async sendRaw(commandString) {
    if (!this.writeChar) throw new Error('Not connected. Call connect() first.');
    const bytes = new TextEncoder().encode(commandString);
    await this.writeChar.writeValueWithoutResponse(bytes);
  }

  /** Builds and sends a checksummed command frame: letter + comma-separated values.
   *  e.g. sendCommand('D', ['', '', someValue, '', '', '', '', '', '']) */
  async sendCommand(letter, values) {
    const sum = this._checksum(letter, values);
    const body = values.join(',');
    const frame = `:${letter}=${body},${sum}`;
    await this.sendRaw(frame);
  }

  _checksum(letter, values) {
    let acc = letter.charCodeAt(0);
    for (const v of values) {
      const n = Number(v);
      if (!Number.isNaN(n)) acc ^= n;
    }
    acc ^= Number(this.password);
    return (acc % 9999) + 1;
  }

  _delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  _handleNotify(dataView) {
    const bytes = new Uint8Array(dataView.buffer);
    const text = new TextDecoder().decode(bytes);
    this._rxBuffer += text;

    // Frames are \r\n-terminated; split and process any complete ones, keep the remainder buffered.
    while (true) {
      const idx = this._rxBuffer.indexOf('\r\n');
      if (idx === -1) break;
      const frame = this._rxBuffer.slice(0, idx);
      this._rxBuffer = this._rxBuffer.slice(idx + 2);
      this._parseFrame(frame);
    }
  }

  _parseFrame(frame) {
    if (!frame.startsWith(':') || frame.length < 2) return;

    const letter = frame[1];
    // Frame body is everything after the letter, optionally after an '=' sign, comma-separated.
    const eqIdx = frame.indexOf('=');
    const body = eqIdx > -1 ? frame.slice(eqIdx + 1) : frame.slice(2);
    const parts = body.split(',');

    if (parts.length < 2) return; // need at least one value + checksum

    const values = parts.slice(0, -1);
    const claimedChecksum = Number(parts[parts.length - 1]);
    const expectedChecksum = this._checksum(letter, values);

    if (claimedChecksum !== expectedChecksum) {
      console.warn(`Checksum mismatch on frame ${frame} (letter ${letter}). Got ${claimedChecksum}, expected ${expectedChecksum}. Ignoring.`);
      return;
    }

    this.lastFrames[letter] = values.map((v) => Number(v));
    this._rawFrameListeners.forEach((cb) => cb({ letter, values: this.lastFrames[letter], raw: frame }));

    if (letter === 'A') {
      this._emitReading();
    }
  }

  _emitReading() {
    const A = this.lastFrames.A;
    const C = this.lastFrames.C;
    if (!A) return;

    const voltage = A[0] !== undefined ? A[0] / 100 : null;
    const current = A[1] !== undefined ? A[1] / 1000 : null;
    const power = voltage !== null && current !== null ? voltage * current : null;
    const remainingAh = A[3] !== undefined ? A[3] : null;

    const fullCapacityAh = this.batteryCapacityAh || (C && C[4] !== undefined ? C[4] : null);
    const socPercent =
      remainingAh !== null && fullCapacityAh ? Math.floor((remainingAh / fullCapacityAh) * 100) : null;

    const reading = {
      connected: true,
      voltage,
      current,
      power,
      remainingAh,
      fullCapacityAh,
      socPercent,
      raw: { A, C },
    };

    this._readingListeners.forEach((cb) => cb(reading));
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { JuncTekShunt };
} else {
  window.JuncTekShunt = JuncTekShunt;
}
