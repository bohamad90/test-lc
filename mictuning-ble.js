/**
 * mictuning-ble.js
 *
 * Web Bluetooth client for MICTUNING P2C-family switch panels (P2C8 / P2C8A / P2C8B /
 * P2C12 / P2C12A / P2C6A / P2C6B and similar gang-count variants).
 *
 * Protocol reverse-engineered via static analysis of the MICTUNING Android app
 * (com.qunchen.headlightSpp v3.6.16), then CORRECTED and CONFIRMED via a live Apple
 * PacketLogger capture against a real P1S 12-gang panel. See MICTUNING_BLE_Protocol.md
 * alongside this file for the full writeup.
 *
 * Requires a browser with navigator.bluetooth -- on iPad/iPhone this means the Bluefy browser
 * (Safari itself has zero Web Bluetooth support, by Apple design, with no plan to change).
 *
 * Usage:
 *   const panel = new MictuningPanel();
 *   await panel.connect();              // prompts the OS BLE device picker
 *   await panel.setChannel(0, true);     // turn channel 1 ON
 *   await panel.setChannel(0, false);    // turn channel 1 OFF
 *   await panel.setAll(true);            // turn ALL channels ON
 *   panel.onStatus((status) => { ... }); // get live status updates
 */

const SERVICE_UUID = '0003cbbb-0000-1000-8000-00805f9bfff0';
const CHAR_FFF1 = '0003cbbb-0000-1000-8000-00805f9bfff1';
const CHAR_FFFA = '0003cbbb-0000-1000-8000-00805f9bfffa'; // main write target

class MictuningPanel {
  constructor(opts = {}) {
    this.device = null;
    this.server = null;
    this.service = null;
    this.writeChar = null;
    this.notifyChar = null;
    this._statusListeners = [];
    this._connectionListeners = [];
    this._channelState = {}; // { [index]: boolean } -- last known on/off state per channel

    // --- Auto-reconnect state ---
    this._autoReconnect = opts.autoReconnect !== false; // on by default
    this._reconnecting = false;
    this._wantConnected = false; // becomes true after a successful manual connect()
    this._reconnectDelayMs = 1500;
    this._maxReconnectDelayMs = 15000;

    if (this._autoReconnect && typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') this._attemptReconnectIfNeeded();
      });
    }
  }

  /** Opens the OS Bluetooth device picker, filtered to this panel's service UUID.
   *  This is the only step that needs a fresh user gesture -- once the device has been
   *  picked once, reconnects happen silently via device.gatt.connect() with no picker. */
  async connect() {
    if (!navigator.bluetooth) {
      throw new Error(
        'Web Bluetooth is not available. On iPad/iPhone, open this page inside the ' +
        'Bluefy browser app (Safari does not support Web Bluetooth).'
      );
    }

    this.device = await navigator.bluetooth.requestDevice({
      filters: [{ services: [SERVICE_UUID] }],
      optionalServices: [SERVICE_UUID],
    });

    this.device.addEventListener('gattserverdisconnected', () => this._onDisconnected());

    await this._setupConnection();
    this._wantConnected = true;

    return this.device.name || 'MICTUNING panel';
  }

  /** Internal: does the actual GATT connect + service/characteristic setup. Shared between
   *  the initial connect() and silent auto-reconnect attempts. */
  async _setupConnection() {
    this.server = await this.device.gatt.connect();
    this.service = await this.server.getPrimaryService(SERVICE_UUID);
    this.writeChar = await this.service.getCharacteristic(CHAR_FFFA);

    // Subscribe to notifications for status updates, if available.
    try {
      this.notifyChar = await this.service.getCharacteristic(CHAR_FFF1);
      await this.notifyChar.startNotifications();
      this.notifyChar.addEventListener('characteristicvaluechanged', (event) =>
        this._handleNotify(event.target.value)
      );
    } catch (err) {
      console.warn('Could not subscribe to FFF1 notifications -- status updates unavailable.', err);
    }

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
    console.warn('MICTUNING panel disconnected.');
    this._statusListeners.forEach((cb) => cb({ connected: false }));
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
      return; // already connected (e.g. visibilitychange fired but we never actually dropped)
    }
    if (!this.device) {
      this._reconnecting = false;
      return; // never connected in the first place -- nothing to reconnect to
    }

    try {
      await this._setupConnection();
      console.log('MICTUNING panel: reconnected.');
      this._reconnecting = false;
    } catch (err) {
      console.warn('MICTUNING panel: reconnect attempt failed, will retry.', err);
      const nextDelay = Math.min(lastDelay * 1.6, this._maxReconnectDelayMs);
      setTimeout(() => this._attemptReconnectIfNeeded(nextDelay), nextDelay);
    }
  }

  /** Register a callback for connection state changes: cb({ connected, reconnected }) */
  onConnectionChange(callback) {
    this._connectionListeners.push(callback);
  }

  /** Register a callback for parsed status updates: cb({ connected, panelOn, channels, raw }) */
  onStatus(callback) {
    this._statusListeners.push(callback);
  }

  /**
   * Turn a single channel on or off.
   * @param {number} channelIndex 0-based channel index (channel 1 = 0, channel 2 = 1, ...)
   * @param {boolean} on
   *
   * Packet structure CONFIRMED via live PacketLogger capture against a real P1S 12-gang panel
   * (see MICTUNING_BLE_Protocol.md section 2). 7 bytes: [0xf5, byte1..byte6], where each of the
   * 6 data bytes covers 2 channels via nibbles (high nibble = first channel of the pair, low
   * nibble = second). All-zero except the one nibble being set.
   */
  async setChannel(channelIndex, on) {
    if (!this.writeChar) throw new Error('Not connected. Call connect() first.');

    const packet = new Uint8Array(7);
    packet[0] = 0xf5;

    const pairIndex = Math.floor(channelIndex / 2); // which data byte (0-5)
    const isHighNibble = channelIndex % 2 === 0; // even index (channel 1,3,5...) = high nibble
    if (pairIndex > 5) throw new Error(`Channel index ${channelIndex} out of range (this packet supports 12 channels, indices 0-11).`);

    if (on) {
      packet[1 + pairIndex] = isHighNibble ? 0x10 : 0x01;
    }
    // OFF is implicitly all-zero -- confirmed by capture, no explicit "off" marker needed.

    this._channelState[channelIndex] = on;

    await this.writeChar.writeValueWithoutResponse(packet);
  }

  /** All On / All Off, using the dedicated 0xf6 opcode (8 bytes), confirmed via live capture. */
  async setAll(on) {
    if (!this.writeChar) throw new Error('Not connected. Call connect() first.');
    const packet = new Uint8Array(8);
    packet[0] = 0xf6;
    packet[1] = on ? 0x01 : 0x00;
    await this.writeChar.writeValueWithoutResponse(packet);
  }

  /** Sends the panel-wide status query (hex "F800") used by the app's checkP2cStatus(). */
  async requestStatus() {
    if (!this.writeChar) throw new Error('Not connected. Call connect() first.');
    await this.writeChar.writeValueWithoutResponse(new Uint8Array([0xf8, 0x00]));
  }

  /**
   * EXPERIMENTAL: turns the panel's master power state on/off, using the 0xf9 (on) / 0xf8 (off)
   * opcode pair. This is a hypothesis being tested live -- the official app appears to
   * auto-enable the panel's master state whenever any channel is toggled, which our simple
   * per-channel 0xf5 write doesn't do on its own. If this works, the panel's status LED should
   * light up correctly without needing the physical master button.
   */
  async setMasterPower(on) {
    if (!this.writeChar) throw new Error('Not connected. Call connect() first.');
    await this.writeChar.writeValueWithoutResponse(new Uint8Array([on ? 0xf9 : 0xf8, 0x00]));
  }

  _handleNotify(dataView) {
    const bytes = new Uint8Array(dataView.buffer);
    const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join('');

    // Best-effort parse per the reverse-engineered status layout. This section is the least
    // confidently verified part of the protocol -- see MICTUNING_BLE_Protocol.md section 4.
    let panelOn = null;
    let channels = [];
    try {
      const statusNibble = hex.substring(2, 4); // "F8" or "F9"
      panelOn = statusNibble === 'F9' ? true : statusNibble === 'F8' ? false : null;

      // One hex char per channel, starting at offset 4, up to 12 channels.
      const channelField = hex.substring(4, 16);
      channels = channelField.split('').map((c) => c !== '0');
    } catch (err) {
      // Parsing is best-effort; fall through with whatever we got.
    }

    const status = { connected: true, panelOn, channels, raw: hex };
    this._statusListeners.forEach((cb) => cb(status));
  }
}

// Export for both <script type="module"> and plain <script> usage.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { MictuningPanel, SERVICE_UUID, CHAR_FFFA, CHAR_FFF1 };
} else {
  window.MictuningPanel = MictuningPanel;
}
