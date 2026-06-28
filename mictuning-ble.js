/**
 * mictuning-ble.js
 *
 * Web Bluetooth client for MICTUNING P2C-family switch panels (P2C8 / P2C8A / P2C8B /
 * P2C12 / P2C12A / P2C6A / P2C6B and similar gang-count variants, including the P1S 12-gang
 * panel this was confirmed against).
 *
 * Protocol reverse-engineered via static analysis of the MICTUNING Android app
 * (com.qunchen.headlightSpp v3.6.16), then CORRECTED and CONFIRMED via a live Apple
 * PacketLogger capture against a real P1S 12-gang panel. See MICTUNING_BLE_Protocol.md
 * alongside this file for the full writeup.
 *
 * CONFIRMED via live capture:
 *   - Plain on/off uses a 7-byte 0xf5 packet. Each of the 6 data bytes covers 2 channels via
 *     nibbles: high nibble = the lower-numbered channel of the pair (0x10 = on), low nibble =
 *     the higher-numbered channel of the pair (0x01 = on). All-zero byte = both channels off.
 *     Channel 1 ON  = f5 10 00 00 00 00 00
 *     Channel 2 ON  = f5 01 00 00 00 00 00
 *     Channel 3 ON  = f5 00 10 00 00 00 00
 *     Channel 4 ON  = f5 00 01 00 00 00 00
 *     ...and so on, two channels per data byte.
 *   - All On / All Off uses a dedicated 8-byte 0xf6 opcode, separate from per-channel toggling.
 *
 * NOT YET CONFIRMED (parked for later polish):
 *   - The panel's physical LED indicator only lights up when a "master power" state is
 *     enabled. The official app appears to send this automatically whenever any channel is
 *     toggled; this client does NOT do that yet, so the LED may not light even though the
 *     relay itself switches correctly. setMasterPower() below is an experimental, untested
 *     attempt at this (hypothesized 0xf9 00 = master ON, 0xf8 00 = master OFF/query) -- it is
 *     NOT wired into the test page automatically. Leave it alone until you want to test it.
 *
 * Requires a browser with navigator.bluetooth -- on iPad/iPhone this means the Bluefy browser
 * (Safari itself has zero Web Bluetooth support, by Apple design, with no plan to change).
 *
 * Usage:
 *   const panel = new MictuningPanel();
 *   await panel.connect();              // prompts the OS BLE device picker
 *   await panel.setChannel(0, true);    // turn channel 1 ON (0-based index)
 *   await panel.setChannel(0, false);   // turn channel 1 OFF
 *   panel.onStatus(function(status) { ... });          // live status notifications
 *   panel.onConnectionChange(function(state) { ... }); // connect/disconnect/reconnect events
 */

const SERVICE_UUID = '0003cbbb-0000-1000-8000-00805f9bfff0';
const CHAR_FFF1 = '0003cbbb-0000-1000-8000-00805f9bfff1'; // notify (status)
const CHAR_FFFA = '0003cbbb-0000-1000-8000-00805f9bfffa'; // write (commands)

class MictuningPanel {
  constructor(opts) {
    opts = opts || {};

    this.device = null;
    this.server = null;
    this.service = null;
    this.writeChar = null;
    this.notifyChar = null;

    this._statusListeners = [];
    this._connectionListeners = [];
    this._channelState = []; // 0-based index -> boolean, last commanded state

    // --- Auto-reconnect state ---
    this._autoReconnect = opts.autoReconnect !== false; // on by default
    this._reconnecting = false;
    this._wantConnected = false;
    this._reconnectDelayMs = 1500;
    this._maxReconnectDelayMs = 15000;

    var self = this;
    if (this._autoReconnect && typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', function () {
        if (document.visibilityState === 'visible') self._attemptReconnectIfNeeded();
      });
    }
  }

  /** Opens the OS Bluetooth device picker, filtered to this panel's service UUID.
   *  This is the only step that needs a fresh user gesture -- reconnects happen silently. */
  async connect() {
    if (!navigator.bluetooth) {
      throw new Error(
        'Web Bluetooth is not available. On iPad/iPhone, open this page inside the ' +
        'Bluefy browser app (Safari does not support Web Bluetooth).'
      );
    }

    var self = this;

    this.device = await navigator.bluetooth.requestDevice({
      filters: [{ services: [SERVICE_UUID] }],
      optionalServices: [SERVICE_UUID],
    });

    this.device.addEventListener('gattserverdisconnected', function () {
      self._onDisconnected();
    });

    await this._setupConnection();
    this._wantConnected = true;

    return this.device.name || 'MICTUNING panel';
  }

  /** Internal: does the actual GATT connect + service/characteristic setup. Shared between
   *  the initial connect() and silent auto-reconnect attempts. */
  async _setupConnection() {
    var self = this;

    this.server = await this.device.gatt.connect();
    this.service = await this.server.getPrimaryService(SERVICE_UUID);
    this.writeChar = await this.service.getCharacteristic(CHAR_FFFA);

    // Subscribe to notifications for status updates, if available.
    try {
      this.notifyChar = await this.service.getCharacteristic(CHAR_FFF1);
      await this.notifyChar.startNotifications();
      this.notifyChar.addEventListener('characteristicvaluechanged', function (event) {
        self._handleNotify(event.target.value);
      });
    } catch (err) {
      console.warn('Could not subscribe to FFF1 notifications -- status updates unavailable.', err);
    }

    this._connectionListeners.forEach(function (cb) {
      cb({ connected: true, reconnected: self._reconnecting });
    });
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
    this._statusListeners.forEach(function (cb) { cb({ connected: false }); });
    this._connectionListeners.forEach(function (cb) { cb({ connected: false }); });

    if (this._autoReconnect && this._wantConnected) {
      this._scheduleReconnect();
    }
  }

  _scheduleReconnect(delay) {
    delay = delay || this._reconnectDelayMs;
    if (this._reconnecting) return;
    this._reconnecting = true;
    var self = this;
    setTimeout(function () { self._attemptReconnectIfNeeded(delay); }, delay);
  }

  async _attemptReconnectIfNeeded(lastDelay) {
    lastDelay = lastDelay || this._reconnectDelayMs;

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

    var self = this;
    try {
      await this._setupConnection();
      console.log('MICTUNING panel: reconnected.');
      this._reconnecting = false;
    } catch (err) {
      console.warn('MICTUNING panel: reconnect attempt failed, will retry.', err);
      var nextDelay = Math.min(lastDelay * 1.6, this._maxReconnectDelayMs);
      setTimeout(function () { self._attemptReconnectIfNeeded(nextDelay); }, nextDelay);
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
   * (see MICTUNING_BLE_Protocol.md). 7 bytes: [0xf5, byte1..byte6], where each of the 6 data
   * bytes covers 2 channels via nibbles (high nibble = first channel of the pair, low nibble =
   * second). All-zero except the one nibble being set; OFF needs no explicit marker.
   */
  async setChannel(channelIndex, on) {
    if (!this.writeChar) throw new Error('Not connected. Call connect() first.');

    var pairIndex = Math.floor(channelIndex / 2); // which data byte (0-5)
    var isHighNibble = channelIndex % 2 === 0; // even index (channel 1,3,5...) = high nibble
    if (pairIndex > 5) {
      throw new Error('Channel index ' + channelIndex + ' out of range (this packet supports 12 channels, indices 0-11).');
    }

    var packet = new Uint8Array(7);
    packet[0] = 0xf5;
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
    var packet = new Uint8Array(8);
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
   * EXPERIMENTAL / NOT YET CONFIRMED -- turns the panel's master power state on/off, using the
   * hypothesized 0xf9 (on) / 0xf8 (off) opcode pair. The official app appears to auto-enable
   * the panel's master state whenever any channel is toggled, which setChannel() does not do
   * on its own. If this works, the panel's status LED should light up correctly without the
   * physical master button. Not called automatically anywhere in this file -- call it
   * manually if/when you want to test it.
   */
  async setMasterPower(on) {
    if (!this.writeChar) throw new Error('Not connected. Call connect() first.');
    await this.writeChar.writeValueWithoutResponse(new Uint8Array([on ? 0xf9 : 0xf8, 0x00]));
  }

  _handleNotify(dataView) {
    var bytes = new Uint8Array(dataView.buffer);
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0').toUpperCase();
    }

    // Best-effort parse per the reverse-engineered status layout. This section is the least
    // confidently verified part of the protocol -- see MICTUNING_BLE_Protocol.md.
    var panelOn = null;
    var channels = [];
    try {
      var statusNibble = hex.substring(2, 4); // "F8" or "F9"
      panelOn = statusNibble === 'F9' ? true : (statusNibble === 'F8' ? false : null);

      // One hex char per channel, starting at offset 4, up to 12 channels.
      var channelField = hex.substring(4, 16);
      channels = channelField.split('').map(function (c) { return c !== '0'; });
    } catch (err) {
      // Parsing is best-effort; fall through with whatever we got.
    }

    var status = { connected: true, panelOn: panelOn, channels: channels, raw: hex };
    this._statusListeners.forEach(function (cb) { cb(status); });
  }
}

// Export for both <script type="module"> and plain <script> usage.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { MictuningPanel: MictuningPanel, SERVICE_UUID: SERVICE_UUID, CHAR_FFFA: CHAR_FFFA, CHAR_FFF1: CHAR_FFF1 };
} else {
  window.MictuningPanel = MictuningPanel;
}
