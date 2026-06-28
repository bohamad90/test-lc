/**
 * victron-ble.js  --  VERSION 8
 *
 * Web Bluetooth client for Victron "Instant Readout" BLE advertisements (SmartSolar MPPT,
 * SmartShunt, BMV, etc). Victron devices broadcast their (encrypted) status in BLE
 * advertisement packets every ~1 second; any nearby listener can read them without pairing.
 *
 * WHAT v8 FIXES (two real bugs found via the v7 on-device event dump)
 *
 *   BUG 1 -- the data shape. On desktop Chrome, event.manufacturerData is a Map keyed by company
 *   id (so .get(0x02E1) works). On Bluefy/iOS it is instead a SINGLE raw DataView holding the
 *   manufacturer-specific data directly -- not a Map, no keys, no .get(). The old code asked that
 *   DataView for Map keys, got [], and concluded "no Victron data" on every advertisement even
 *   though the bytes were right there. v8 reads the DataView directly (and still supports the
 *   Map shape on Chrome).
 *
 *   BUG 2 -- the frame offsets. The previous framing was off by 2 bytes versus the reference
 *   implementation (keshavdv/victron-ble) and would never have decrypted. The correct layout of
 *   the manufacturer-data VALUE (the bytes WITHOUT the 2-byte company id) is:
 *       value[0:2]  prefix    (uint16 LE, 0x0010 -- low byte 0x10 marks an Instant Readout)
 *       value[2:4]  model id  (uint16 LE)
 *       value[4]    readout type
 *       value[5:7]  IV/nonce  (uint16 LE -- the AES-CTR counter initial value)
 *       value[7]    key-check byte (must equal the first byte of the encryption key)
 *       value[8:]   AES-128-CTR encrypted payload
 *
 * v8 also ALWAYS logs the raw value bytes for the first Victron-bearing advertisement, so if
 * anything is still off we can see the exact bytes and finish the job.
 *
 * Encryption key: VictronConnect > device gear > Product Info > Instant Readout via Bluetooth > Show.
 */

/** Convert any buffer-ish value (DataView / TypedArray / ArrayBuffer) to a Uint8Array,
 *  respecting byteOffset/byteLength. Returns null if it isn't buffer-ish. */
function vbToU8(v) {
  if (!v) return null;
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (typeof v.byteLength === 'number' && v.buffer) {
    return new Uint8Array(v.buffer, v.byteOffset || 0, v.byteLength);
  }
  return null;
}

/** Hex-dump any buffer-ish value. */
function vbHex(buf) {
  var u = vbToU8(buf);
  if (!u) return '(not a buffer)';
  var s = '';
  for (var i = 0; i < u.length; i++) s += u[i].toString(16).padStart(2, '0') + ' ';
  return s.trim();
}

/** Map-shape helper kept for desktop Chrome: pull the 0x02E1 value out of a real Map. */
function mfgDataGet(manufacturerData, id) {
  if (!manufacturerData) return null;
  if (typeof manufacturerData.get === 'function') {
    var viaGet = manufacturerData.get(id);
    if (viaGet !== undefined && viaGet !== null) return viaGet;
  }
  if (manufacturerData[id] !== undefined) return manufacturerData[id];
  if (manufacturerData[String(id)] !== undefined) return manufacturerData[String(id)];
  return null;
}

/** Human description of any value, for the diagnostic dump. */
function vbDescribe(v) {
  if (v === null) return 'null';
  if (v === undefined) return 'undefined';
  var t = typeof v;
  if (t === 'function') return '[function]';
  if (t === 'number' || t === 'boolean' || t === 'string') return t + ': ' + v;
  var cname = (v.constructor && v.constructor.name) || '?';
  if (v instanceof ArrayBuffer) return 'ArrayBuffer(' + v.byteLength + '): ' + vbHex(v);
  if (cname.indexOf('DataView') >= 0) return 'DataView(' + v.byteLength + '): ' + vbHex(v);
  if (typeof ArrayBuffer.isView === 'function' && ArrayBuffer.isView(v)) {
    return cname + '(' + v.length + '): ' + vbHex(v);
  }
  if (v instanceof Map) {
    var parts = [];
    v.forEach(function (val, key) { parts.push(key + ' => ' + vbDescribe(val)); });
    return 'Map(size=' + v.size + ') { ' + parts.join(', ') + ' }';
  }
  if (t === 'object') {
    var ks = [];
    try { ks = Object.keys(v); } catch (e) {}
    var js;
    try { js = JSON.stringify(v); } catch (e2) { js = '[unstringifiable]'; }
    return cname + ' keys=[' + ks.join(',') + '] json=' + js;
  }
  return String(v);
}

class VictronBLE {
  constructor(opts) {
    opts = opts || {};
    this.encryptionKey = opts.encryptionKey ? this._hexToBytes(opts.encryptionKey) : null;
    this.device = null;
    this._readingListeners = [];
    this._debugListeners = [];
    this._dumpListeners = [];
    this._statusListeners = [];
    this._dumpedEventOnce = false;
    this._loggedRawOnce = false;
    this._adsSeen = 0;
    this._victronAdsSeen = 0;
    this._cryptoKeyPromise = this.encryptionKey ? this._importKey(this.encryptionKey) : null;
  }

  onDebug(callback) { this._debugListeners.push(callback); }
  _debug(msg) {
    console.log('[VictronBLE]', msg);
    this._debugListeners.forEach(function (cb) { cb(msg); });
  }

  /** Fires ONCE with the full first-advertisement event dump (multi-line string). */
  onDump(callback) { this._dumpListeners.push(callback); }

  /** Fires ~once/sec with counters: cb({ adsSeen, victronAdsSeen, lastRssi, lastName }). */
  onStatus(callback) { this._statusListeners.push(callback); }

  /** Register a callback for parsed readings: cb({ deviceType, ...fields }) */
  onReading(callback) { this._readingListeners.push(callback); }

  async addDevice() {
    if (!navigator.bluetooth) {
      throw new Error(
        'Web Bluetooth is not available. On iPad/iPhone, open this page inside the ' +
        'Bluefy browser app (Safari does not support Web Bluetooth).'
      );
    }
    if (typeof navigator.bluetooth.requestDevice !== 'function') {
      throw new Error('navigator.bluetooth.requestDevice is not available in this browser.');
    }

    var self = this;

    this.device = await navigator.bluetooth.requestDevice({
      acceptAllDevices: true,
      optionalManufacturerData: [0x02e1],
    });

    if (typeof this.device.watchAdvertisements !== 'function') {
      throw new Error(
        'This browser does not support watchAdvertisements(). Update Bluefy to the latest ' +
        'version from the App Store.'
      );
    }

    this.device.addEventListener('advertisementreceived', function (event) {
      self._handleAdvertisement(event);
    });
    await this.device.watchAdvertisements();

    return this.device.name || 'Victron device';
  }

  stopWatching() {
    if (this.device && typeof this.device.unwatchAdvertisements === 'function') {
      try { this.device.unwatchAdvertisements(); } catch (e) {}
    }
  }

  async setEncryptionKey(hexKey) {
    this.encryptionKey = this._hexToBytes(hexKey);
    this._cryptoKeyPromise = this._importKey(this.encryptionKey);
  }

  _hexToBytes(hex) {
    var clean = hex.replace(/[^0-9a-fA-F]/g, '');
    var bytes = new Uint8Array(clean.length / 2);
    for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
    return bytes;
  }

  async _importKey(keyBytes) {
    return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CTR' }, false, ['decrypt']);
  }

  /**
   * Returns the Victron manufacturer-data VALUE (bytes WITHOUT the 2-byte company id) as a
   * Uint8Array, or null. Handles both the Chrome Map shape and the Bluefy single-DataView shape.
   */
  _extractVictronValue(manufacturerData) {
    if (!manufacturerData) return null;

    // Chrome / spec shape: a real Map keyed by company id. .get(0x02E1) yields the value already
    // stripped of the company id (so it starts at the 0x10 prefix byte).
    if (manufacturerData instanceof Map ||
        (typeof manufacturerData.get === 'function' && typeof manufacturerData.forEach === 'function')) {
      var fromMap = vbToU8(mfgDataGet(manufacturerData, 0x02e1));
      return fromMap && fromMap.length ? fromMap : null;
    }

    // Bluefy shape: a single DataView holding the manufacturer-specific data directly.
    var u = vbToU8(manufacturerData);
    if (!u || !u.length) return null;
    // Strip the company id prefix if Bluefy includes it (E1 02 == 0x02E1 little-endian).
    if (u.length >= 2 && u[0] === 0xe1 && u[1] === 0x02) return u.subarray(2);
    return u;
  }

  _buildEventDump(event) {
    var lines = [];
    lines.push('=== FIRST-ADVERTISEMENT EVENT DUMP (v8) ===');

    var ownKeys = [];
    try { ownKeys = Object.keys(event); } catch (e) {}
    var protoKeys = [];
    try { protoKeys = Object.getOwnPropertyNames(Object.getPrototypeOf(event)); } catch (e) {}
    lines.push('own keys: [' + ownKeys.join(',') + ']');
    lines.push('prototype keys: [' + protoKeys.join(',') + ']');

    var all = ownKeys.concat(protoKeys);
    for (var i = 0; i < all.length; i++) {
      var name = all[i];
      if (name === 'manufacturerData' || name === 'serviceData') continue;
      try {
        var val = event[name];
        if (typeof val === 'function') continue;
        lines.push('event.' + name + ' = ' + vbDescribe(val));
      } catch (e3) {
        lines.push('event.' + name + ' -- error reading: ' + e3.message);
      }
    }

    this._inspectDataMap(lines, 'event.manufacturerData', event.manufacturerData);
    this._inspectDataMap(lines, 'event.serviceData', event.serviceData);

    // Also show what we actually extracted as the Victron value.
    var value = this._extractVictronValue(event.manufacturerData);
    lines.push('--- extracted Victron value ---');
    lines.push(value ? ('  bytes (' + value.length + '): ' + vbHex(value)) : '  (none extracted)');

    lines.push('=== END DUMP ===');
    return lines.join('\n');
  }

  _inspectDataMap(lines, label, m) {
    lines.push('--- ' + label + ' ---');
    if (m === null || m === undefined) { lines.push('  (null/undefined -- not present in event)'); return; }
    lines.push('  typeof=' + (typeof m) + ' constructor=' + ((m.constructor && m.constructor.name) || '?'));
    lines.push('  instanceof Map: ' + (m instanceof Map) + (m instanceof Map ? (' size=' + m.size) : ''));

    // If it's actually a buffer (Bluefy), dump the bytes -- this is the part v7 was missing.
    var asU8 = vbToU8(m);
    if (asU8) lines.push('  RAW BYTES (' + asU8.length + '): ' + vbHex(asU8));

    try { lines.push('  Object.keys=[' + Object.keys(m).join(',') + ']'); } catch (e) {}
    if (typeof m.forEach === 'function') {
      try {
        var fe = [];
        m.forEach(function (v, k) { fe.push(k + ' => ' + vbDescribe(v)); });
        lines.push('  forEach: ' + (fe.length ? fe.join('  |  ') : '(no entries)'));
      } catch (e) { lines.push('  forEach error: ' + e.message); }
    }
  }

  async _handleAdvertisement(event) {
    try {
      this._adsSeen++;

      if (!this._dumpedEventOnce) {
        this._dumpedEventOnce = true;
        var dump = this._buildEventDump(event);
        this._dumpListeners.forEach(function (cb) { cb(dump); });
      }

      var value = this._extractVictronValue(event.manufacturerData);

      var self = this;
      var lastName = (event.device && event.device.name) || (this.device && this.device.name) || '?';
      this._statusListeners.forEach(function (cb) {
        cb({ adsSeen: self._adsSeen, victronAdsSeen: self._victronAdsSeen, lastRssi: event.rssi, lastName: lastName });
      });

      if (!value || !value.length) {
        return; // nothing usable this round -- counters updated, no log spam
      }

      this._victronAdsSeen++;

      // Always show the first real value so we can verify the frame even if parsing is off.
      if (!this._loggedRawOnce) {
        this._loggedRawOnce = true;
        this._debug('First Victron value bytes (' + value.length + '): ' + vbHex(value));
      }

      if (!this.encryptionKey) { this._debug('Have Victron value but no encryption key set yet.'); return; }
      if (value.length < 9) { this._debug('Victron value too short (' + value.length + ' bytes, need >= 9).'); return; }
      if (value[0] !== 0x10) { this._debug('Prefix byte is 0x' + value[0].toString(16) + ', not 0x10 (not an Instant Readout record).'); return; }

      var ivLow = value[5];
      var ivHigh = value[6];
      var keyCheck = value[7];

      if (keyCheck !== this.encryptionKey[0]) {
        this._debug(
          'KEY-CHECK MISMATCH: got 0x' + keyCheck.toString(16).padStart(2, '0') +
          ', expected 0x' + this.encryptionKey[0].toString(16).padStart(2, '0') +
          ' -- re-copy the key from VictronConnect.'
        );
        return;
      }

      var ciphertext = value.subarray(8);
      var decrypted = await this._decrypt(ciphertext, ivLow, ivHigh);
      this._debug('Decrypted (' + decrypted.length + ' bytes): ' + vbHex(decrypted));

      var parsed = this._parsePayload(decrypted);
      if (parsed) {
        this._debug('Parsed OK as ' + parsed.deviceType);
        parsed.deviceName = this.device.name;
        parsed.rssi = event.rssi;
        this._readingListeners.forEach(function (cb) { cb(parsed); });
      } else {
        this._debug('Decryption succeeded but parsing failed both layouts.');
      }
    } catch (err) {
      this._debug('_handleAdvertisement error: ' + err.message);
    }
  }

  async _decrypt(ciphertextBytes, ivLow, ivHigh) {
    var key = await this._cryptoKeyPromise;
    // 16-bit IV occupies the first two bytes of the 16-byte CTR counter block, little-endian.
    var counter = new Uint8Array(16);
    counter[0] = ivLow;
    counter[1] = ivHigh;
    var result = await crypto.subtle.decrypt(
      { name: 'AES-CTR', counter: counter, length: 128 },
      key,
      ciphertextBytes
    );
    return new Uint8Array(result);
  }

  _parsePayload(data) {
    // --- Solar Charger (MPPT) layout ---
    try {
      var reader = new BitReader(data);
      var deviceState = reader.readUint(8);
      var chargerError = reader.readUint(8);
      var batteryVoltageRaw = reader.readInt(16);
      var batteryCurrentRaw = reader.readInt(16);
      var yieldTodayRaw = reader.readUint(16);
      var pvPowerRaw = reader.readUint(16);
      var loadCurrentRaw = reader.readUint(9);

      var batteryVoltage = batteryVoltageRaw / 100;
      var batteryCurrent = batteryCurrentRaw / 10;

      if (batteryVoltage > 5 && batteryVoltage < 100) {
        return {
          deviceType: 'solar_charger',
          deviceState: deviceState,
          deviceStateName: VictronBLE.CHARGER_STATES[deviceState] || ('Unknown (' + deviceState + ')'),
          chargerError: chargerError,
          batteryVoltage: batteryVoltage,
          batteryCurrent: batteryCurrent,
          yieldToday: yieldTodayRaw / 100,
          pvPower: pvPowerRaw,
          loadCurrent: loadCurrentRaw / 10,
        };
      }
    } catch (e) { /* fall through */ }

    // --- Battery Monitor (SmartShunt/BMV) layout ---
    try {
      var reader2 = new BitReader(data);
      var auxMode = reader2.readUint(2);
      reader2.skip(14);
      var voltageRaw = reader2.readInt(16);
      reader2.skip(16);
      reader2.skip(16);
      var currentRaw = reader2.readInt(22);
      var consumedAhRaw = reader2.readUint(20);
      var socRaw = reader2.readUint(10);

      var voltage = voltageRaw / 100;
      var current = currentRaw / 1000;
      var soc = socRaw / 10;

      if (voltage > 5 && voltage < 100 && soc >= 0 && soc <= 100) {
        return {
          deviceType: 'battery_monitor',
          auxMode: auxMode,
          voltage: voltage,
          current: current,
          consumedAh: consumedAhRaw / 10,
          soc: soc,
        };
      }
    } catch (e) { /* both layouts failed */ }

    console.warn('VictronBLE: could not parse as solar charger or battery monitor. Raw:', vbHex(data));
    return null;
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { VictronBLE: VictronBLE };
} else {
  window.VictronBLE = VictronBLE;
}

console.log('>>> victron-ble.js VERSION 8 LOADED <<<');
if (typeof window !== 'undefined') {
  window.__VICTRON_BLE_VERSION__ = 8;
}

VictronBLE.CHARGER_STATES = {
  0: 'Off', 1: 'Low power', 2: 'Fault', 3: 'Bulk', 4: 'Absorption', 5: 'Float',
  6: 'Storage', 7: 'Equalize (manual)', 9: 'Inverting', 11: 'Power supply',
  245: 'Starting-up', 246: 'Repeated absorption', 247: 'Auto equalize / recondition',
  248: 'BatterySafe', 252: 'External control',
};

/** Reads variable-width little-endian bit fields (Victron packs sub-byte fields back to back). */
class BitReader {
  constructor(bytes) { this.bytes = bytes; this.bitPos = 0; }
  skip(bits) { this.bitPos += bits; }
  readUint(bits) {
    var value = 0;
    for (var i = 0; i < bits; i++) {
      var byteIndex = (this.bitPos + i) >> 3;
      var bitIndex = (this.bitPos + i) & 7;
      if (byteIndex >= this.bytes.length) throw new Error('BitReader: out of data');
      var bit = (this.bytes[byteIndex] >> bitIndex) & 1;
      value |= bit << i;
    }
    this.bitPos += bits;
    return value >>> 0;
  }
  readInt(bits) {
    var raw = this.readUint(bits);
    var signBit = 1 << (bits - 1);
    if (raw & signBit) return raw - (1 << bits);
    return raw;
  }
}
