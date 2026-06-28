/**
 * victron-ble.js  --  VERSION 7 (diagnostic build)
 *
 * Web Bluetooth client for Victron "Instant Readout" BLE advertisements (SmartSolar MPPT,
 * SmartShunt, BMV, etc). Victron devices broadcast their (encrypted) status in BLE
 * advertisement packets every ~1 second; any nearby listener can read them without pairing.
 *
 * WHY v7 EXISTS
 * On Bluefy/iOS the manufacturer-data section has not been appearing in the advertisement
 * event (every ad logs mfgDataKeys=[]). v6 dumped the raw event once and then called
 * stopWatching() -- but on Bluefy stopWatching() does NOT stop the advertisement stream, so the
 * one-time dump got instantly buried under hundreds of later log lines and could never be read.
 *
 * v7 fixes the diagnosis path:
 *   1. The first-advertisement dump is delivered via a dedicated onDump() callback so the test
 *      page can render it in its own fixed, copyable panel (never buried in the scrolling log).
 *   2. After the dump we DO NOT spam one line per advertisement. Instead onStatus() fires with
 *      running counters (ads seen / Victron ads seen / last rssi) that the page updates in place.
 *   3. The dump deep-inspects event.manufacturerData and event.serviceData every possible way
 *      (Map, plain object, iterator, get(737)/get(0x2e1), for..in, DataView byte contents), so we
 *      can see exactly where -- if anywhere -- Bluefy is putting the data.
 *
 * Protocol: officially documented by Victron, AES-128-CTR encrypted, manufacturer ID 0x02E1.
 * Mirrors keshavdv/victron-ble (Python) + node-red-contrib-victron-ble (TS), ported to Web Crypto.
 *
 * Get your device's encryption key from VictronConnect:
 *   Settings > Product Info > Instant Readout via Bluetooth > Show (under "Instant Readout Details")
 */

/** Bluefy on iOS may not return event.manufacturerData as a real JS Map (no .forEach/.get),
 *  unlike desktop Chrome which follows the spec's BluetoothManufacturerDataMap. These helpers
 *  work with either shape. */
function mfgDataKeys(manufacturerData) {
  var keys = [];
  if (!manufacturerData) return keys;
  if (typeof manufacturerData.forEach === 'function') {
    manufacturerData.forEach(function (value, key) { keys.push(key); });
    return keys;
  }
  if (typeof manufacturerData.keys === 'function') {
    try {
      var it = manufacturerData.keys();
      var item = it.next();
      while (!item.done) { keys.push(item.value); item = it.next(); }
      return keys;
    } catch (e) { /* fall through */ }
  }
  for (var k in manufacturerData) {
    if (Object.prototype.hasOwnProperty.call(manufacturerData, k)) keys.push(k);
  }
  return keys;
}

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

/** Hex-dump any buffer-ish value. */
function vbHex(buf) {
  var u;
  if (buf instanceof Uint8Array) u = buf;
  else if (buf && buf.buffer) u = new Uint8Array(buf.buffer);
  else if (buf instanceof ArrayBuffer) u = new Uint8Array(buf);
  else return '(not a buffer)';
  var s = '';
  for (var i = 0; i < u.length; i++) s += u[i].toString(16).padStart(2, '0') + ' ';
  return s.trim();
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
    this._adsSeen = 0;
    this._victronAdsSeen = 0;
    this._cryptoKeyPromise = this.encryptionKey ? this._importKey(this.encryptionKey) : null;
  }

  /** Meaningful diagnostics only (key-check, decrypt, parse, errors) -- NOT one-per-advertisement. */
  onDebug(callback) { this._debugListeners.push(callback); }
  _debug(msg) {
    console.log('[VictronBLE]', msg);
    this._debugListeners.forEach(function (cb) { cb(msg); });
  }

  /** Fires ONCE with the full first-advertisement event dump (a multi-line string). The test page
   *  should render this in its own panel so it can't scroll away. */
  onDump(callback) { this._dumpListeners.push(callback); }

  /** Fires ~once per second with running counters so the page can show progress without flooding:
   *  cb({ adsSeen, victronAdsSeen, lastRssi, lastName }). */
  onStatus(callback) { this._statusListeners.push(callback); }

  /** Register a callback for parsed readings: cb({ deviceType, ...fields }) */
  onReading(callback) { this._readingListeners.push(callback); }

  /** Opens the OS Bluetooth device picker and starts watching advertisements. acceptAllDevices
   *  because Victron doesn't reliably expose a filterable service UUID; optionalManufacturerData
   *  requests the 0x02E1 company id so the browser is allowed to expose it (spec privacy gate). */
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
        'version from the App Store -- manufacturer-data forwarding was fixed in newer builds.'
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

  /** Update the encryption key after construction. */
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

  /** Build a thorough, human-readable dump of the first advertisement event. */
  _buildEventDump(event) {
    var lines = [];
    lines.push('=== FIRST-ADVERTISEMENT EVENT DUMP (v7) ===');

    var ownKeys = [];
    try { ownKeys = Object.keys(event); } catch (e) {}
    var protoKeys = [];
    try { protoKeys = Object.getOwnPropertyNames(Object.getPrototypeOf(event)); } catch (e) {}
    lines.push('own keys: [' + ownKeys.join(',') + ']');
    lines.push('prototype keys: [' + protoKeys.join(',') + ']');

    // Every readable scalar/other property (manufacturerData / serviceData handled separately).
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

    this._inspectDataMap(lines, 'event.manufacturerData', event.manufacturerData, 0x02e1, 737);
    this._inspectDataMap(lines, 'event.serviceData', event.serviceData, null, null);

    lines.push('=== END DUMP ===');
    return lines.join('\n');
  }

  /** Deep-inspect a Map-or-object data map (manufacturerData / serviceData), trying every access
   *  method, so we can see exactly how Bluefy structures it. */
  _inspectDataMap(lines, label, m, idA, idB) {
    lines.push('--- ' + label + ' ---');
    if (m === null || m === undefined) { lines.push('  (null/undefined -- not present in event)'); return; }
    lines.push('  typeof=' + (typeof m) + ' constructor=' + ((m.constructor && m.constructor.name) || '?'));
    lines.push('  instanceof Map: ' + (m instanceof Map) + (m instanceof Map ? (' size=' + m.size) : ''));
    try { lines.push('  Object.keys=[' + Object.keys(m).join(',') + ']'); } catch (e) { lines.push('  Object.keys error: ' + e.message); }
    try { lines.push('  getOwnPropertyNames=[' + Object.getOwnPropertyNames(m).join(',') + ']'); } catch (e) {}

    if (typeof m.forEach === 'function') {
      try {
        var fe = [];
        m.forEach(function (v, k) { fe.push(k + ' => ' + vbDescribe(v)); });
        lines.push('  forEach: ' + (fe.length ? fe.join('  |  ') : '(no entries)'));
      } catch (e) { lines.push('  forEach error: ' + e.message); }
    }
    if (typeof m.entries === 'function') {
      try {
        var es = [];
        var it = m.entries();
        var r = it.next();
        while (!r.done) { es.push(r.value[0] + ' => ' + vbDescribe(r.value[1])); r = it.next(); }
        lines.push('  entries(): ' + (es.length ? es.join('  |  ') : '(no entries)'));
      } catch (e) { lines.push('  entries() error: ' + e.message); }
    }
    var fin = [];
    for (var k in m) fin.push(k);
    lines.push('  for..in keys=[' + fin.join(',') + ']');

    // Direct lookups for the Victron company id, both numeric and string forms.
    if (idA !== null) {
      var tries = [idA, idB, String(idA), String(idB), '0x' + idA.toString(16)];
      for (var t = 0; t < tries.length; t++) {
        var key = tries[t];
        var got = null;
        try { got = (typeof m.get === 'function') ? m.get(key) : undefined; } catch (e) {}
        if (got === undefined || got === null) { try { got = m[key]; } catch (e2) {} }
        lines.push('  lookup[' + key + '] = ' + vbDescribe(got));
      }
    }
  }

  async _handleAdvertisement(event) {
    try {
      this._adsSeen++;

      // First advertisement: capture the full dump, deliver it to the dedicated panel, keep going.
      if (!this._dumpedEventOnce) {
        this._dumpedEventOnce = true;
        var dump = this._buildEventDump(event);
        this._dumpListeners.forEach(function (cb) { cb(dump); });
      }

      var mfgKeys = mfgDataKeys(event.manufacturerData);

      // Quietly push counters so the page can show progress without flooding the log.
      var self = this;
      var lastName = (event.device && event.device.name) || (this.device && this.device.name) || '?';
      this._statusListeners.forEach(function (cb) {
        cb({ adsSeen: self._adsSeen, victronAdsSeen: self._victronAdsSeen, lastRssi: event.rssi, lastName: lastName });
      });

      if (!mfgKeys.length) {
        return; // no manufacturer data this round -- counters already updated, no log spam
      }

      if (!this.encryptionKey) {
        this._debug('Manufacturer data present (keys=[' + mfgKeys.join(',') + ']) but no encryption key set yet.');
        return;
      }

      var mfgData = mfgDataGet(event.manufacturerData, 0x02e1);
      if (!mfgData) {
        this._debug('Advertisement has manufacturer data keys=[' + mfgKeys.join(',') + '] but none for Victron id 0x02E1.');
        return;
      }

      this._victronAdsSeen++;
      var bytes = new Uint8Array(mfgData.buffer || mfgData);
      this._debug('Victron mfg data (' + bytes.length + ' bytes): ' + vbHex(bytes));

      if (bytes.length < 9) { this._debug('Mfg data too short (' + bytes.length + ' bytes, need >= 9).'); return; }

      var recordType = bytes[2];
      if (recordType !== 0x10) { this._debug('Record type 0x' + recordType.toString(16) + ' is not 0x10 (Instant Readout).'); return; }

      var nonceLow = bytes[5];
      var nonceHigh = bytes[6];
      var keyCheck = bytes[7];

      if (keyCheck !== this.encryptionKey[0]) {
        this._debug(
          'KEY-CHECK MISMATCH: got 0x' + keyCheck.toString(16).padStart(2, '0') +
          ', expected 0x' + this.encryptionKey[0].toString(16).padStart(2, '0') +
          ' -- re-copy the key from VictronConnect (Product Info > Instant Readout via Bluetooth > Show).'
        );
        return;
      }
      this._debug('Key-check matched (0x' + keyCheck.toString(16).padStart(2, '0') + ') -- decrypting...');

      var encrypted = bytes.slice(8);
      var decrypted = await this._decrypt(encrypted, nonceLow, nonceHigh);
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

  async _decrypt(encryptedBytes, nonceLow, nonceHigh) {
    var key = await this._cryptoKeyPromise;
    var counter = new Uint8Array(16);
    counter[0] = nonceLow;
    counter[1] = nonceHigh;
    var result = await crypto.subtle.decrypt(
      { name: 'AES-CTR', counter: counter, length: 128 },
      key,
      encryptedBytes
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

console.log('>>> victron-ble.js VERSION 7 LOADED <<<');
if (typeof window !== 'undefined') {
  window.__VICTRON_BLE_VERSION__ = 7;
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
