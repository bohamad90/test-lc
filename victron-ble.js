/**
 * victron-ble.js
 *
 * Web Bluetooth client for Victron "Instant Readout" BLE advertisements (SmartSolar MPPT,
 * SmartShunt, BMV, etc). Unlike the MICTUNING/JuncTek clients, this is NOT a GATT
 * connect-and-write client -- Victron devices broadcast their (encrypted) status in BLE
 * advertisement packets every ~1 second, and any nearby listener can read them without
 * pairing or connecting at all. This file just decrypts and parses those broadcasts.
 *
 * Protocol: officially documented by Victron ("Extra manufacturer data" PDF), AES-128-CTR
 * encrypted, manufacturer ID 0x02E1. This implementation mirrors the well-established
 * keshavdv/victron-ble (Python) and node-red-contrib-victron-ble (TypeScript) community
 * implementations, ported to the browser's native Web Crypto API.
 *
 * Confirmed for: SmartSolar MPPT 100/30. This model is a standard "Solar Charger" device
 * class in Victron's Instant Readout spec -- no model-specific quirks.
 *
 * You'll need your device's encryption key first -- get it from the VictronConnect app:
 *   Settings > Product Info > Instant Readout via Bluetooth > Show (under "Instant Readout Details")
 *
 * --- IMPORTANT iOS/Bluefy constraint ---
 * Web Bluetooth's advertisement-watching API (watchAdvertisements) requires a BluetoothDevice
 * object, which can only be obtained via the user-gesture device picker (requestDevice). There
 * is no "scan for any nearby device" API on iOS the way there is with native Core Bluetooth or
 * desktop tools like bleak/noble. So the flow here is:
 *   1. User taps "Add Victron Device" -> opens the OS picker (unfiltered, since Victron
 *      doesn't reliably expose a filterable service UUID in the legacy advertisement)
 *   2. Once picked, we call watchAdvertisements() and listen passively from then on
 *   3. No GATT connection is ever made -- this is a pure listen, which is also why it's very
 *      battery-friendly and immune to the connection-drop issues GATT clients have.
 *
 * Usage:
 *   var victron = new VictronBLE({ encryptionKey: 'a1b2c3...' }); // hex string from VictronConnect
 *   await victron.addDevice();                 // opens device picker once
 *   victron.onReading(function (data) { ... }); // fires on every decrypted advertisement
 */

class VictronBLE {
  constructor(opts) {
    opts = opts || {};
    this.encryptionKey = opts.encryptionKey ? this._hexToBytes(opts.encryptionKey) : null;
    this.device = null;
    this._readingListeners = [];
    this._debugListeners = [];
    this._cryptoKeyPromise = this.encryptionKey ? this._importKey(this.encryptionKey) : null;
  }

  /** Register a callback for low-level diagnostic messages: cb(msg). Fires at every stage of
   *  handling an advertisement -- whether one arrived at all, whether it carried Victron
   *  manufacturer data, key-check pass/fail, decrypt success/failure, parse result. Use this
   *  on the test page to see what's happening on-screen, since console.warn isn't visible on
   *  iOS/Bluefy without a remote debugger attached. */
  onDebug(callback) {
    this._debugListeners.push(callback);
  }

  _debug(msg) {
    console.log('[VictronBLE]', msg);
    this._debugListeners.forEach(function (cb) { cb(msg); });
  }

  /** Opens the OS Bluetooth device picker and starts watching advertisements from the chosen
   *  device. Victron devices don't reliably expose a filterable service UUID in the legacy
   *  advertisement (it's all inside manufacturer data), so acceptAllDevices is the practical
   *  choice -- the person picks their SmartSolar/SmartShunt by name from the list. */
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

    this.device = await navigator.bluetooth.requestDevice({ acceptAllDevices: true });

    if (typeof this.device.watchAdvertisements !== 'function') {
      throw new Error(
        'This browser does not support watchAdvertisements(). Bluefy added this in a recent ' +
        'update -- make sure Bluefy is fully up to date.'
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
      this.device.unwatchAdvertisements();
    }
  }

  /** Register a callback for parsed readings: cb({ deviceType, ...fields }) */
  onReading(callback) {
    this._readingListeners.push(callback);
  }

  /** Update the encryption key after construction (e.g. once the user pastes it in). */
  async setEncryptionKey(hexKey) {
    this.encryptionKey = this._hexToBytes(hexKey);
    this._cryptoKeyPromise = this._importKey(this.encryptionKey);
  }

  _hexToBytes(hex) {
    var clean = hex.replace(/[^0-9a-fA-F]/g, '');
    var bytes = new Uint8Array(clean.length / 2);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  async _importKey(keyBytes) {
    return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CTR' }, false, ['decrypt']);
  }

  async _handleAdvertisement(event) {
    var mfgKeys = [];
    if (event.manufacturerData) {
      event.manufacturerData.forEach(function (value, key) { mfgKeys.push(key); });
    }
    this._debug(
      'Advertisement received from "' + (event.device ? event.device.name : '?') +
      '" rssi=' + event.rssi + ' mfgDataKeys=[' + mfgKeys.join(',') + ']'
    );

    if (!this.encryptionKey) {
      this._debug('No encryption key set yet -- ignoring advertisement. Call setEncryptionKey() first.');
      return;
    }

    // Victron's manufacturer ID is 0x02E1 (737 decimal).
    var mfgData = event.manufacturerData && event.manufacturerData.get(0x02e1);
    if (!mfgData) {
      this._debug('No manufacturer data for ID 0x02E1 in this advertisement -- not a Victron payload this round.');
      return; // not a Victron advertisement, or doesn't carry mfg data this round
    }

    var bytes = new Uint8Array(mfgData.buffer || mfgData);
    var rawHex = '';
    for (var h = 0; h < bytes.length; h++) {
      rawHex += bytes[h].toString(16).padStart(2, '0') + ' ';
    }
    this._debug('Victron mfg data (' + bytes.length + ' bytes): ' + rawHex);

    // Layout per Victron's published spec:
    //   [0:2]  Vendor ID (already matched via manufacturerData key, redundant here)
    //   [2]    Beacon/record type -- 0x10 for "Product Advertisement" (Instant Readout)
    //   [3]    Unknown/version-ish byte
    //   [4]    Device/model state byte (varies per device type)
    //   [5:7]  Nonce / data counter (little-endian uint16) -- used as the AES-CTR counter
    //   [7]    Key-check byte -- should match first byte of your encryption key
    //   [8:]   Encrypted payload
    if (bytes.length < 9) {
      this._debug('Mfg data too short (' + bytes.length + ' bytes, need at least 9) -- skipping.');
      return;
    }

    var recordType = bytes[2];
    if (recordType !== 0x10) {
      this._debug('Record type 0x' + recordType.toString(16) + ' is not 0x10 (Instant Readout) -- skipping.');
      return; // not an Instant Readout record
    }

    var nonceLow = bytes[5];
    var nonceHigh = bytes[6];
    var keyCheck = bytes[7];

    if (keyCheck !== this.encryptionKey[0]) {
      this._debug(
        'KEY-CHECK MISMATCH: got 0x' + keyCheck.toString(16).padStart(2, '0') +
        ', expected 0x' + this.encryptionKey[0].toString(16).padStart(2, '0') +
        ' -- your encryption key is almost certainly wrong for this device. Re-copy it from ' +
        'VictronConnect (Product Info > Instant Readout via Bluetooth > Show).'
      );
      return;
    }
    this._debug('Key-check byte matched (0x' + keyCheck.toString(16).padStart(2, '0') + ') -- decrypting...');

    var encrypted = bytes.slice(8);

    try {
      var decrypted = await this._decrypt(encrypted, nonceLow, nonceHigh);
      var decHex = '';
      for (var d = 0; d < decrypted.length; d++) {
        decHex += decrypted[d].toString(16).padStart(2, '0') + ' ';
      }
      this._debug('Decrypted (' + decrypted.length + ' bytes): ' + decHex);

      var parsed = this._parsePayload(decrypted);
      if (parsed) {
        this._debug('Parsed OK as ' + parsed.deviceType);
        parsed.deviceName = this.device.name;
        parsed.rssi = event.rssi;
        var listeners = this._readingListeners;
        listeners.forEach(function (cb) { cb(parsed); });
      } else {
        this._debug('Decryption succeeded but parsing failed both layouts -- see raw decrypted bytes above.');
      }
    } catch (err) {
      this._debug('Decryption threw an error: ' + err.message);
    }
  }

  async _decrypt(encryptedBytes, nonceLow, nonceHigh) {
    var key = await this._cryptoKeyPromise;
    // Victron's nonce is a 16-bit little-endian counter, zero-padded to a 16-byte CTR counter block.
    var counter = new Uint8Array(16);
    counter[0] = nonceLow;
    counter[1] = nonceHigh;
    // bytes [2..15] remain zero

    var result = await crypto.subtle.decrypt(
      { name: 'AES-CTR', counter: counter, length: 128 },
      key,
      encryptedBytes
    );
    return new Uint8Array(result);
  }

  /**
   * Parses decrypted payload bytes into a readings object. Victron packs multiple small
   * fields per device type using bit-level packing (not byte-aligned), documented per device
   * type in the official PDF. This implementation covers the two most common types for a
   * camper setup: Solar Charger (MPPT) and Battery Monitor (SmartShunt/BMV). Extend as needed
   * for other device types (inverters, DC-DC converters, etc) using the same bit-reader pattern.
   *
   * NOTE: bit offsets below follow the community-verified layout from keshavdv/victron-ble.
   * Treat as a strong first draft -- cross-check against VictronConnect's own readings the
   * first time you run this against your real MPPT 100/30.
   */
  _parsePayload(data) {
    // --- Try Solar Charger (MPPT) layout ---
    // device_state (u8), charger_error (u8), battery_voltage (u16, 0.01V), battery_current (u16, 0.1A),
    // yield_today (u16, 0.01kWh), pv_power (u16, 1W), load_current (u9, 0.1A)
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

      // Sanity check: solar battery voltage for a 12V system should land roughly 8-16V.
      // If this looks wildly wrong, it's likely actually a different device type/layout.
      if (batteryVoltage > 5 && batteryVoltage < 100) {
        return {
          deviceType: 'solar_charger',
          deviceState: deviceState,
          deviceStateName: VictronBLE.CHARGER_STATES[deviceState] || ('Unknown (' + deviceState + ')'),
          chargerError: chargerError,
          batteryVoltage: batteryVoltage,
          batteryCurrent: batteryCurrent,
          yieldToday: yieldTodayRaw / 100, // kWh
          pvPower: pvPowerRaw, // W
          loadCurrent: loadCurrentRaw / 10, // A
        };
      }
    } catch (e) {
      // fall through to shunt layout
    }

    // --- Try Battery Monitor (SmartShunt/BMV) layout ---
    // aux_mode (u2), voltage (u16, 0.01V), alarm (u16), aux value (u16), current (i22, 0.001A),
    // consumed_ah (u20, 0.1Ah), soc (u10, 0.1%)
    try {
      var reader2 = new BitReader(data);
      var auxMode = reader2.readUint(2);
      reader2.skip(14); // reserved bits in this byte-pair, per spec padding
      var voltageRaw = reader2.readInt(16);
      reader2.skip(16); // alarm reason, not decoded here
      reader2.skip(16); // aux value (temperature or starter voltage depending on auxMode), not decoded here
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
    } catch (e) {
      // both layouts failed
    }

    var hexDump = '';
    for (var i = 0; i < data.length; i++) {
      hexDump += data[i].toString(16).padStart(2, '0') + ' ';
    }
    console.warn('VictronBLE: could not confidently parse this advertisement as solar charger or battery monitor. Raw decrypted bytes:', hexDump);
    return null;
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { VictronBLE: VictronBLE };
} else {
  window.VictronBLE = VictronBLE;
}

console.log('>>> victron-ble.js VERSION 2 LOADED <<<');
if (typeof window !== 'undefined') {
  window.__VICTRON_BLE_VERSION__ = 2;
}

// Victron's charger device-state enum, per the published Instant Readout spec / VE.Direct
// protocol docs. Attached as a static property so it's easy to reference from a dashboard
// (e.g. VictronBLE.CHARGER_STATES[7]).
VictronBLE.CHARGER_STATES = {
  0: 'Off',
  1: 'Low power',
  2: 'Fault',
  3: 'Bulk',
  4: 'Absorption',
  5: 'Float',
  6: 'Storage',
  7: 'Equalize (manual)',
  9: 'Inverting',
  11: 'Power supply',
  245: 'Starting-up',
  246: 'Repeated absorption',
  247: 'Auto equalize / recondition',
  248: 'BatterySafe',
  252: 'External control',
};

/** Small helper for reading variable-width little-endian bit fields out of a byte array,
 *  matching how Victron (and the construct-based Python parser) packs multiple sub-byte
 *  fields back to back regardless of byte boundaries. */
class BitReader {
  constructor(bytes) {
    this.bytes = bytes;
    this.bitPos = 0;
  }

  skip(bits) {
    this.bitPos += bits;
  }

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
    if (raw & signBit) {
      return raw - (1 << bits);
    }
    return raw;
  }
}
