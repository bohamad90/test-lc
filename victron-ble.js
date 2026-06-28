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
 * implementations, ported to Web Crypto.
 *
 * You'll need your device's encryption key first -- get it from the VictronConnect app:
 *   Settings > Product Info > Instant Readout via Bluetooth > Show (under "Instant Readout Details")
 *
 * --- IMPORTANT iOS/Bluefy constraint ---
 * Web Bluetooth's advertisement-watching API (watchAdvertisements) requires a BluetoothDevice
 * object, which can only be obtained via the user-gesture device picker (requestDevice). There
 * is no "scan for any nearby device" API on iOS the way there is with native Core Bluetooth or
 * desktop tools like bleak/noble. So the flow here is:
 *   1. User taps "Add Victron device" -> opens the OS picker (filtered as best as possible)
 *   2. Once picked, we call watchAdvertisements() and listen passively from then on
 *   3. No GATT connection is ever made -- this is a pure listen, which is also why it's
 *      very battery-friendly and immune to the connection-drop issues GATT clients have.
 *
 * Usage:
 *   const victron = new VictronBLE({ encryptionKey: 'a1b2c3...' }); // hex string from VictronConnect
 *   await victron.addDevice();             // opens device picker once
 *   victron.onReading((data) => { ... });  // fires on every decrypted advertisement
 */

class VictronBLE {
  constructor(opts = {}) {
    this.encryptionKey = opts.encryptionKey ? this._hexToBytes(opts.encryptionKey) : null;
    this.device = null;
    this._readingListeners = [];
    this._cryptoKeyPromise = this.encryptionKey ? this._importKey(this.encryptionKey) : null;
  }

  /** Opens the OS Bluetooth device picker and starts watching advertisements from the chosen device.
   *  Victron devices don't reliably expose a filterable service UUID in the legacy advertisement
   *  (it's all inside manufacturer data), so acceptAllDevices is the practical choice here --
   *  the person picks their SmartSolar/SmartShunt by name from the list. */
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

    this.device = await navigator.bluetooth.requestDevice({ acceptAllDevices: true });

    if (typeof this.device.watchAdvertisements !== 'function') {
      throw new Error(
        'This browser does not support watchAdvertisements(). Bluefy added this in a recent ' +
        'update -- make sure Bluefy is fully up to date.'
      );
    }

    this.device.addEventListener('advertisementreceived', (event) => this._handleAdvertisement(event));
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
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  async _importKey(keyBytes) {
    return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CTR' }, false, ['decrypt']);
  }

  async _handleAdvertisement(event) {
    if (!this.encryptionKey) {
      console.warn('VictronBLE: no encryption key set yet -- ignoring advertisement. Call setEncryptionKey() first.');
      return;
    }

    // Victron's manufacturer ID is 0x02E1 (737 decimal).
    const mfgData = event.manufacturerData && event.manufacturerData.get(0x02e1);
    if (!mfgData) return; // not a Victron advertisement, or doesn't carry mfg data this round

    const bytes = new Uint8Array(mfgData.buffer || mfgData);
    // Layout per Victron's published spec:
    //   [0:2]  Vendor ID (already matched via manufacturerData key, redundant here)
    //   [2]    Beacon/record type -- 0x10 for "Product Advertisement" (Instant Readout)
    //   [3]    Unknown/version-ish byte
    //   [4]    Device/model state byte (varies per device type)
    //   [5:7]  Nonce / data counter (little-endian uint16) -- used as the AES-CTR counter
    //   [7]    Key-check byte -- should match first byte of your encryption key
    //   [8:]   Encrypted payload
    if (bytes.length < 9) return;

    const recordType = bytes[2];
    if (recordType !== 0x10) return; // not an Instant Readout record

    const nonceLow = bytes[5];
    const nonceHigh = bytes[6];
    const keyCheck = bytes[7];

    if (keyCheck !== this.encryptionKey[0]) {
      console.warn(
        `VictronBLE: key-check byte mismatch (got 0x${keyCheck.toString(16)}, expected 0x${this.encryptionKey[0].toString(16)}). ` +
        'Your encryption key is probably wrong for this device.'
      );
      return;
    }

    const encrypted = bytes.slice(8);

    try {
      const decrypted = await this._decrypt(encrypted, nonceLow, nonceHigh);
      const parsed = this._parsePayload(decrypted);
      if (parsed) {
        parsed.deviceName = this.device.name;
        parsed.rssi = event.rssi;
        this._readingListeners.forEach((cb) => cb(parsed));
      }
    } catch (err) {
      console.warn('VictronBLE: decryption/parse failed:', err);
    }
  }

  async _decrypt(encryptedBytes, nonceLow, nonceHigh) {
    const key = await this._cryptoKeyPromise;
    // Victron's nonce is a 16-bit little-endian counter, zero-padded to a 16-byte CTR counter block.
    const counter = new Uint8Array(16);
    counter[0] = nonceLow;
    counter[1] = nonceHigh;
    // bytes [2..15] remain zero

    const result = await crypto.subtle.decrypt(
      { name: 'AES-CTR', counter, length: 128 },
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
   * Treat as a strong first draft -- cross-check against your device's readings in
   * VictronConnect the first time you run this.
   */
  _parsePayload(data) {
    // First decrypted byte is the device "state"/mode indicator shared across types in some
    // firmware revisions; the actual field layout differs per device "model" (which isn't
    // directly given -- we infer by trying the solar-charger layout, since that's the
    // primary device for this project, and fall back to shunt layout if values look implausible).
    const reader = new BitReader(data);

    // --- Try Solar Charger (MPPT) layout ---
    // device_state (u8), charger_error (u8), battery_voltage (u16, 0.01V), battery_current (u16, 0.1A),
    // yield_today (u16, 0.01kWh), pv_power (u16, 1W), load_current (u9, 0.1A)
    try {
      const deviceState = reader.readUint(8);
      const chargerError = reader.readUint(8);
      const batteryVoltageRaw = reader.readInt(16);
      const batteryCurrentRaw = reader.readInt(16);
      const yieldTodayRaw = reader.readUint(16);
      const pvPowerRaw = reader.readUint(16);
      const loadCurrentRaw = reader.readUint(9);

      const batteryVoltage = batteryVoltageRaw / 100;
      const batteryCurrent = batteryCurrentRaw / 10;

      // Sanity check: solar battery voltage for a 12V system should land roughly 8-16V.
      // If this looks wildly wrong, it's likely actually a different device type/layout.
      if (batteryVoltage > 5 && batteryVoltage < 100) {
        return {
          deviceType: 'solar_charger',
          deviceState,
          deviceStateName: VictronBLE.CHARGER_STATES[deviceState] || `Unknown (${deviceState})`,
          chargerError,
          batteryVoltage,
          batteryCurrent,
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
      const reader2 = new BitReader(data);
      const auxMode = reader2.readUint(2);
      reader2.skip(14); // reserved bits in this byte-pair, per spec padding
      const voltageRaw = reader2.readInt(16);
      reader2.skip(16); // alarm reason, not decoded here
      reader2.skip(16); // aux value (temperature or starter voltage depending on auxMode), not decoded here
      const currentRaw = reader2.readInt(22);
      const consumedAhRaw = reader2.readUint(20);
      const socRaw = reader2.readUint(10);

      const voltage = voltageRaw / 100;
      const current = currentRaw / 1000;
      const soc = socRaw / 10;

      if (voltage > 5 && voltage < 100 && soc >= 0 && soc <= 100) {
        return {
          deviceType: 'battery_monitor',
          auxMode,
          voltage,
          current,
          consumedAh: consumedAhRaw / 10,
          soc,
        };
      }
    } catch (e) {
      // both layouts failed
    }

    console.warn('VictronBLE: could not confidently parse this advertisement as solar charger or battery monitor. Raw decrypted bytes:', [...data].map(b => b.toString(16).padStart(2, '0')).join(' '));
    return null;
  }
}

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
    let value = 0;
    for (let i = 0; i < bits; i++) {
      const byteIndex = (this.bitPos + i) >> 3;
      const bitIndex = (this.bitPos + i) & 7;
      if (byteIndex >= this.bytes.length) throw new Error('BitReader: out of data');
      const bit = (this.bytes[byteIndex] >> bitIndex) & 1;
      value |= bit << i;
    }
    this.bitPos += bits;
    return value >>> 0;
  }

  readInt(bits) {
    const raw = this.readUint(bits);
    const signBit = 1 << (bits - 1);
    if (raw & signBit) {
      return raw - (1 << bits);
    }
    return raw;
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { VictronBLE };
} else {
  window.VictronBLE = VictronBLE;
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
