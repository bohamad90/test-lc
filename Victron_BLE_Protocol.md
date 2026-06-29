# Victron Instant Readout — BLE Protocol Notes

**Confirmed for: SmartSolar MPPT 100/30.** This model is a standard "Solar Charger" device class
in Victron's Instant Readout spec — no model-specific quirks, and it's been independently
confirmed working by other people reverse-engineering this exact same model. The solar-charger
field layout in section "Decrypted payload layout" below applies directly, no adjustments
needed.

Unlike the MICTUNING and JuncTek write-ups, this protocol is **officially published by Victron**
(not reverse-engineered) — see their "Extra manufacturer data" PDF, linked from the community
forum threads. This file just explains how the JS client implements it and what to double-check.

## How this is fundamentally different from the other two devices

Victron devices don't need you to connect to them at all. They continuously broadcast their
status in BLE **advertisement packets** (the same kind of packet a device sends out just to say
"I exist and here's my name") roughly once a second, with the live data embedded inside as
encrypted manufacturer-specific data. Any nearby listener can pick this up passively — no
pairing, no GATT connection, no write commands.

This has real upsides for your dashboard:
- **No connection to drop.** Since there's no GATT session, there's nothing to disconnect from —
  it either hears the broadcast or it doesn't, moment to moment.
- **Very battery-friendly**, since it's pure listening.
- **Works even if the device is "connected" to something else** (e.g. VictronConnect open on
  someone's phone) — advertisements are public, multiple listeners can read them simultaneously.

The one real complication on iOS/Bluefy: Web Bluetooth's advertisement-listening API
(`watchAdvertisements()`) still requires a `BluetoothDevice` object, which can only come from
the user-gesture device picker (`requestDevice()`). There's no "just scan silently for any
nearby device" API the way there is on desktop (bleak/noble) or native iOS (Core Bluetooth). So
the flow is: tap "Add Victron Device" once → pick it from the list → from then on it's pure
passive listening, no further picker prompts needed for that session.

## Getting your encryption key

Victron's broadcast data is encrypted per-device. You only need to do this once:
1. Open VictronConnect (the official app) and connect to your SmartSolar as normal.
2. Tap the gear icon → **Product Info**.
3. Scroll to **Instant Readout via Bluetooth** and make sure it's enabled.
4. Tap **Show** under **Instant Readout Details** — this reveals the encryption key (a hex
   string).

This key goes into the dashboard once and is then stored locally — same as Bluefy permissions,
no internet involved.

## Packet structure (manufacturer-data VALUE, company ID 0x02E1)

These offsets are relative to the manufacturer-data **value** — i.e. the bytes **after** the
2-byte company id (`E1 02`). This matches the reference layout in `keshavdv/victron-ble` and is
what `victron-ble.js` v8 implements. **CONFIRMED working live on a SmartSolar MPPT 100/30.**

| Bytes | Field |
|---|---|
| `[0:2]` | Prefix, little-endian uint16. Low byte `0x10` marks an Instant Readout product advertisement. |
| `[2:4]` | Model id, little-endian uint16 |
| `[4]` | Readout type |
| `[5:7]` | IV / nonce, little-endian uint16 — the AES-CTR counter initial value |
| `[7]` | Key-check byte — must equal the first byte of your encryption key (wrong key ⇒ mismatch). |
| `[8:]` | Encrypted payload (AES-128-CTR) |

Decryption: AES-128-CTR using your encryption key, with the 16-byte counter block = IV bytes
`[5:7]` in the first two positions, little-endian, rest zero. Mirrors `keshavdv/victron-ble`
(Python) and `node-red-contrib-victron-ble` (TypeScript), ported to Web Crypto.

> ⚠️ **Two bugs that blocked this until v8 — do not reintroduce:**
> 1. **Shape:** desktop Chrome exposes `event.manufacturerData` as a `Map` keyed by company id
>    (use `.get(0x02E1)`), but **Bluefy/iOS exposes it as a single raw `DataView`** holding the
>    manufacturer data directly (no Map, no keys, no `.get`). v8 handles both. On Bluefy the
>    `DataView` may or may not include the `E1 02` company-id prefix, so v8 strips it if present.
> 2. **Offsets:** the earlier framing read the IV at `[5:7]`/key-check at `[7]` **of the
>    company-id-inclusive bytes**, which is 2 bytes too early. The value-relative offsets above
>    are correct.

## Decrypted payload layout (varies per device type)

Victron packs several small fields into the decrypted bytes using **bit-level packing** —
fields don't always start or end on byte boundaries, which is why the client uses a bit-reader
rather than simple byte slicing.

**This client currently decodes two device types:**

### Solar Charger (MPPT) — what you have
| Field | Bits | Scaling |
|---|---|---|
| Device state | 8 | raw enum (bulk/absorption/float/etc — not yet mapped to friendly names) |
| Charger error | 8 | raw error code |
| Battery voltage | 16 (signed) | ÷ 100 → Volts |
| Battery current | 16 (signed) | ÷ 10 → Amps |
| Yield today | 16 | ÷ 100 → kWh |
| PV power | 16 | 1W per unit, no scaling |
| Load current | 9 | ÷ 10 → Amps (only relevant if your MPPT has a load output terminal) |

### Battery Monitor (SmartShunt/BMV) — included for completeness, not your primary device
| Field | Bits | Scaling |
|---|---|---|
| Aux mode | 2 | enum: starter battery / midpoint / temperature |
| Voltage | 16 (signed) | ÷ 100 → Volts |
| Current | 22 (signed) | ÷ 1000 → Amps |
| Consumed Ah | 20 | ÷ 10 → Ah |
| State of charge | 10 | ÷ 10 → % |

The client tries the solar-charger layout first and falls back to the battery-monitor layout if
the numbers from the first attempt look implausible (e.g. voltage way outside a sane 5-100V
range). This is a heuristic, not a clean device-type field read directly from the packet — it
works because you're very unlikely to have an actual BMV broadcasting alongside the MPPT in a
way that gets confused, but it's worth knowing this is how the disambiguation works.

## What's confirmed vs. what to verify live

**High confidence** (this is Victron's own published spec, used by multiple working open-source
libraries for years, and your exact model — MPPT 100/30 — is a standard, well-documented "Solar
Charger" class with no known quirks):
- Packet structure, encryption scheme, nonce/key-check byte logic
- Solar charger field layout and scaling factors (voltage, current, yield, PV power, load current)

**Worth double-checking once you're testing live, just as a sanity check, not because of any
known issue:**
- The `deviceState` enum is **now mapped** to readable names via `VictronBLE.CHARGER_STATES`
  (0 = Off, 3 = Bulk, 4 = Absorption, 5 = Float, etc.). Worth pairing your first live test with
  VictronConnect open side-by-side to confirm voltage/current/yield numbers match exactly.

---

## Current status — RESOLVED / WORKING (v8)

**Live readings confirmed on Bluefy/iOS against the real SmartSolar MPPT 100/30.** Battery
voltage and yield-today read correctly; battery current and PV power read 0 at night (no sun),
as expected — to be re-confirmed in daylight against VictronConnect side-by-side.

- **Device encryption key:** `6cc611245a854a60cde278f036c5c98a`
- **What was actually wrong (two bugs, both fixed in v8 — see the ⚠️ note under "Packet
  structure"):**
  1. Bluefy returns `event.manufacturerData` as a single raw `DataView`, not a spec `Map`. The
     old `mfgDataKeys()`/`.get()` path saw no keys and reported "no Victron data" forever.
  2. The frame offsets were 2 bytes too early (IV/key-check/ciphertext).
- **How it was diagnosed:** the v7 build delivered the first-advertisement event dump into a
  dedicated, copyable on-screen panel (instead of letting it scroll away under ~1 log line/sec).
  The dump showed `manufacturerData` had `constructor=DataView`, which pointed straight at bug 1.
- **Confirmed irrelevant in the end:** signal strength, `optionalManufacturerData`, the
  `rssi=127` sentinel — none were the cause.

### Live verification still to do (daylight)
Open VictronConnect next to the dashboard for a minute in sunlight and confirm battery current,
PV power, and charger state (Bulk/Absorption/Float) match. Voltage + yield already verified.
