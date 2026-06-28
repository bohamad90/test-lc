# JuncTek KM-F Battery Shunt — BLE Protocol Notes
Reverse-engineered from the **Junce Home** app v1.6.8 (`com.juntek.platform`), via static
analysis of its bundled JavaScript source (this app is built with DCloud/uni-app — the actual
business logic ships as plain, readable JS inside the APK rather than compiled native code,
which made this considerably easier to trace than the MICTUNING app).

**Confirmed for: KMF230001 (KM-F series battery shunt/coulomb meter, BLE mode).**

> ⚠️ As with the MICTUNING notes, this comes from reading app source, not from a live capture.
> The protocol structure (framing, checksum, register letters) is read very clearly and
> confidently from the code. The exact meaning of every single field index is not 100%
> exhaustively confirmed — enough are confirmed to build a working live-data dashboard, but
> treat unlabeled indices as "probably this, verify against your live readings."

---

## 1. Big picture: this is a plain-text protocol, not binary

Unlike MICTUNING's panel, JuncTek's BLE link carries **plain ASCII text frames**, the same
style as their published RS485/Modbus-ASCII documentation — BLE here is just a transparent pipe
for the same command language used on the wired interface. There is no encryption and no
binary packing of values; everything is human-readable once you decode the bytes as ASCII.

**Frame format (both directions):**
```
:LETTER=value1,value2,value3,...,checksum\r\n
```
or for read responses, the same shape without the `=` (depending on direction — see below):
```
:LETTERvalue1,value2,value3,...,checksum\r\n
```
- Starts with `:` (`0x3A`)
- Second character is a single uppercase **register letter** (`A`, `B`, `C`, `D`, `E`, `F`, ...)
  identifying what kind of data the frame carries
- Remaining fields are comma-separated decimal numbers
- **Last comma field is a checksum** (see section 3)
- Frame ends with `\r\n` (`0x0D 0x0A`)

Multiple frames can arrive concatenated in one BLE notification; the app buffers and splits on
`\r\n` boundaries.

---

## 2. BLE connection sequence

There's no hardcoded service/characteristic UUID in this app at all — it discovers them at
runtime, and picks them **positionally**:

1. Connect to the device, call `getPrimaryServices()` (or platform equivalent).
2. **Use the last service in the returned list** (`services[services.length - 1]`).
3. Get that service's characteristics.
4. **`characteristics[0]`** = the notify/read characteristic — subscribe to notifications on it.
5. **`characteristics[1]`** = the write characteristic — send commands here.
6. Once notifications are subscribed, send the initial handshake/ping command (see section 4)
   to kick off the device into sending data.

This positional approach is a bit fragile in general, but it's exactly what the official app
does, so it's a reasonable starting point. If it doesn't pick the right characteristics on your
specific shunt, the fallback is to enumerate all services/characteristics with a generic BLE
scanner (nRF Connect / LightBlue) and hardcode the UUIDs you find instead.

**Important:** outgoing command strings are sent as **plain ASCII bytes** — i.e. to send the
literal string `:r00=86.`, you write the UTF-8/ASCII bytes for that exact string to the write
characteristic. No hex-encoding, no binary packing.

---

## 3. Checksum algorithm

Both reading (validating incoming frames) and writing (building outgoing frames) use the same
checksum:

```js
function checksum(letter, values, password = "11223344") {
  // values = array of the comma-separated numeric fields, NOT including the checksum itself
  let acc = letter.charCodeAt(0); // ASCII code of the register letter, e.g. 'A' = 65
  for (const v of values) {
    acc ^= Number(v);
  }
  acc ^= Number(password);
  return (acc % 9999) + 1;
}
```

The device requires a password be XORed into every checksum — default password is the string
`"11223344"`. If your shunt has never had its password changed from factory default, this
should just work. If checksum validation fails repeatedly, the app's logic suggests the device
gates further communication behind a password-entry flow (3 failed attempts trigger a "wrong
password" UI in the app) — something to watch for if frames consistently get rejected.

---

## 4. Initial handshake / "ping" command

After subscribing to notifications, the app's first move is to send:
```
:r00=86.
```
This appears to be a generic "send me your current data" request. Sending this is a reasonable
first command to try once connected.

---

## 5. Known register letters and field meanings

These are the registers I found clear evidence for. Index numbers are 0-based positions within
the comma-separated value list for that letter.

### Register `A` — live measurements (read-only, this is what you poll for the dashboard)

| Index | Field | Scaling |
|---|---|---|
| `A[0]` | Voltage | raw ÷ 100 → Volts (e.g. `1234` → `12.34V`) |
| `A[1]` | Current | raw ÷ 1000 → Amps (i.e. raw is milliamps) |
| `A[2]` | Charge/discharge direction flag | `0` = one state (app special-cases display), nonzero relates to polarity — exact enum not fully confirmed |
| `A[3]` | Remaining capacity | Amp-hours remaining, paired with `C[4]` (configured full capacity) to compute SOC% |
| `A[4]` | (power-related numerator) | used as `A[4]/A[5]` to compute a displayed "power" value — exact unit not fully confirmed |
| `A[5]` | (power-related denominator) | see above |
| `A[6]` | Low-voltage alarm threshold (mirrors a `C`-register setting) | raw ÷ 10 |
| `A[7]` | Some kind of mode/index field | referenced when building a `:D=` write command — exact meaning unclear, treat as opaque passthrough |

**State of Charge (%) calculation** (derived from `getValueLowBattery` logic in the app):
```js
const socPercent = Math.floor((A[3] / C[4]) * 100);
```
where `C[4]` is the battery's configured total capacity in Ah (a setting you configure once via
the app, mirrored back in the `C` register).

**Power (Watts)** — straightforward voltage × current:
```js
const powerWatts = (A[0] / 100) * (A[1] / 1000);
```

### Register `C` — device settings (mostly write/config, not live telemetry)

| Index | Field |
|---|---|
| `C[0]` | Temperature unit (Celsius/Fahrenheit toggle) |
| `C[1]` | Display brightness |
| `C[2]` | "Wheel display" on/off (a UI feature on the device's own screen) |
| `C[3]` | Screen backlight on/off |
| `C[4]` | **Configured battery capacity (Ah)** — needed for SOC% calc above |
| `C[5]` | Upper limit / alarm threshold setting |
| `C[6]` | Rapid discharge alarm setting |

### Register `E` — alarm/threshold active-state flags
Referenced alongside `C` register settings (e.g. `E[0]`, `E[5]`, `E[6]`) as the "is this alarm
currently active" boolean counterparts to the `C` register's configured threshold values.
Structure looks like `E[n]` mirrors `C[n]`'s on/off state, but this isn't fully traced.

### Register `B` — network/connectivity config
Used for WiFi/MQTT setup on WiFi-capable KM-F units, not relevant to pure-BLE usage. Skip this.

### Other registers seen but not traced (`D`, `F`)
`D` appears to be used for write commands (e.g. `:D=,,A[7],,,,,,,`), `F` appears at least once
with `F[0]`. Not enough context gathered to document confidently — these likely matter for
deeper settings (alarm config writes, etc.) but aren't necessary for a basic live-readings
dashboard.

---

## 6. Practical plan for the dashboard

For a "show me live voltage/current/power/SOC" panel, you only need:
1. Connect per section 2.
2. Send `:r00=86.` once connected.
3. Parse incoming `:A...` frames using the checksum-validated split-on-comma logic.
4. Compute voltage, current, power, SOC% per the formulas in section 5.
5. Re-request periodically (or rely on the device pushing updates — the app's code suggests it
   keeps streaming after the initial request, so a single kickoff command may be enough).

This is a meaningfully smaller scope than the full settings/alarm-configuration surface the app
exposes — and matches what you actually asked for (live tracking), so it's the right place to
start before optionally adding settings-write support later.
