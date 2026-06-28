# MICTUNING Switch Panel — BLE Protocol Notes
Reverse-engineered from `com.qunchen.headlightSpp` v3.6.16 (static analysis of the APK).

**Confirmed for: P1S 12-Gang (BLE app-control version).**

The app identifies panels by their advertised BLE device name and routes to a shared protocol
implementation based on gang count, not a model-specific one. Your P1S 12-gang panel advertises
a name starting with `"P1S-2LP-"` (with a `12` suffix, e.g. `P1S-2LP-XXXX12` or similar — the app
just checks `name.endsWith("12")` for gang count). Tracing `MianbanFiltration`'s routing logic
(`isMianBan` → `isAModel`/`isBModel` both false for P1S → falls through to `is12road`), a P1S
12-gang panel is routed to **`P2C12ControlActivity`** — the exact same code path documented
below for the P2C8 family, just with 12 channels (index `0`–`11`) instead of 8.

Other panels sharing this same protocol family (differing only by gang count / RGB capability
flags, confirmed via the same routing table): P1, P1B, P1C, P1R, P1Y, P1SR, P8 Ultra, P8Y
(4/6/8/12-gang variants of each). Genuinely different protocol families in the same app: the
`MS-2LP` series (routes to `MS2A4ControlActivity`/`MS2A6ControlActivity` — untested, not covered
here) and the `MP-2LP` series (routes to `MPMainActivity`, uses the *other* generic
`0000fff0`/`0000fff1` service UUID — also not covered here).

Covers the **P2C-family** panels (`P2C8`, `P2C8A`, `P2C8B`, `P2C12`, `P2C12A`, `P2C6A`, `P2C6B` —
internally these are basically the same protocol with different gang counts/RGB variants).

> ⚠️ This was derived by reading decompiled bytecode, not by sniffing real traffic from a powered
> panel. Treat it as a strong first draft — verify the exact opcodes against your panel with
> a BLE scanner (nRF Connect / LightBlue) before wiring it into anything that drives real switches.

---

## 1. BLE identifiers

| Role | UUID |
|---|---|
| Primary service | `0003cbbb-0000-1000-8000-00805f9bfff0` |
| Characteristic FFF1 | `0003cbbb-0000-1000-8000-00805f9bfff1` |
| Characteristic FFF2 | `0003cbbb-0000-1000-8000-00805f9bfff2` |
| Characteristic FFF3 | `0003cbbb-0000-1000-8000-00805f9bfff3` |
| Characteristic FFF4 | `0003cbbb-0000-1000-8000-00805f9bfff4` |
| Characteristic FFF5 | `0003cbbb-0000-1000-8000-00805f9bfff5` |
| **Characteristic FFFA (main write target)** | `0003cbbb-0000-1000-8000-00805f9bfffa` |
| CCCD (enable notify) | `00002902-0000-1000-8000-00805f9b34fb` (standard) |

There's also a second, unrelated product family in the same app using the generic Nordic-style
`0000fff0` / `0000fff1` service — that's for a different panel line ("MP"), not yours.

Writes go to **FFFA** using **Write Without Response** (`writeNoRsp` in the app — GATT property
`WRITE_NO_RESPONSE`, not `WRITE`). Status/colour readbacks come back as **notifications** on
FFF1 (and possibly FFF2-FFF5 for other fields) — you need to subscribe via the CCCD on those
characteristics to receive them.

If your physical panel turns out to be in "SPP fallback" mode (`DeviceBean.bluetoothMode == 1`
in the app), it instead tunnels the same byte payloads over classic Bluetooth SPP
(UUID `00001101-0000-1000-8000-00805F9B34FB`) rather than BLE GATT. iPad/Bluefy can't do classic
SPP at all — only BLE — so if your panel insists on SPP mode this whole approach won't work and
you'd need a different bridge. Most P2C-series panels default to BLE GATT mode, so this is
unlikely to bite you, but worth confirming during testing.

---

## 2. Command packet — per-channel control (`getRGBCtl`)

This is the command the app sends for: turning an individual switch/channel on or off, and for
RGB/scene/brightness changes on that channel. **10 raw bytes**, written directly to FFFA (no
checksum byte, no length prefix — short fixed packet):

| Byte index | Field | Notes |
|---|---|---|
| 0 | `0x03` | Fixed opcode for "set channel" command |
| 1 | `btnIndex` | Which switch/channel, **0-based** (channel 1 = `0x00`, channel 2 = `0x01`, … up to channel 12 = `0x0B` on your 12-gang panel) |
| 2 | `onOff` | `0x00` = off, `0x01` = on |
| 3 | mode flag | `0x00` if exactly one color in the colour list, else `0xBC` |
| 4 | speed (low byte) *or* `0xBC` | if 1 colour: `speed & 0xFF`. If multi-colour: fixed `0xBC` |
| 5 | speed (high byte) *or* `0x08` | if 1 colour: `(speed >> 8) & 0xFF`. If multi-colour: fixed `0x08` |
| 6 | `lightness` | brightness, 0–100 (one byte, direct value — not scaled to 0-255) |
| 7 | `flash` | flash/strobe mode index |
| 8 | `colorCount` | number of colours in the colour list (single solid colour = `1`) |
| 9 | `isSave` | `0x01` = persist this setting on the panel, `0x00` = apply only (don't save) |

**Minimal "just toggle switch N on/off" packet** (ignore RGB/brightness, reuse panel's current
settings for those — this is the safest starting point since it mirrors a plain on/off tap):

```
[0x03, N, onOff, 0x00, 0x00, 0x00, <lightness>, <flash>, 0x01, 0x00]
```

Where `N` = 0-based channel index, `onOff` = 0/1, and `lightness`/`flash` should just be whatever
last-known values you have for that channel (or sensible defaults like `lightness=100`,
`flash=0` if you don't have last-known state yet).

### "Master" / whole-panel on-off
Separately, there's a simpler whole-panel toggle, sent as **hex string `"F800"`** (i.e. raw bytes
`0xF8, 0x00`) to query/report panel-wide status — `checkP2cStatus()` in the app uses this. This
looks like a status *request*, not a command — the response decodes per section 3 below.

---

## 3. Status / notify payload (`resetListUI` parsing)

When the panel pushes a notification (or responds to a query), the app hex-encodes the raw bytes
into a string and parses positionally. Decoded layout (after converting the notify payload to an
uppercase hex string):

| Hex-string char range | Meaning |
|---|---|
| chars 0–2 (1st byte) | header/type byte — not decoded in app, ignored |
| chars 2–4 | `"F8"` = panel off, `"F9"` = panel on (master status) |
| chars 4–N (until lightness section) | one hex digit *per channel* — looks like a 1-nibble on/off flag per switch, repeated for each of the up to 12 channels |
| chars 14–16 | `lightness`, parsed as `Integer.parseInt(str, 16)` — i.e. **this nibble pair is hex-encoded brightness**, not decimal |
| chars 16+ (pairs of 2) | additional per-channel data, parsed in pairs — likely per-channel RGB or extended state, structure not fully confirmed |

This part of the protocol is messier and I'd treat the exact slot boundaries as approximate until
verified against a live capture — the app's own code logs `"resetUI: 判断错误"` ("judgment error")
when the leading status nibble isn't `F8` or `F9`, implying even MICTUNING's own parsing is
somewhat fragile/version-dependent across panel firmware revisions.

---

## 4. Checksum (used elsewhere in the app, not in `getRGBCtl`)

Some other command paths (e.g. the "DreamLight" product variant, not your panel) prepend
`0xAF` and append a checksum byte. The checksum is trivial:

```js
function checkCode(bytes) {
  let sum = 0;
  for (const b of bytes) sum += b;
  return sum & 0xFF;
}
```

Your P2C8-family `getRGBCtl` packet does **not** use this checksum — it's a fixed 10-byte
payload with no trailer. Worth keeping this function around anyway in case live testing reveals
your specific panel firmware does expect one (cheap to add, easy to verify by trial).

---

## 5. What's confirmed vs. what needs live verification

**High confidence** (read directly from clear, non-obfuscated Kotlin logic):
- Service/characteristic UUIDs
- FFFA is the write target, write-without-response
- The 10-byte `getRGBCtl` packet structure and byte offsets
- The plain sum-of-bytes checksum algorithm (where used)
- RGB colours are plain 3-byte R,G,B

**Needs live verification against your actual panel:**
- Exact channel numbering (is channel 1 really index `0`, or does the panel start counting
  differently — group panels, gang-up channels, etc. add complexity the app handles separately)
- The full notify/status payload layout in section 3 (approximate, not fully traced)
- Whether your specific panel unit is in BLE-GATT mode or classic-SPP mode
- Whether write-without-response actually round-trips reliably over Bluefy's BLE stack on iPad
  (Bluefy's iOS BLE bridging has historically been less robust than Android's native stack)

The recommended next step is exactly what we discussed earlier: do one Wireshark/HCI-snoop
capture of the real MICTUNING app toggling a couple of switches, and diff the actual bytes against
this spec. If they match, we're done. If they don't, the diff will tell us immediately which
field is off.
