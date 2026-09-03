# MindRove live bridge orchestration

This package is the hardware boundary between pinned `wifit3` v0.1.5 and the
hardware-independent station/crypto code in `mindrove_station`. It intentionally
does not make the Realtek adapter a general macOS network interface. Instead, it
claims only USB `0bda:c811`, leaves built-in Wi-Fi untouched, associates to one
explicit MindRove BSSID, and can forward decoded MindRove datagrams to a process
listening on loopback UDP port 4210.

Implemented here:

- exact VID/PID and pinned-version selection;
- the `bt_coexist=False` channel-tune compatibility guard;
- deliberate fixed-channel tuning with RF18 band/channel readback and full-band
  retry (the RX reader is paused during readback);
- a bounded RX queue filtered to the target BSSID and station/group receiver;
- a locally administered active-monitor station MAC;
- targeted Open System authentication and a WPA2-PSK/CCMP association request;
- a concrete WPA2 four-way handshake and pairwise/group-key CCMP data plane;
- protected DHCP discover/request with strict transaction/MAC/server/profile
  validation, followed by ARP and the leased `192.168.4.2` to `192.168.4.1`
  IPv4/UDP profile;
- one captured five-zero-byte EXG configuration datagram, sent exactly once and
  only after protected ARP resolves the MindRove peer, from a per-session
  dynamic source port to UDP destination 4210;
- a strict decoder for the 216-byte stream payload (two 108-byte samples with
  eight EXG channels, accelerometer XYZ, gyroscope XYZ, battery, trigger,
  resistance, and measurement counter);
- pluggable handshake/decryption and decoded-packet callbacks for testing and
  future protocol adapters;
- a loopback-only UDP sink (default `127.0.0.1:4210`).

## Safety and credentials

Importing or testing the package never opens USB. The CLI has no password
argument. It reads the passphrase from the environment variable `MINDROVE_PSK`
or, when absent, from a hidden `getpass` prompt. Do not pass secrets through a
provider specification or shell command line.

Active station mode fails closed unless the SSID begins with `MindRove` and the
target is on the FCC/US 2.4-GHz channel plan (channels 1–11). Do not transmit it
under another regulatory domain without first reviewing that domain's channel
and power requirements. The bridge does not override the adapter's eFuse
calibration or Wifit3 transmit-power setup.

## Setup and run

Leave MindRove Connect open if you want to use its plots; it listens for the
bridge on local UDP port 4210. Close only software that directly claims the USB
adapter, then create an isolated environment from the repository root. Wifit3
requires Python 3.11 or newer, so verify the selected interpreter first:

```sh
python3 --version
python3 -m venv .venv-mindrove-bridge
source .venv-mindrove-bridge/bin/activate
python -m pip install pip==26.2.1
python -m pip install -r tools/mindrove_bridge/requirements.txt
```

The dependency file pins wifit3 to reviewed release commit
`e1f449c0248a8ad1d4080975ca0368d3f44d75d6`. The bridge refuses a different
reported wifit3 version and claims only one attached `0bda:c811` device.

The default CLI uses the repository's audited WPA2/CCMP implementation:

If you do not yet know the BSSID and channel, stop any process claiming the
dongle and follow the [target-only passive scanner](../mindrove_passive_scan/README.md)
guide. Then close the scanner before starting the active bridge.

```sh
python -m tools.mindrove_bridge \
  --ssid 'MindRove_...' \
  --bssid 'aa:bb:cc:dd:ee:ff' \
  --channel 6 \
  --station-mac '02:11:22:33:44:55'
```

`--station-mac` is optional, but reusing the last successful client identity is
useful when the device's DHCP lease or stream target is still tied to it. If it
is omitted, the bridge generates a fresh locally administered address.

Start MindRove Connect before or after the command. A successful run reports a
DHCP lease at `192.168.4.2` and then `validated first MindRove UDP/4210 payload
for loopback delivery`. Keep the terminal process running while acquiring data.
The built-in Wi-Fi remains managed by macOS and retains the default route.

Internally the handshake callback receives a `StationExchange` and
`SecretValue`; the completed decoder accepts target 802.11 frames and returns
either a validated MindRove UDP/4210 payload or `None`. The credential is
redacted in `str`/`repr` and cleared when the CLI exits.

## Validate a saved stream

MindRove Connect saves tab-separated data despite the `.csv` extension. The
read-only validator checks finite values, measurement-counter continuity,
approximately 500-Hz acquisition, and activity across all eight EMG and all six
IMU fields:

```sh
python -m tools.mindrove_bridge.validate_log '/path/to/MindRove log.csv'
```

The validator reads only the completed log. It does not bind UDP port 4210,
claim the adapter, or transmit, so the live bridge and MindRove Connect can keep
running. The current hardware carries IMU values in the 500-Hz records, while
new accelerometer and gyroscope values arrive at approximately 50 Hz.

## Current limitations

- Only WPA2-Personal with CCMP-128 and classic PSK AKM is selected. WPA3, WEP,
  Enterprise, TKIP, and APs requiring protected management frames fail closed.
- The adapter remains a user-space radio; unmodified apps need the packet
  protocol adapter to translate their traffic to/from loopback.
- DHCP is the only supported address configuration. It explicitly requests and
  accepts only `192.168.4.2`, because current acquisition firmware sends its
  stream to that literal destination even if DHCP leases another address. If
  `.2` is still leased to a different identity, reuse that station MAC or
  power-cycle the device/AP before retrying. Renewal/rebinding is not yet
  implemented.
- The GTK delivered in the authenticated four-way handshake is installed for
  broadcast/multicast receive. Later pairwise/group rekey handshakes are not
  implemented; reconnect before any key lifetime expires.
- The CLI currently forwards device-originated UDP/4210 payloads to loopback;
  arbitrary application command ingress still needs an adapter. MindRove
  Connect's live EXG plotting works with the implemented loopback path.
- The `0bda:c811` board is live-tested by this project but is not yet listed as
  an upstream hardware-tested wifit3 target. RF18 readback and authenticated
  packet flow provide both tuning and end-to-end packet validation.

Run the hardware-free tests with:

```sh
python -m pip install -r tools/mindrove_bridge/requirements-dev.txt
python -m pytest -q
python -m ruff check mindrove_station tools tests/mindrove_station
python -m mypy --explicit-package-bases --ignore-missing-imports mindrove_station tools/mindrove_bridge tools/mindrove_passive_scan
```
