# Passive MindRove beacon probe

This experiment initializes exactly one USB device with ID `0bda:c811`, uses
the RTL8821CU monitor receive path from the pinned wifit3 release, and waits for
beacons. It never sends probe requests and installs fail-closed guards over all
wifit3 frame-injection and active-monitor entry points.

The only successful stdout output is one JSON object containing the exact
requested SSID, its BSSID and channel, parsed security properties, and its raw
RSN/RSNXE/WPA/WPS information elements. Other nearby network identities are
not emitted or retained by the collector.

## Setup on macOS

Use Python 3.11 or newer. Quit MindRove Connect first so it does not hold the
USB interface.

```sh
python3 -m venv .venv-passive-scan
source .venv-passive-scan/bin/activate
python -m pip install --upgrade pip
python -m pip install -r tools/mindrove_passive_scan/requirements.txt
```

The requirement is pinned to wifit3 `v0.1.5`, immutable commit
`e1f449c0248a8ad1d4080975ca0368d3f44d75d6`. That dependency is
GPL-2.0-only. It supplies its own Realtek firmware asset; this repository does
not copy or redistribute that blob.

### `c811` Wi-Fi-only compatibility fix

A serialized live EFUSE read of the target `0bda:c811` reported
`bt_coexist=False`. Wifit3 `v0.1.5` correctly skips Bluetooth-coexistence
initialization for that value, but its channel setter still unconditionally
calls the BTC band notifier and dereferences state that was never created.

Before opening USB, this tool installs a narrow runtime compatibility guard
equivalent to wrapping the two notifier calls in `if info.bt_coexist:`. The
reviewable upstream-style patch and provenance are in
[`patches/wifit3-v0.1.5-c811-no-bt-coexist.patch`](patches/wifit3-v0.1.5-c811-no-bt-coexist.patch).
The shim does not change the Bluetooth-combo path and restores upstream
function references even if tuning raises.

## Hardware-free checks

```sh
python -m unittest discover -s tools/mindrove_passive_scan -p 'test_*.py'
python -m tools.mindrove_passive_scan --help
```

## Serialized hardware run

Do not run this concurrently with MindRove Connect, wifit3, or another probe.
Use the complete, case-sensitive SSID printed on/configured for the device:

```sh
python -m tools.mindrove_passive_scan --ssid '<MINDROVE_SSID>'
```

If more than one device advertises that SSID, constrain the target without
exposing unrelated networks:

```sh
python -m tools.mindrove_passive_scan \
  --ssid '<MINDROVE_SSID>' \
  --bssid '<TARGET_BSSID>' \
  --channels '1-11' \
  --passes 3 \
  --dwell 1.5
```

The default is two one-second passes over channels 1 through 11. Five-GHz
non-DFS channels may be requested explicitly, for example
`--channels '1-11,36,40,44,48,149,153,157,161,165'`.

"Passive" here describes the radio scan: no 802.11 frames are injected. Cold
bring-up necessarily claims the USB interface, uploads firmware over USB, and
writes volatile chip registers. The `c811` ID is listed by wifit3 but has not
yet been hardware-validated upstream. A failed first attempt may require a
physical unplug/replug before retrying.
