# Mind Blowing Rove

An open-source effort to use the MindRove USB Wi-Fi adapter on modern Apple-silicon Macs while keeping the Mac's built-in Wi-Fi connected to the internet.

The adapter supplied with the device enumerates as:

| Field | Value |
| --- | --- |
| USB vendor | Realtek (`0x0bda`) |
| USB product | `0xc811` |
| Chip family | RTL8821CU / RTL8811CU family |
| Tested host | Apple silicon on a recent macOS release |

## Project status

The native user-space bridge is working on the tested `0bda:c811` adapter. It
associates the dongle directly with a MindRove ARB access point, completes
WPA2-PSK/CCMP and DHCP, decrypts the device's UDP stream, and relays it to
MindRove Connect on loopback port 4210. It never changes the built-in Wi-Fi
interface or the Mac's default route, so the primary internet Wi-Fi remains usable.

- [x] Confirm the adapter is visible on USB on Apple silicon.
- [x] Provide a small, privacy-conscious hardware probe.
- [x] Bring up RTL8821CU in macOS user space with fixed-channel recovery.
- [x] Implement authentication, association, WPA2, CCMP, DHCP, ARP, IPv4, and UDP.
- [x] Validate live 500 Hz EMG and approximately 50 Hz accelerometer/gyroscope
  updates in MindRove Connect on Apple silicon.
- [ ] Add automatic BSSID/channel discovery and a signed installer.

There are two implementation tracks:

1. **Native user space (working):** use the existing GPL-2.0 [Wifit3](https://github.com/derv82/wifit3) RTL8821CU mini-driver with this repository's narrow MindRove station/UDP stack. This avoids Apple's private Wi-Fi stack and keeps the built-in radio free for the primary internet connection.
2. **Linux fallback:** pass the dongle to a small Linux VM, use Linux's upstream `rtw88` driver, and expose only the MindRove subnet to macOS. This remains an option for future, untested adapter variants.

Apple's public DriverKit API explicitly does not support USB devices that communicate over Wi-Fi, and NetworkingDriverKit exposes Ethernet rather than a third-party Wi-Fi interface. A DriverKit Ethernet facade remains a research idea, not the plan we promise users. See [Research](docs/research.md) for the evidence and exact upstream revisions.

See [Architecture](docs/architecture.md), [Linux bridge setup](docs/linux-bridge.md), and [Roadmap](docs/roadmap.md) for the technical plan.
Live signal evidence is summarized in the privacy-safe [validation report](docs/validation.md).

## Run the live macOS bridge

See the [live bridge guide](tools/mindrove_bridge/README.md) for the isolated
environment setup and command. If the target BSSID or channel is unknown, use
the [target-only passive scanner](tools/mindrove_passive_scan/README.md) first.
The bridge accepts the Wi-Fi passphrase only
through a hidden prompt or environment variable; it has no password command-line
argument. For the currently tested firmware, the dongle must obtain
`192.168.4.2`, because the device sends its UDP stream to that fixed address.

## Run the USB probe

Requirements: macOS and the Xcode command-line tools.

```sh
make probe
```

For an issue-friendly machine-readable report:

```sh
make build
./build/mindrove-usb-probe --json
```

The probe reports USB identifiers, interface descriptors, and whether a macOS network service attached. It intentionally omits serial numbers, usernames, SSIDs, IP addresses, and the rest of the USB registry.

Expected result on an unsupported Mac:

```text
Adapter: FOUND (0x0bda:0xc811)
macOS network service: NOT ATTACHED
Diagnosis: USB works; a compatible network driver is missing.
```

## Contributing

Hardware reports, packet captures made on hardware you own, Linux networking experience, and RTL8821CU testing are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before posting diagnostic output.

Do not install unsigned legacy kernel extensions or disable macOS security protections just to test this project. The native track is intentionally user-space-first.

## License

GPL-2.0-only. This choice preserves compatibility with the Wifit3 and Linux/vendor-derived RTL8821CU work we extend. Firmware remains under its own vendor terms and is not vendored by this repository.
