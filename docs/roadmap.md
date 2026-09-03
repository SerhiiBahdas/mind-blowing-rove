# Roadmap

Each milestone should leave behind a reproducible test or usable artifact.

## M0 — Hardware identity and diagnostics

- [x] Confirm `0x0bda:0xc811` enumeration on Apple silicon and recent macOS.
- [x] Add a minimal USB and driver-attachment probe.
- [x] Identify a working macOS user-space RTL8821CU implementation as an upstream base.
- [ ] Collect probe reports from at least two hubs and two Apple-silicon generations.
- [x] Compare this adapter's descriptors and eFuse data with Wifit3's tested reference adapter.

Exit criterion: contributors can distinguish USB/hub failures from a missing driver without posting private system dumps.

## M1 — Linux reference and usable bridge

- [ ] Verify the exact upstream `rtw88_8821cu` module and firmware on arm64 Linux.
- [ ] Pass USB `0x0bda:0xc811` through to a lightweight VM.
- [ ] Associate the VM with the password-protected MindRove network.
- [ ] Route only `192.168.4.0/24` to the macOS host.
- [ ] Verify `192.168.4.1:4210` and MindRove Connect while built-in Wi-Fi stays online.
- [ ] Package repeatable setup, health-check, and teardown scripts.

Exit criterion: a user can use MindRove and the primary internet Wi-Fi concurrently on Apple silicon without weakening macOS security.

## M2 — Native user-space radio proof

- [ ] Coordinate with Wifit3 upstream before duplicating its chipset module.
- [x] Add a read-only eFuse/board-variant report for `0x0bda:0xc811`.
- [x] Validate firmware boot, RX, TX, and hardware acknowledgements on this exact dongle.
- [x] Capture the MindRove AP's channel, capabilities, and WPA2-PSK/CCMP security mode.
- [x] Add deterministic unit tests for association, WPA2/CCMP, DHCP, and packet validation.

Exit criterion: the supplied dongle reliably receives the target AP's beacons on macOS without a VM.

## M3 — MindRove station and data path

- [x] Implement authentication and association for WPA2-PSK/CCMP.
- [x] Implement only the required DHCP, ARP, IPv4, and UDP data path.
- [x] Receive from and transmit to the documented `192.168.4.1:4210` endpoint.
- [x] Feed validated packets into the unmodified MindRove Connect app over loopback.
- [ ] Add disconnect recovery and long-duration EXG/IMU streaming tests.

Exit criterion: a native user-space process acquires MindRove samples while macOS remains on its primary internet Wi-Fi.

## M4 — Friendly native app

- [ ] Add safe device selection and connection state.
- [ ] Store any credential in Keychain; never log it.
- [ ] Add a local sample stream, recorder, and basic signal viewer.
- [ ] Sign and notarize a universal macOS build.
- [ ] Document clean install, update, and removal.

Exit criterion: a new user can install, connect, stream, and uninstall without Terminal or reduced security settings.

## Optional compatibility experiment

- [ ] Ask Apple DTS whether a selective `NEPacketTunnelProvider` is acceptable for this non-VPN device link.
- [ ] If approved, route only `192.168.4.0/24`; never claim the default route.
- [ ] Test discovery and unmodified MindRove Connect behavior.

This experiment is optional because Apple documents packet-tunnel providers for VPN use. It must not block our own acquisition client.

## Research gates

Before distributing a combined native implementation, resolve:

1. Wifit3 collaboration and GPL-2.0-only provenance;
2. Realtek firmware notice retention and redistribution packaging;
3. radio-regulatory and transmit-power behavior for the adapter's eFuse variant;
4. Apple policy approval only before any optional Network Extension or DriverKit experiment.
