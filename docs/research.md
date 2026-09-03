# Research record

Links point to primary vendor or source-code material reviewed for this release.

## Confirmed locally

On an Apple-silicon Mac running a recent macOS release, the supplied adapter
appears as one USB 2.0 vendor-specific interface:

```text
Vendor:        Realtek (0x0bda)
Product:       802.11ac NIC (0xc811)
Interface:     class 0xff, subclass 0xff, protocol 0xff
Network child: none
```

This means the Mac, Type-C hub, and USB enumeration are working. The bridge intentionally uses the vendor-specific USB interface directly, so no second macOS `en` interface is required.

## Existing RTL8821CU work

- Linux's upstream [`rtw8821cu.c`](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/realtek/rtw88/rtw8821cu.c) includes the exact `USB_DEVICE_AND_INTERFACE_INFO(0x0bda, 0xc811, 0xff, 0xff, 0xff)` match.
- [Wifit3](https://github.com/derv82/wifit3) is GPL-2.0-only and provides macOS universal2 user-space radio drivers through PyUSB/libusb.
- The bridge pins stable release [`v0.1.5`](https://github.com/derv82/wifit3/releases/tag/v0.1.5), commit [`e1f449c`](https://github.com/derv82/wifit3/commit/e1f449c0248a8ad1d4080975ca0368d3f44d75d6), instead of following a moving branch.
- At inspected commit [`650de6e`](https://github.com/derv82/wifit3/commit/650de6ead251734be267c5550ee4eedea8b26d86), its [RTL8821CU supported-ID table](https://github.com/derv82/wifit3/blob/650de6ead251734be267c5550ee4eedea8b26d86/src/wifit3/chips/rtl8821cu_dkms/__init__.py) includes `0x0bda:0xc811`.
- Its [RTL8821CU implementation notes](https://github.com/derv82/wifit3/blob/650de6ead251734be267c5550ee4eedea8b26d86/src/wifit3/chips/rtl8821cu_dkms/RTL8821CU_DKMS.md) report working firmware boot, monitor RX, TX, channel control, and hardware ACK on an RTL8821CU reference adapter. We verified the same operations on the MindRove-branded `0xc811` variant.
- Wifit3 implements monitor/injection behavior, not a managed station or an operating-system network interface. It is a chipset base, not an installable solution for this use case.
- The upstream RTL8821CU/device-ID tests and this project's station/bridge tests pass locally. Live hardware validation confirms the physical `0xc811` adapter can authenticate, obtain a lease, exchange protected frames, and relay MindRove data.

### Firmware hold

Wifit3 currently includes an RTL8821CU firmware image, but the inspected asset directory lacks an adjacent license and its firmware provenance document does not enumerate that specific blob. The separately published linux-firmware image has a Realtek notice, but its patent language for combinations with an OSI-approved operating system needs clarification for macOS. This repository therefore includes no firmware. Seek clarification from Wifit3 upstream and Realtek/MindRove before redistributing one.

## macOS API boundary

- Apple's [DriverKit creation guidance](https://developer.apple.com/documentation/driverkit/creating-a-driver-using-the-driverkit-sdk) says DriverKit does not support USB devices that communicate wirelessly over Wi-Fi.
- [NetworkingDriverKit](https://developer.apple.com/documentation/networkingdriverkit) supports Ethernet network interfaces.
- [CoreWLAN's `CWInterface`](https://developer.apple.com/documentation/corewlan/cwinterface) controls an existing Wi-Fi interface; it does not provide a third-party hardware-driver boundary.
- [IOUSBHost](https://developer.apple.com/documentation/iousbhost) does provide user-space USB access, which is consistent with Wifit3's working libusb approach.
- A selective [Network Extension route](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic) is technically interesting, but Apple's [TN3120](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers) defines packet tunnels as VPN technology and warns against unsupported uses.

Conclusion: a normal Wi-Fi-menu driver cannot be built with supported public DriverKit APIs. A narrow user-space MindRove transport is feasible; compatibility through a virtual interface needs a separate Apple policy decision.

## MindRove link facts

- MindRove's [supported-board documentation](https://docs.mindrove.com/main/SupportedBoards.html) gives the default Wi-Fi shield address as `192.168.4.1` and port `4210`.
- The [MindRove Connect v2.10 manual](https://mindrove.com/wp-content/uploads/2026/06/MindRove_Connect_User_Manual_v2_10_0.pdf) describes a password-protected `MindRove_<type>_<ssid>` network. Live capture confirmed WPA2-PSK with CCMP and no protected-management-frame requirement on the tested unit.
- The official [MindRove SDK](https://github.com/MindRove/MindRoveSDK) is public and can serve as the application-side compatibility reference.
- Firmware analysis and live DHCP capture show that this unit streams to `192.168.4.2`; the bridge therefore explicitly requests and validates that lease. Each observed UDP payload is 216 bytes and carries two consecutive signal samples.
- Decoder comparison with the SDK and live validation establish a 108-byte
  little-endian record: eight 32-bit EXG values, ten resistance values, battery,
  trigger, accelerometer XYZ, gyroscope XYZ, and a measurement counter. Records
  arrive at 500 Hz; changing IMU vectors were observed at approximately 50 Hz.

## Decision

1. Use the native user-space bridge as the primary macOS path for this exact adapter.
2. Keep the Linux VM design as a fallback for untested adapter or firmware variants.
3. Continue coordinating the Wifit3-derived chipset work and preserving GPL provenance.
4. Do not require legacy kernel extensions, virtual interfaces, or reduced macOS security.
