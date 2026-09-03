# Architecture

## Goal

Keep the Mac's built-in Wi-Fi associated with its primary internet network while a second USB adapter carries traffic to a MindRove device.

The supplied dongle is a Realtek `0x0bda:0xc811` device in the RTL8821CU /
RTL8811CU family. Recent macOS releases on Apple silicon enumerate its
vendor-specific USB interface, but no network service attaches to it.

## Constraints

There is no supported public macOS API for a third-party USB Wi-Fi driver that joins the normal Wi-Fi stack:

- Apple's DriverKit guidance explicitly excludes USB devices that communicate over Wi-Fi.
- NetworkingDriverKit supports Ethernet interfaces, not general 802.11 interfaces.
- CoreWLAN manages Wi-Fi interfaces that already exist; it is not a driver interface.
- A legacy Wi-Fi kernel extension would require reduced security on Apple silicon and private 802.11 interfaces. That is not a maintainable public solution.

The project now provides a native user-space bridge. It claims only the external Realtek adapter, so macOS keeps the built-in Wi-Fi interface and its default route unchanged.

## Track A: Linux bridge

```text
MindRove access point
        |
RTL8821CU USB dongle
        |
arm64 Linux VM + upstream rtw88
        |
host-only virtual network
        |
route only 192.168.4.0/24
        |
macOS / unmodified MindRove software

macOS built-in Wi-Fi ----------------> primary internet Wi-Fi + default route
```

The VM owns the physical USB device and associates normally using Linux's mature Wi-Fi stack. It forwards only the MindRove network to the host. macOS keeps its default route and DNS on built-in Wi-Fi.

This remains a fallback for adapter or firmware variants that the native path has not yet validated. The current macOS bridge does not require a VM.

## Track B: native user-space mini-driver (working)

[Wifit3](https://github.com/derv82/wifit3) provides the firmware boot, channel control, receive, transmit, and hardware-acknowledgement foundation for RTL8821CU from macOS through PyUSB/libusb. We validated that foundation on the MindRove adapter's exact `0x0bda:0xc811` USB ID.

The implemented data path is:

```text
MindRove access point
        |
WPA2-PSK association + CCMP
        |
Wifit3-derived RTL8821CU engine
        |
PyUSB/libusb now; native IOUSBHost later
        |
strict DHCP + ARP / IPv4 / UDP implementation
        |
authenticated MindRove UDP relay
        |
UDP loopback to unmodified MindRove Connect
```

This path deliberately targets the MindRove use case rather than attempting to become a general Wi-Fi adapter. On the tested device it validates the target BSSID and WPA2/CCMP capabilities, completes the four-way handshake, obtains the firmware-required `192.168.4.2` lease, and forwards only valid UDP/4210 payloads to loopback.

### Compatibility with MindRove Connect

The bridge feeds packets directly to the unmodified MindRove Connect app through UDP loopback without creating a macOS network interface. A Network Extension or virtual route is therefore not required.

## Track C: DriverKit experiment only

An Ethernet facade could conceivably combine USBDriverKit transport with an `IOUserNetworkEthernet` interface. It would appear as Ethernet rather than Wi-Fi, and a companion app would own scan/join state. However, this conflicts with Apple's explicit Wi-Fi exclusion and requires managed DriverKit entitlements tied to hardware vendor IDs. Work does not begin here unless Apple Developer Technical Support confirms that use and entitlement approval in writing.

## Hardware probe

The included probe establishes a reproducible baseline before any driver is installed:

- match only USB `0x0bda:0xc811`;
- record safe descriptor data;
- enumerate USB interfaces;
- detect whether a network service is attached;
- omit credentials, serial numbers, SSIDs, IP addresses, and unrelated registry content.

## Licensing and provenance

The project is GPL-2.0-only so it can legally derive chipset work from Wifit3 and the GPLv2 Linux/vendor driver sources on which Wifit3 is based. Every imported file must retain authorship and provenance. Firmware is a separate work under Realtek's firmware terms and must keep its accompanying license.

## Boundaries and non-goals

- No legacy macOS kernel extension.
- No instruction to disable System Integrity Protection, AMFI, or Full Security.
- No use of Apple's private AirPort/IO80211 interfaces.
- No general-purpose offensive Wi-Fi features.
- No collection of unrelated USB, Wi-Fi, or network information.
- No default-route or DNS replacement; only MindRove traffic leaves through the dongle.
