# Linux bridge: experimental fallback

This fallback keeps macOS on its primary internet Wi-Fi and gives the Realtek dongle exclusively to a small Debian VM.

## Status

The configuration and scripts are ready for hardware testing but have not been exercised in a VM on this Mac. The native user-space bridge is the tested primary path. Firmware analysis and live capture confirm that the current device sends UDP/4210 unicast to its client at `192.168.4.2`.

## Network design

```text
primary internet Wi-Fi <- macOS built-in Wi-Fi (default route)
                    |
          UTM host-only network
          macOS 172.31.242.1
                    |
          Debian 172.31.242.2
                    |
       narrow forwarding + NAT
                    |
        USB Wi-Fi 192.168.4.x
                    |
        MindRove 192.168.4.1
```

Only a host route for `192.168.4.1` is added. Internet traffic and DNS stay on the built-in Wi-Fi.

## 1. Create the VM

Install [UTM](https://mac.getutm.app/) from its official distribution and create a Debian 13 ARM64 VM with these settings:

- backend: **QEMU**, not Apple Virtualization;
- Hypervisor enabled;
- 1 CPU, 1 GB RAM, and roughly 4 GB disk are sufficient for a headless appliance;
- USB sharing enabled, with at least one shared USB slot;
- one **Host Only** network device, with host access enabled and guest isolation disabled;
- host network `172.31.242.0/24`, host address `172.31.242.1`, guest address `172.31.242.2`.

UTM supports USB passthrough only with its QEMU backend. Its documentation also warns that macOS cannot give a passed-through device a true hardware reset, so USB capture is the first go/no-go test. See [UTM USB sharing](https://docs.getutm.app/guest-support/sharing/usb/) and [UTM network modes](https://docs.getutm.app/settings-qemu/devices/network/network/).

During initial package installation, add a second **Shared Network** interface temporarily. Remove it before normal use so the appliance has no internet-facing runtime interface.

Start Debian, use UTM's USB toolbar to attach **Realtek 802.11ac NIC (`0bda:c811`)**, and verify:

```sh
lsusb -d 0bda:c811
```

## 2. Provision Debian

Run while the temporary Shared Network interface is present:

```sh
sudo apt update
sudo apt install network-manager nftables firmware-realtek usbutils iw tcpdump
sudo modprobe rtw88_8821cu
modinfo rtw88_8821cu
ip -br link
nmcli -f DEVICE,TYPE,STATE device
```

Linux mainline explicitly supports `0bda:c811`; Debian's `firmware-realtek` package supplies `rtw88/rtw8821c_fw.bin`. If the firmware package is unavailable, enable Debian's `non-free-firmware` repository component—do not copy an unexplained firmware blob into this repository.

Identify the VM-facing Ethernet interface and USB Wi-Fi interface. The examples below call them `<HOST_IF>` and `<WLAN_IF>`.

Configure the host-only interface:

```sh
sudo nmcli con add type ethernet ifname <HOST_IF> con-name mindrove-host \
  ipv4.method manual ipv4.addresses 172.31.242.2/24 \
  ipv4.never-default yes ipv6.method disabled
```

Scan for the live device and record the reported security mode:

```sh
nmcli -f SSID,CHAN,SECURITY,SIGNAL dev wifi list ifname <WLAN_IF>
```

Connect without putting the password in shell history or this repository:

```sh
sudo nmcli --ask dev wifi connect '<EXACT_MINDROVE_SSID>' ifname <WLAN_IF>
sudo nmcli con modify '<EXACT_MINDROVE_SSID>' ipv4.never-default yes ipv6.method disabled
ping -c 3 192.168.4.1
```

The official manual documents the device password, but the bridge intentionally prompts for it rather than embedding it.

## 3. Enable the narrow router

Copy `bridge/linux/mindrove-router.sh` into the VM, then run:

```sh
sudo ./mindrove-router.sh up <HOST_IF> <WLAN_IF>
```

The script:

- enables IPv4 forwarding while preserving its previous value;
- creates only two dedicated nftables tables;
- permits the Mac host to reach only `192.168.4.1` through the radio;
- applies source NAT so the board can reply;
- directs UDP packets from the board on port `4210` to the Mac host.

It never flushes the VM's global firewall ruleset.

## 4. Add the one-host route on macOS

From this repository on the Mac:

```sh
./bridge/macos/mindrove-route.sh status
./bridge/macos/mindrove-route.sh up 172.31.242.2
```

The script asks for administrator approval only for the route change. Verify that the default route still uses built-in Wi-Fi and MindRove uses the VM:

```sh
route -n get default
route -n get 192.168.4.1
ping -c 1 192.168.4.1
```

## 5. Validate the data path

Run these captures during one short MindRove Connect attempt:

```sh
# Debian, terminal 1
sudo tcpdump -ni <WLAN_IF> 'host 192.168.4.1 or udp port 4210'

# Debian, terminal 2
sudo tcpdump -ni <HOST_IF> 'host 192.168.4.1 or udp port 4210'

# macOS
sudo tcpdump -ni any 'host 192.168.4.1 or udp port 4210'
```

The current firmware sends UDP/4210 to the Wi-Fi client at `192.168.4.2`. The nftables prerouting rule converts matching traffic from `192.168.4.1` into host-directed unicast. If traffic appears on `<WLAN_IF>` but not `<HOST_IF>`, add a small UDP relay after confirming the actual destination and port from the capture.

MindRove Connect may additionally insist that macOS itself report the MindRove SSID. If that application-level check blocks it, run the official MindRove SDK inside Debian and export samples to the Mac; the USB and routing bridge can still be reused.

## Teardown

On macOS:

```sh
./bridge/macos/mindrove-route.sh down 172.31.242.2
```

In Debian:

```sh
sudo ./mindrove-router.sh down
```

Then detach the USB device from the VM before unplugging it.
