# MindRove station protocol primitives

This package contains only hardware-independent byte handling. It neither
opens a USB device nor transmits frames. Its current scope is:

- Open System authentication and association request/response frames;
- strict IEEE 802.11 information-element parsing;
- RSN and legacy WPA security information;
- WPA2-Personal PMK/PTK derivation and strict EAPOL-Key framing;
- replay-safe supplicant state for the WPA2 four-way handshake;
- authenticated RFC 3394 M3 key-data unwrap and strict CCMP GTK extraction;
- CCMP-128 encryption/decryption, including nonce/AAD generation and receive
  replay protection;
- RFC 1042 LLC/SNAP encapsulation for IPv4, ARP, and other EtherTypes; and
- three-/four-address data headers, including QoS header-length handling.

It deliberately does **not** implement scanning, radio timing,
fragmentation/reassembly, A-MSDU protection, GCMP, PMF group-management keys,
or a general-purpose Wi-Fi supplicant. The handshake implementation is
intentionally restricted to the observed WPA2-PSK/CCMP profile (RSN descriptor
version 2, no PMF). It accepts only AP-originated M1/M3 and caches responses to
legitimate retransmissions so keys and packet-number state are never
reinstalled.

Packet encryption delegates AES-CCM and AES-CMAC to the audited
`cryptography` package. Install the narrow dependency set before using CCMP:

```sh
python3 -m pip install -r mindrove_station/requirements.txt
```

The implementation was written from the published formats rather than copied
from another driver. Useful normative and interoperability references are:

- [IEEE 802.11 standards landing page](https://standards.ieee.org/ieee/802.11/7028/)
- [RFC 1042: IP and ARP over IEEE 802 networks](https://www.rfc-editor.org/rfc/rfc1042)
- [IANA IEEE 802 numbers](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml)
- [Wireshark IEEE 802.11 display-filter reference](https://www.wireshark.org/docs/dfref/w/wlan.html)

Run the isolated standard-library test suite from the repository root:

```sh
python3 -m unittest discover -s tests/mindrove_station -p 'test_*.py'
```
