# SPDX-License-Identifier: GPL-2.0-only

from __future__ import annotations

from ipaddress import IPv4Address
import struct
from types import SimpleNamespace
import unittest
from typing import Optional

from mindrove_station.ccmp import CCMPHeader
from mindrove_station.data import build_ap_data, parse_data
from mindrove_station.llc import EtherType
from mindrove_station.network import (
    IP_PROTOCOL_UDP,
    build_ipv4,
    build_udp,
    parse_ipv4_udp,
)
from tools.mindrove_bridge.dhcp import (
    DHCPError,
    DHCPMessageType,
    MindRoveDHCPClient,
)
from tools.mindrove_bridge.config import BridgeConfig
from tools.mindrove_bridge.wpa2_provider import DHCPTimeout, SecureMindRoveDataPlane


MAC = bytes.fromhex("7666cbe6e8c7")
SERVER = IPv4Address("192.168.4.1")
LEASE = IPv4Address("192.168.4.2")
XID = 0x12345678
COOKIE = b"\x63\x82\x53\x63"
BSSID = bytes.fromhex("102030405060")


def option(code: int, value: bytes) -> bytes:
    return bytes((code, len(value))) + value


def reply(
    message_type: DHCPMessageType,
    *,
    xid: int = XID,
    mac: bytes = MAC,
    address: IPv4Address = LEASE,
    siaddr: IPv4Address = SERVER,
    include_server: bool = True,
    subnet: Optional[IPv4Address] = IPv4Address("255.255.255.0"),
    router: Optional[IPv4Address] = SERVER,
    extra_options: bytes = b"",
    end: bool = True,
) -> bytes:
    fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        2,
        1,
        6,
        0,
        xid,
        0,
        0x8000,
        bytes(4),
        address.packed,
        siaddr.packed,
        bytes(4),
        mac + bytes(10),
        bytes(64),
        bytes(128),
    )
    options = option(53, bytes((int(message_type),)))
    if include_server:
        options += option(54, SERVER.packed)
    if subnet is not None:
        options += option(1, subnet.packed)
    if router is not None:
        options += option(3, router.packed)
    options += option(51, struct.pack("!I", 3600)) + extra_options
    if end:
        options += b"\xff"
    return fixed + COOKIE + options


def parsed_options(packet: bytes) -> dict[int, bytes]:
    result = {}
    offset = 240
    while packet[offset] != 255:
        code = packet[offset]
        offset += 1
        if code == 0:
            continue
        length = packet[offset]
        offset += 1
        result[code] = packet[offset : offset + length]
        offset += length
    return result


class DHCPClientTests(unittest.TestCase):
    def setUp(self):
        self.client = MindRoveDHCPClient(MAC, transaction_id=XID)

    def test_discover_and_request_have_bounded_bootp_wire_layout(self):
        discover = self.client.discover()
        self.assertEqual(len(discover), 300)
        self.assertEqual(discover[:4], b"\x01\x01\x06\x00")
        self.assertEqual(discover[4:8], XID.to_bytes(4, "big"))
        self.assertEqual(discover[10:12], b"\x80\x00")
        self.assertEqual(discover[28:44], MAC + bytes(10))
        self.assertEqual(discover[236:240], COOKIE)
        discover_options = parsed_options(discover)
        self.assertEqual(discover_options[53], b"\x01")
        self.assertEqual(discover_options[61], b"\x01" + MAC)
        self.assertEqual(discover_options[50], LEASE.packed)
        self.assertEqual(discover_options[57], b"\x05\xdc")

        offer = self.client.parse_offer(reply(DHCPMessageType.OFFER), source_ip=SERVER)
        request = self.client.request(offer)
        request_options = parsed_options(request)
        self.assertEqual(request_options[53], b"\x03")
        self.assertEqual(request_options[50], LEASE.packed)
        self.assertEqual(request_options[54], SERVER.packed)

    def test_offer_ack_install_narrow_lease_with_optional_fallbacks(self):
        offer = self.client.parse_offer(
            reply(
                DHCPMessageType.OFFER,
                include_server=False,
                subnet=None,
                router=None,
            ),
            source_ip=SERVER,
        )
        lease = self.client.parse_ack(
            reply(
                DHCPMessageType.ACK,
                include_server=False,
                subnet=None,
                router=None,
            ),
            offer,
            source_ip=SERVER,
        )
        self.assertEqual(lease.address, LEASE)
        self.assertEqual(lease.server, SERVER)
        self.assertEqual(lease.subnet_mask, IPv4Address("255.255.255.0"))
        self.assertEqual(lease.router, SERVER)
        self.assertEqual(lease.lease_seconds, 3600)

    def test_transaction_mac_server_and_profile_are_strict(self):
        bad_packets = (
            reply(DHCPMessageType.OFFER, xid=XID + 1),
            reply(DHCPMessageType.OFFER, mac=bytes.fromhex("021122334455")),
            reply(
                DHCPMessageType.OFFER,
                address=IPv4Address("10.0.0.2"),
            ),
            reply(
                DHCPMessageType.OFFER,
                address=IPv4Address("192.168.4.3"),
            ),
            reply(
                DHCPMessageType.OFFER,
                subnet=IPv4Address("255.255.0.0"),
            ),
            reply(
                DHCPMessageType.OFFER,
                router=IPv4Address("192.168.4.9"),
            ),
        )
        for packet in bad_packets:
            with self.subTest(packet=packet[4:20].hex()):
                with self.assertRaises(DHCPError):
                    self.client.parse_offer(packet, source_ip=SERVER)
        with self.assertRaises(DHCPError):
            self.client.parse_offer(
                reply(DHCPMessageType.OFFER),
                source_ip=IPv4Address("192.168.4.9"),
            )

    def test_option_framing_duplicates_overload_and_end_are_strict(self):
        malformed = (
            reply(
                DHCPMessageType.OFFER,
                extra_options=option(53, b"\x02"),
            ),
            reply(
                DHCPMessageType.OFFER,
                extra_options=option(52, b"\x01"),
            ),
            reply(DHCPMessageType.OFFER, extra_options=b"\x99\x04\x00"),
            reply(DHCPMessageType.OFFER, end=False),
        )
        for packet in malformed:
            with self.subTest(tail=packet[-12:].hex()):
                with self.assertRaises(DHCPError):
                    self.client.parse_offer(packet, source_ip=SERVER)

    def test_ack_must_match_selected_offer_and_nak_is_rejected(self):
        offer = self.client.parse_offer(reply(DHCPMessageType.OFFER), source_ip=SERVER)
        with self.assertRaises(DHCPError):
            self.client.parse_ack(
                reply(DHCPMessageType.ACK, address=IPv4Address("192.168.4.3")),
                offer,
                source_ip=SERVER,
            )
        with self.assertRaisesRegex(DHCPError, "rejected"):
            self.client.parse_ack(
                reply(
                    DHCPMessageType.NAK,
                    address=IPv4Address("0.0.0.0"),
                ),
                offer,
                source_ip=SERVER,
            )


class DHCPDataPlaneTests(unittest.IsolatedAsyncioTestCase):
    async def test_protected_discover_offer_request_ack_precedes_arp(self):
        broadcast_ip = IPv4Address("255.255.255.255")

        def dhcp_ipv4(message_type: DHCPMessageType) -> bytes:
            udp = build_udp(
                reply(message_type),
                67,
                68,
                SERVER,
                broadcast_ip,
            )
            return build_ipv4(
                udp,
                SERVER,
                broadcast_ip,
                IP_PROTOCOL_UDP,
            )

        plaintexts = [
            build_ap_data(
                BSSID,
                b"\xff" * 6,
                BSSID,
                dhcp_ipv4(DHCPMessageType.OFFER),
                EtherType.IPV4,
                sequence_number=1,
            ),
            build_ap_data(
                BSSID,
                b"\xff" * 6,
                BSSID,
                dhcp_ipv4(DHCPMessageType.ACK),
                EtherType.IPV4,
                sequence_number=2,
            ),
        ]

        class Receiver:
            def __init__(self, _key, **_kwargs):
                pass

            def decrypt(self, _raw):
                return SimpleNamespace(frame=plaintexts.pop(0))

        class Transmitter:
            def __init__(self, _key):
                pass

            @staticmethod
            def encrypt(plaintext):
                return plaintext

        def protected_group_frame(packet_number: int) -> bytes:
            frame = bytearray(
                build_ap_data(
                    BSSID,
                    b"\xff" * 6,
                    BSSID,
                    b"",
                    EtherType.IPV4,
                    sequence_number=packet_number,
                )[:24]
                + CCMPHeader(packet_number=packet_number, key_id=1).encode()
                + b"ciphertext-and-mic"
            )
            frame[1] |= 0x40
            return bytes(frame)

        class Exchange:
            def __init__(self):
                self.config = BridgeConfig("MindRove_Test", BSSID, 6)
                self.station_mac = MAC
                self.frames = [protected_group_frame(1), protected_group_frame(2)]
                self.sent = []
                self.status = []

            async def receive_frame(self, _timeout=None):
                return self.frames.pop(0)

            async def send_frame(self, frame):
                self.sent.append(frame)

            def report_status(self, message):
                self.status.append(message)

        handshake = SimpleNamespace(
            complete=True,
            pairwise_keys=SimpleNamespace(temporal_key=b"P" * 16),
            group_key=SimpleNamespace(
                temporal_key=b"G" * 16,
                key_id=1,
                receive_packet_number=0,
            ),
        )
        exchange = Exchange()
        plane = SecureMindRoveDataPlane(
            exchange,  # type: ignore[arg-type]
            handshake,  # type: ignore[arg-type]
            receiver_factory=Receiver,
            transmitter_factory=Transmitter,
            dhcp_factory=lambda mac: MindRoveDHCPClient(mac, transaction_id=XID),
            ephemeral_port_factory=lambda: 60000,
        )

        lease = await plane.acquire_lease(
            attempts=1,
            offer_timeout=0.1,
            ack_timeout=0.1,
        )

        self.assertEqual(lease.address, LEASE)
        self.assertEqual(plane.network.config.host_ip, LEASE)
        self.assertEqual(len(exchange.sent), 2)
        first_data = parse_data(exchange.sent[0])
        first_ip, first_udp = parse_ipv4_udp(first_data.llc.payload)
        self.assertEqual(first_ip.source, IPv4Address("0.0.0.0"))
        self.assertEqual(first_ip.destination, broadcast_ip)
        self.assertEqual((first_udp.source_port, first_udp.destination_port), (68, 67))
        self.assertEqual(parsed_options(first_udp.payload)[53], b"\x01")
        second_data = parse_data(exchange.sent[1])
        _, second_udp = parse_ipv4_udp(second_data.llc.payload)
        self.assertEqual(parsed_options(second_udp.payload)[53], b"\x03")

        await plane.request_peer_mac()
        self.assertEqual(len(exchange.sent), 3)
        self.assertEqual(parse_data(exchange.sent[2]).llc.ethertype, int(EtherType.ARP))
        self.assertTrue(any("installed DHCP lease" in item for item in exchange.status))

    async def test_dhcp_retries_are_bounded_and_reported(self):
        class Exchange:
            def __init__(self):
                self.config = BridgeConfig("MindRove_Test", BSSID, 6)
                self.station_mac = MAC
                self.sent = []
                self.status = []

            async def receive_frame(self, _timeout=None):
                raise TimeoutError("fixture timeout")

            async def send_frame(self, frame):
                self.sent.append(frame)

            def report_status(self, message):
                self.status.append(message)

        class Receiver:
            def __init__(self, _key, **_kwargs):
                pass

        class Transmitter:
            def __init__(self, _key):
                pass

            @staticmethod
            def encrypt(plaintext):
                return plaintext

        handshake = SimpleNamespace(
            complete=True,
            pairwise_keys=SimpleNamespace(temporal_key=b"P" * 16),
            group_key=SimpleNamespace(
                temporal_key=b"G" * 16,
                key_id=1,
                receive_packet_number=0,
            ),
        )
        exchange = Exchange()
        plane = SecureMindRoveDataPlane(
            exchange,  # type: ignore[arg-type]
            handshake,  # type: ignore[arg-type]
            receiver_factory=Receiver,
            transmitter_factory=Transmitter,
            dhcp_factory=lambda mac: MindRoveDHCPClient(mac, transaction_id=XID),
            ephemeral_port_factory=lambda: 60000,
        )

        with self.assertRaises(DHCPTimeout):
            await plane.acquire_lease(
                attempts=3,
                offer_timeout=0.01,
                ack_timeout=0.01,
            )

        self.assertEqual(len(exchange.sent), 3)
        self.assertEqual(
            sum("DHCPDISCOVER" in message for message in exchange.status),
            3,
        )


if __name__ == "__main__":
    unittest.main()
