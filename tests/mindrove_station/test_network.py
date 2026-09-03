# SPDX-License-Identifier: GPL-2.0-only

from ipaddress import IPv4Address
import random
import struct
import unittest

from mindrove_station.errors import FrameFormatError, IntegrityError
from mindrove_station.network import (
    ARPOperation,
    IP_PROTOCOL_UDP,
    MINDROVE_NETWORK,
    MINDROVE_PEER_IP,
    MINDROVE_STREAM_PORT,
    MindRoveNetworkState,
    MindRoveStaticConfig,
    build_arp_reply,
    build_arp_request,
    build_ipv4,
    build_udp,
    internet_checksum,
    parse_arp,
    parse_ipv4,
    parse_ipv4_udp,
    parse_udp,
)


HOST_IP = IPv4Address("192.168.4.2")
PEER_IP = IPv4Address("192.168.4.1")
OTHER_IP = IPv4Address("192.168.4.3")
HOST_MAC = bytes.fromhex("021122334455")
PEER_MAC = bytes.fromhex("02aabbccddee")
OTHER_MAC = bytes.fromhex("02deadbeef01")

# Fixed, externally checkable vector: IPv4 ID 0x1234, DF, UDP 4210 -> 4210,
# payload "MindRove".  The IPv4 and UDP checksums are 0x9f41 and 0xd0f3.
UDP_VECTOR = bytes.fromhex("107210720010d0f34d696e64526f7665")
IPV4_UDP_VECTOR = bytes.fromhex(
    "450000241234400040119f41c0a80401c0a80402" "107210720010d0f34d696e64526f7665"
)
ARP_REQUEST_VECTOR = bytes.fromhex(
    "0001080006040001" "021122334455c0a80402" "000000000000c0a80401"
)
ARP_REPLY_VECTOR = bytes.fromhex(
    "0001080006040002" "02aabbccddeec0a80401" "021122334455c0a80402"
)


class ChecksumTests(unittest.TestCase):
    def test_rfc_1071_style_ipv4_header_vector(self):
        header = bytes.fromhex("45000073000040004011b861c0a80001c0a800c7")
        self.assertEqual(internet_checksum(header), 0)
        self.assertEqual(
            internet_checksum(header[:10] + b"\x00\x00" + header[12:]), 0xB861
        )

    def test_odd_byte_is_zero_padded(self):
        self.assertEqual(internet_checksum(bytes.fromhex("0001f2")), 0x0DFE)


class IPv4Tests(unittest.TestCase):
    def test_fixed_vector_parses_and_builds(self):
        parsed = parse_ipv4(IPV4_UDP_VECTOR)
        self.assertEqual(parsed.source, PEER_IP)
        self.assertEqual(parsed.destination, HOST_IP)
        self.assertEqual(parsed.protocol, IP_PROTOCOL_UDP)
        self.assertEqual(parsed.identification, 0x1234)
        self.assertTrue(parsed.dont_fragment)
        self.assertEqual(parsed.header_checksum, 0x9F41)
        self.assertEqual(parsed.payload, UDP_VECTOR)
        self.assertEqual(
            build_ipv4(
                UDP_VECTOR,
                PEER_IP,
                HOST_IP,
                IP_PROTOCOL_UDP,
                identification=0x1234,
            ),
            IPV4_UDP_VECTOR,
        )

    def test_bad_header_checksum_is_rejected(self):
        corrupt = bytearray(IPV4_UDP_VECTOR)
        corrupt[8] ^= 1
        with self.assertRaises(IntegrityError):
            parse_ipv4(corrupt)

    def test_options_and_every_form_of_fragmentation_are_explicitly_rejected(self):
        with self.assertRaisesRegex(FrameFormatError, "options"):
            parse_ipv4(bytes((0x46,)) + IPV4_UDP_VECTOR[1:] + b"\x00\x00\x00\x00")

        for flags_fragment in (0x2000, 0x0001, 0x2001):
            header = bytearray(IPV4_UDP_VECTOR[:20])
            header[6:8] = struct.pack("!H", flags_fragment)
            header[10:12] = b"\x00\x00"
            header[10:12] = struct.pack("!H", internet_checksum(header))
            with self.assertRaisesRegex(FrameFormatError, "fragmented"):
                parse_ipv4(bytes(header) + IPV4_UDP_VECTOR[20:])

    def test_reserved_flag_and_length_mismatch_are_rejected(self):
        header = bytearray(IPV4_UDP_VECTOR[:20])
        header[6:8] = struct.pack("!H", 0x8000)
        header[10:12] = b"\x00\x00"
        header[10:12] = struct.pack("!H", internet_checksum(header))
        with self.assertRaisesRegex(FrameFormatError, "reserved"):
            parse_ipv4(bytes(header) + IPV4_UDP_VECTOR[20:])
        with self.assertRaises(FrameFormatError):
            parse_ipv4(IPV4_UDP_VECTOR + b"padding")
        with self.assertRaises(FrameFormatError):
            parse_ipv4(IPV4_UDP_VECTOR[:-1])

    def test_large_payload_and_invalid_fields_are_rejected(self):
        with self.assertRaises(ValueError):
            build_ipv4(b"x" * 65516, PEER_IP, HOST_IP, 17)
        for kwargs in ({"protocol": 256}, {"protocol": -1}, {"protocol": True}):
            with self.assertRaises(ValueError):
                build_ipv4(b"", PEER_IP, HOST_IP, **kwargs)


class UDPTests(unittest.TestCase):
    def test_fixed_vector_checksum_parses_and_builds(self):
        parsed = parse_udp(UDP_VECTOR, PEER_IP, HOST_IP)
        self.assertEqual(parsed.source_port, MINDROVE_STREAM_PORT)
        self.assertEqual(parsed.destination_port, MINDROVE_STREAM_PORT)
        self.assertEqual(parsed.payload, b"MindRove")
        self.assertTrue(parsed.checksum_present)
        self.assertEqual(
            build_udp(
                b"MindRove",
                MINDROVE_STREAM_PORT,
                MINDROVE_STREAM_PORT,
                PEER_IP,
                HOST_IP,
            ),
            UDP_VECTOR,
        )

    def test_ipv4_udp_composed_parser_validates_both_layers(self):
        ipv4, udp = parse_ipv4_udp(IPV4_UDP_VECTOR)
        self.assertEqual(ipv4.payload, UDP_VECTOR)
        self.assertEqual(udp.payload, b"MindRove")

    def test_payload_or_pseudo_header_corruption_is_rejected(self):
        corrupt = bytearray(UDP_VECTOR)
        corrupt[-1] ^= 1
        with self.assertRaises(IntegrityError):
            parse_udp(corrupt, PEER_IP, HOST_IP)
        with self.assertRaises(IntegrityError):
            parse_udp(UDP_VECTOR, OTHER_IP, HOST_IP)

    def test_zero_ipv4_udp_checksum_policy_is_explicit(self):
        zero_checksum = UDP_VECTOR[:6] + b"\x00\x00" + UDP_VECTOR[8:]
        parsed = parse_udp(zero_checksum, PEER_IP, HOST_IP)
        self.assertFalse(parsed.checksum_present)
        with self.assertRaisesRegex(IntegrityError, "absent"):
            parse_udp(
                zero_checksum,
                PEER_IP,
                HOST_IP,
                allow_zero_checksum=False,
            )

    def test_strict_udp_lengths(self):
        with self.assertRaises(FrameFormatError):
            parse_udp(UDP_VECTOR[:-1], PEER_IP, HOST_IP)
        with self.assertRaises(FrameFormatError):
            parse_udp(UDP_VECTOR + b"padding", PEER_IP, HOST_IP)
        too_short_length = UDP_VECTOR[:4] + b"\x00\x07" + UDP_VECTOR[6:]
        with self.assertRaises(FrameFormatError):
            parse_udp(too_short_length, PEER_IP, HOST_IP)


class ARPTests(unittest.TestCase):
    def test_request_fixed_vector(self):
        self.assertEqual(
            build_arp_request(HOST_MAC, HOST_IP, PEER_IP), ARP_REQUEST_VECTOR
        )
        parsed = parse_arp(ARP_REQUEST_VECTOR)
        self.assertEqual(parsed.operation, ARPOperation.REQUEST)
        self.assertEqual(parsed.sender_hardware, HOST_MAC)
        self.assertEqual(parsed.sender_protocol, HOST_IP)
        self.assertEqual(parsed.target_hardware, b"\x00" * 6)
        self.assertEqual(parsed.target_protocol, PEER_IP)

    def test_reply_fixed_vector(self):
        self.assertEqual(
            build_arp_reply(PEER_MAC, PEER_IP, HOST_MAC, HOST_IP),
            ARP_REPLY_VECTOR,
        )
        parsed = parse_arp(ARP_REPLY_VECTOR)
        self.assertEqual(parsed.operation, ARPOperation.REPLY)
        self.assertEqual(parsed.sender_hardware, PEER_MAC)
        self.assertEqual(parsed.target_hardware, HOST_MAC)

    def test_wrong_length_types_address_sizes_and_operation_are_rejected(self):
        for length in range(len(ARP_REQUEST_VECTOR)):
            with self.assertRaises(FrameFormatError):
                parse_arp(ARP_REQUEST_VECTOR[:length])
        with self.assertRaises(FrameFormatError):
            parse_arp(ARP_REQUEST_VECTOR + b"\x00")
        for offset, replacement in (
            (0, b"\x00\x02"),
            (2, b"\x86\xdd"),
            (4, b"\x05"),
            (5, b"\x10"),
            (6, b"\x00\x03"),
        ):
            corrupt = bytearray(ARP_REQUEST_VECTOR)
            corrupt[offset : offset + len(replacement)] = replacement
            with self.assertRaises(FrameFormatError):
                parse_arp(corrupt)


class MindRoveStateTests(unittest.TestCase):
    def test_static_config_is_confined_to_mindrove_subnet(self):
        config = MindRoveStaticConfig("192.168.4.42")
        self.assertEqual(config.host_ip, IPv4Address("192.168.4.42"))
        self.assertEqual(config.peer_ip, MINDROVE_PEER_IP)
        self.assertEqual(config.prefix_length, 24)
        self.assertEqual(config.stream_port, MINDROVE_STREAM_PORT)
        self.assertIn(config.host_ip, MINDROVE_NETWORK)
        for invalid in (
            "192.168.3.2",
            "192.168.4.0",
            "192.168.4.1",
            "192.168.4.255",
            "not-an-address",
        ):
            with self.assertRaises(ValueError):
                MindRoveStaticConfig(invalid)

    def test_arp_request_reply_learning_and_response(self):
        state = MindRoveNetworkState(HOST_MAC)
        self.assertEqual(state.build_arp_request(), ARP_REQUEST_VECTOR)
        self.assertIsNone(state.peer_mac)
        self.assertIsNone(state.handle_arp(ARP_REPLY_VECTOR))
        self.assertEqual(state.peer_mac, PEER_MAC)

        peer_request = build_arp_request(PEER_MAC, PEER_IP, HOST_IP)
        expected_reply = build_arp_reply(HOST_MAC, HOST_IP, PEER_MAC, PEER_IP)
        self.assertEqual(state.handle_arp(peer_request), expected_reply)

    def test_arp_state_ignores_spoofed_or_unrelated_packets(self):
        state = MindRoveNetworkState(HOST_MAC)
        spoofed_reply = build_arp_reply(OTHER_MAC, OTHER_IP, HOST_MAC, HOST_IP)
        self.assertIsNone(state.handle_arp(spoofed_reply))
        self.assertIsNone(state.peer_mac)

        multicast_sender = bytes.fromhex("010000000001")
        invalid_sender = build_arp_reply(multicast_sender, PEER_IP, HOST_MAC, HOST_IP)
        self.assertIsNone(state.handle_arp(invalid_sender))
        self.assertIsNone(state.peer_mac)

        wrong_target = build_arp_reply(PEER_MAC, PEER_IP, OTHER_MAC, HOST_IP)
        self.assertIsNone(state.handle_arp(wrong_target))
        self.assertIsNone(state.peer_mac)

    def test_outgoing_udp_is_peer_only_and_identification_increments(self):
        state = MindRoveNetworkState(HOST_MAC, MindRoveStaticConfig("192.168.4.42"))
        first_ip, first_udp = parse_ipv4_udp(state.build_udp(b"one", source_port=50000))
        second_ip, second_udp = parse_ipv4_udp(
            state.build_udp(b"two", source_port=50000)
        )
        self.assertEqual(first_ip.source, IPv4Address("192.168.4.42"))
        self.assertEqual(first_ip.destination, PEER_IP)
        self.assertEqual(first_ip.identification, 0)
        self.assertEqual(second_ip.identification, 1)
        self.assertEqual(first_udp.destination_port, MINDROVE_STREAM_PORT)
        self.assertEqual(first_udp.payload, b"one")
        self.assertEqual(second_udp.payload, b"two")

    def test_receive_delivers_exactly_peer_udp_4210_for_host_or_broadcast(self):
        state = MindRoveNetworkState(HOST_MAC)
        destinations = (HOST_IP, MINDROVE_NETWORK.broadcast_address, "255.255.255.255")
        for destination in destinations:
            udp = build_udp(
                b"samples", 50000, MINDROVE_STREAM_PORT, PEER_IP, destination
            )
            packet = build_ipv4(udp, PEER_IP, destination, IP_PROTOCOL_UDP)
            delivered = state.receive_ipv4(packet)
            self.assertIsNotNone(delivered)
            self.assertEqual(delivered.payload, b"samples")
            self.assertEqual(delivered.source_port, 50000)
            self.assertEqual(delivered.destination_port, MINDROVE_STREAM_PORT)

        wrong_port = build_udp(b"no", 50000, 4209, PEER_IP, HOST_IP)
        wrong_source = build_udp(b"no", 50000, MINDROVE_STREAM_PORT, OTHER_IP, HOST_IP)
        wrong_destination = build_udp(
            b"no", 50000, MINDROVE_STREAM_PORT, PEER_IP, OTHER_IP
        )
        self.assertIsNone(
            state.receive_ipv4(
                build_ipv4(wrong_port, PEER_IP, HOST_IP, IP_PROTOCOL_UDP)
            )
        )
        self.assertIsNone(
            state.receive_ipv4(
                build_ipv4(wrong_source, OTHER_IP, HOST_IP, IP_PROTOCOL_UDP)
            )
        )
        self.assertIsNone(
            state.receive_ipv4(
                build_ipv4(wrong_destination, PEER_IP, OTHER_IP, IP_PROTOCOL_UDP)
            )
        )
        self.assertIsNone(state.receive_ipv4(build_ipv4(b"icmp", PEER_IP, HOST_IP, 1)))


class MalformedInputFuzzTests(unittest.TestCase):
    def test_ipv4_and_udp_truncation_and_single_bit_mutations_fail_cleanly(self):
        expected = (FrameFormatError, IntegrityError)
        for length in range(len(IPV4_UDP_VECTOR)):
            with self.assertRaises(expected):
                parse_ipv4_udp(IPV4_UDP_VECTOR[:length])

        # Every single-bit mutation in the IPv4 header must be caught by
        # structure checks or its header checksum.  UDP payload mutations must
        # be caught by the UDP checksum.
        for byte_offset in range(len(IPV4_UDP_VECTOR)):
            for bit in range(8):
                corrupt = bytearray(IPV4_UDP_VECTOR)
                corrupt[byte_offset] ^= 1 << bit
                with self.assertRaises(expected):
                    parse_ipv4_udp(corrupt)

    def test_deterministic_random_garbage_never_leaks_low_level_exceptions(self):
        rng = random.Random(0x4210)
        parsers = (
            lambda value: parse_ipv4(value),
            lambda value: parse_udp(value, PEER_IP, HOST_IP),
            lambda value: parse_arp(value),
        )
        for _ in range(500):
            value = rng.randbytes(rng.randrange(0, 80))
            for parser in parsers:
                try:
                    parser(value)
                except (FrameFormatError, IntegrityError):
                    pass


if __name__ == "__main__":
    unittest.main()
