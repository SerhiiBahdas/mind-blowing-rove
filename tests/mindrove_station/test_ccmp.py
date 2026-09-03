# SPDX-License-Identifier: GPL-2.0-only

import unittest

from mindrove_station import EtherType, build_ap_data, build_station_data, parse_data
from mindrove_station.ccmp import (
    CCMPHeader,
    CCMPReceiver,
    CCMPTransmitter,
    ccmp_aad,
    ccmp_nonce,
    decrypt_ccmp,
    encrypt_ccmp,
)
from mindrove_station.errors import FrameFormatError, IntegrityError, ReplayError


STATION = bytes.fromhex("021122334455")
ACCESS_POINT = bytes.fromhex("02aabbccddee")
GATEWAY = bytes.fromhex("02deadbeef01")
TEMPORAL_KEY = bytes(range(16))
IP_PACKET = bytes.fromhex("45000014000000004011a6d1c0a80402c0a80401")


class CCMPHeaderTests(unittest.TestCase):
    def test_packet_number_wire_order_and_key_id(self):
        header = CCMPHeader(0x010203040506, key_id=2)
        self.assertEqual(header.encode().hex(), "060500a004030201")
        self.assertEqual(CCMPHeader.parse(header.encode()), header)

    def test_reserved_bits_zero_pn_and_bad_extiv_are_rejected(self):
        with self.assertRaises(FrameFormatError):
            CCMPHeader.parse(bytes.fromhex("0102012000000000"))
        with self.assertRaises(FrameFormatError):
            CCMPHeader.parse(bytes.fromhex("0102000000000000"))
        with self.assertRaises(ReplayError):
            CCMPHeader.parse(bytes.fromhex("0000002000000000"))


class CCMPPacketTests(unittest.TestCase):
    def setUp(self):
        self.plaintext = build_station_data(
            STATION,
            ACCESS_POINT,
            GATEWAY,
            IP_PACKET,
            EtherType.IPV4,
            sequence_number=0x345,
            qos_tid=5,
        )

    def test_known_header_aad_nonce_and_ciphertext(self):
        protected = encrypt_ccmp(
            self.plaintext,
            TEMPORAL_KEY,
            0x010203040506,
        )
        self.assertEqual(
            protected.hex(),
            "8841000002aabbccddee02112233445502deadbeef0150340500"
            "0605002004030201"
            "236be29bd643dc42b9eaf96f9895aacefa223859595ccc27"
            "f0863b98807b2be25326305f",
        )
        self.assertEqual(
            ccmp_aad(protected).hex(),
            "884102aabbccddee02112233445502deadbeef0100000500",
        )
        self.assertEqual(
            ccmp_nonce(protected, 0x010203040506).hex(),
            "05021122334455010203040506",
        )

        result = decrypt_ccmp(protected, TEMPORAL_KEY)
        self.assertEqual(result.frame, self.plaintext)
        self.assertEqual(result.plaintext_body, parse_data(self.plaintext).body)
        self.assertEqual(result.packet_number, 0x010203040506)
        self.assertEqual(result.qos_tid, 5)

    def test_mic_covers_ciphertext_header_and_aad(self):
        protected = bytearray(encrypt_ccmp(self.plaintext, TEMPORAL_KEY, 1))
        for offset in (1, 4, 30, len(protected) - 1):
            damaged = bytearray(protected)
            damaged[offset] ^= 1
            with self.assertRaises((IntegrityError, FrameFormatError)):
                decrypt_ccmp(bytes(damaged), TEMPORAL_KEY)

    def test_plaintext_and_wrong_key_are_rejected(self):
        with self.assertRaises(FrameFormatError):
            decrypt_ccmp(self.plaintext, TEMPORAL_KEY)
        protected = encrypt_ccmp(self.plaintext, TEMPORAL_KEY, 1)
        with self.assertRaises(IntegrityError):
            decrypt_ccmp(protected, b"\xff" * 16)


class CCMPStateTests(unittest.TestCase):
    def test_transmitter_never_reuses_packet_numbers(self):
        transmitter = CCMPTransmitter(TEMPORAL_KEY)
        first = transmitter.encrypt(
            build_station_data(
                STATION,
                ACCESS_POINT,
                GATEWAY,
                b"one",
                EtherType.IPV4,
                sequence_number=1,
            )
        )
        second = transmitter.encrypt(
            build_station_data(
                STATION,
                ACCESS_POINT,
                GATEWAY,
                b"two",
                EtherType.IPV4,
                sequence_number=2,
            )
        )
        self.assertEqual(CCMPHeader.parse(parse_data(first, decode_llc=False).body[:8]).packet_number, 1)
        self.assertEqual(CCMPHeader.parse(parse_data(second, decode_llc=False).body[:8]).packet_number, 2)
        self.assertEqual(transmitter.next_packet_number, 3)

    def test_receiver_rejects_duplicates_and_out_of_order_packets(self):
        receiver = CCMPReceiver(TEMPORAL_KEY)
        high = build_ap_data(
            ACCESS_POINT,
            STATION,
            GATEWAY,
            b"high",
            EtherType.IPV4,
            sequence_number=1,
        )
        low = build_ap_data(
            ACCESS_POINT,
            STATION,
            GATEWAY,
            b"low",
            EtherType.IPV4,
            sequence_number=2,
        )
        high_protected = encrypt_ccmp(high, TEMPORAL_KEY, 10)
        low_protected = encrypt_ccmp(low, TEMPORAL_KEY, 9)
        self.assertEqual(receiver.decrypt(high_protected).frame, high)
        with self.assertRaises(ReplayError):
            receiver.decrypt(high_protected)
        with self.assertRaises(ReplayError):
            receiver.decrypt(low_protected)
        self.assertEqual(receiver.last_packet_number(ACCESS_POINT), 10)

    def test_bad_mic_does_not_consume_packet_number(self):
        receiver = CCMPReceiver(TEMPORAL_KEY)
        frame = build_ap_data(
            ACCESS_POINT,
            STATION,
            GATEWAY,
            b"payload",
            EtherType.IPV4,
            sequence_number=1,
        )
        protected = encrypt_ccmp(frame, TEMPORAL_KEY, 4)
        damaged = bytearray(protected)
        damaged[-1] ^= 1
        with self.assertRaises(IntegrityError):
            receiver.decrypt(bytes(damaged))
        self.assertIsNone(receiver.last_packet_number(ACCESS_POINT))
        self.assertEqual(receiver.decrypt(protected).packet_number, 4)

    def test_replay_domains_are_separate_per_qos_tid(self):
        receiver = CCMPReceiver(TEMPORAL_KEY)
        for tid in (1, 2):
            frame = build_ap_data(
                ACCESS_POINT,
                STATION,
                GATEWAY,
                bytes((tid,)),
                EtherType.IPV4,
                sequence_number=tid,
                qos_tid=tid,
            )
            receiver.decrypt(encrypt_ccmp(frame, TEMPORAL_KEY, 1))
        self.assertEqual(receiver.last_packet_number(ACCESS_POINT, qos_tid=1), 1)
        self.assertEqual(receiver.last_packet_number(ACCESS_POINT, qos_tid=2), 1)

    def test_initial_group_rsc_is_enforced_for_every_replay_domain(self):
        receiver = CCMPReceiver(
            TEMPORAL_KEY,
            expected_key_id=1,
            initial_packet_number=7,
        )
        frame = build_ap_data(
            ACCESS_POINT,
            b"\xff" * 6,
            GATEWAY,
            b"group",
            EtherType.IPV4,
            sequence_number=1,
        )
        with self.assertRaises(ReplayError):
            receiver.decrypt(encrypt_ccmp(frame, TEMPORAL_KEY, 7, key_id=1))
        accepted = receiver.decrypt(
            encrypt_ccmp(frame, TEMPORAL_KEY, 8, key_id=1)
        )
        self.assertEqual(accepted.packet_number, 8)

    def test_non_qos_and_qos_tid_zero_have_separate_replay_domains(self):
        receiver = CCMPReceiver(TEMPORAL_KEY)
        for sequence, tid in ((1, None), (2, 0)):
            frame = build_ap_data(
                ACCESS_POINT,
                STATION,
                GATEWAY,
                b"payload",
                EtherType.IPV4,
                sequence_number=sequence,
                qos_tid=tid,
            )
            receiver.decrypt(encrypt_ccmp(frame, TEMPORAL_KEY, 1))
        self.assertEqual(receiver.last_packet_number(ACCESS_POINT), 1)
        self.assertEqual(receiver.last_packet_number(ACCESS_POINT, qos_tid=0), 1)


if __name__ == "__main__":
    unittest.main()
