# SPDX-License-Identifier: GPL-2.0-only

import unittest

from mindrove_station import (
    EtherType,
    FrameControl,
    FrameFormatError,
    build_ap_data,
    build_raw_data,
    build_station_data,
    decapsulate,
    encapsulate_arp,
    encapsulate_ipv4,
    parse_data,
)


STATION = bytes.fromhex("021122334455")
ACCESS_POINT = bytes.fromhex("02aabbccddee")
GATEWAY = bytes.fromhex("02deadbeef01")
BROADCAST = b"\xff" * 6


class LLCSnapTests(unittest.TestCase):
    def test_ipv4_encapsulation_uses_network_order_ethertype(self):
        packet = bytes.fromhex("45000014")
        encoded = encapsulate_ipv4(packet)
        self.assertEqual(encoded, bytes.fromhex("aaaa03000000080045000014"))
        decoded = decapsulate(encoded)
        self.assertEqual(decoded.ethertype, EtherType.IPV4)
        self.assertEqual(decoded.payload, packet)

    def test_arp_encapsulation(self):
        arp = bytes.fromhex("0001080006040001")
        encoded = encapsulate_arp(arp)
        self.assertEqual(encoded[:8], bytes.fromhex("aaaa030000000806"))
        self.assertEqual(decapsulate(encoded).payload, arp)

    def test_invalid_llc_header_oui_and_length_are_rejected(self):
        with self.assertRaises(FrameFormatError):
            decapsulate(b"\xaa\xaa\x03")
        with self.assertRaises(FrameFormatError):
            decapsulate(bytes.fromhex("abab030000000800"))
        with self.assertRaises(FrameFormatError):
            decapsulate(bytes.fromhex("aaaa030050f20800"))


class DataFrameTests(unittest.TestCase):
    def test_station_to_ds_address_mapping_and_ipv4_payload(self):
        ip = bytes.fromhex("45000014000000004011a6d1c0a80402c0a80401")
        frame = build_station_data(
            STATION,
            ACCESS_POINT,
            GATEWAY,
            ip,
            EtherType.IPV4,
            sequence_number=0x345,
        )
        self.assertEqual(frame[:2], bytes.fromhex("0801"))
        parsed = parse_data(frame)
        self.assertTrue(parsed.frame_control.to_ds)
        self.assertFalse(parsed.frame_control.from_ds)
        self.assertEqual(parsed.receiver, ACCESS_POINT)
        self.assertEqual(parsed.transmitter, STATION)
        self.assertEqual(parsed.bssid, ACCESS_POINT)
        self.assertEqual(parsed.source, STATION)
        self.assertEqual(parsed.destination, GATEWAY)
        self.assertEqual(parsed.sequence_number, 0x345)
        self.assertEqual(parsed.llc.ethertype, EtherType.IPV4)
        self.assertEqual(parsed.llc.payload, ip)

    def test_ap_to_station_mapping_and_arp_payload(self):
        arp = bytes.fromhex("000108000604000202deadbeef01c0a80401")
        frame = build_ap_data(
            ACCESS_POINT,
            STATION,
            GATEWAY,
            arp,
            EtherType.ARP,
            sequence_number=18,
        )
        self.assertEqual(frame[:2], bytes.fromhex("0802"))
        parsed = parse_data(frame)
        self.assertEqual(parsed.bssid, ACCESS_POINT)
        self.assertEqual(parsed.source, GATEWAY)
        self.assertEqual(parsed.destination, STATION)
        self.assertEqual(parsed.llc.ethertype, EtherType.ARP)
        self.assertEqual(parsed.llc.payload, arp)

    def test_qos_tid_is_encoded_after_three_address_header(self):
        frame = build_station_data(
            STATION,
            ACCESS_POINT,
            BROADCAST,
            b"arp",
            EtherType.ARP,
            sequence_number=3,
            qos_tid=5,
        )
        self.assertEqual(frame[:2], bytes.fromhex("8801"))
        self.assertEqual(frame[24:26], bytes.fromhex("0500"))
        parsed = parse_data(frame)
        self.assertEqual(parsed.qos_tid, 5)
        self.assertEqual(parsed.llc.payload, b"arp")

    def test_four_address_qos_ht_header_offsets(self):
        control = FrameControl.build(
            2,
            8,
            to_ds=True,
            from_ds=True,
            order=True,
        )
        source = bytes.fromhex("020102030405")
        body = bytes.fromhex("aaaa030000000806") + b"payload"
        frame = build_raw_data(
            frame_control=control,
            duration=4,
            address1=ACCESS_POINT,
            address2=STATION,
            address3=BROADCAST,
            address4=source,
            sequence_number=1,
            qos_control=3,
            ht_control=0x12345678,
            body=body,
        )
        parsed = parse_data(frame)
        self.assertEqual(parsed.address4, source)
        self.assertEqual(parsed.source, source)
        self.assertIsNone(parsed.bssid)
        self.assertEqual(parsed.qos_tid, 3)
        self.assertEqual(parsed.ht_control, 0x12345678)
        self.assertEqual(parsed.llc.payload, b"payload")

    def test_protected_body_is_not_misparsed_as_llc(self):
        control = FrameControl.build(2, 0, from_ds=True, protected=True)
        ciphertext = bytes.fromhex("010203040506070809")
        frame = build_raw_data(
            frame_control=control,
            duration=0,
            address1=STATION,
            address2=ACCESS_POINT,
            address3=GATEWAY,
            sequence_number=1,
            body=ciphertext,
        )
        parsed = parse_data(frame)
        self.assertEqual(parsed.body, ciphertext)
        self.assertIsNone(parsed.llc)

    def test_malformed_qos_and_four_address_headers_are_rejected(self):
        basic = build_station_data(
            STATION,
            ACCESS_POINT,
            GATEWAY,
            b"x",
            EtherType.IPV4,
            sequence_number=0,
        )
        qos_without_control = bytes((0x88, basic[1])) + basic[2:24]
        with self.assertRaises(FrameFormatError):
            parse_data(qos_without_control)

        four_address_control = FrameControl.build(
            2, 0, to_ds=True, from_ds=True
        ).encode()
        with self.assertRaises(FrameFormatError):
            parse_data(four_address_control + basic[2:24])


if __name__ == "__main__":
    unittest.main()
