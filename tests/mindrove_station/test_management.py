# SPDX-License-Identifier: GPL-2.0-only

import unittest

from mindrove_station import (
    AuthenticationAlgorithm,
    Capability,
    ElementID,
    FrameFormatError,
    build_association_request,
    build_association_response,
    build_authentication,
    build_rsn_element,
    parse_association_request,
    parse_association_response,
    parse_authentication,
    parse_information_elements,
)


STATION = bytes.fromhex("021122334455")
ACCESS_POINT = bytes.fromhex("02aabbccddee")
RATES = (0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24, 0x30)


class AuthenticationTests(unittest.TestCase):
    def test_open_authentication_request_has_standard_wire_layout(self):
        frame = build_authentication(
            STATION,
            ACCESS_POINT,
            algorithm=AuthenticationAlgorithm.OPEN_SYSTEM,
            transaction=1,
            sequence_number=0x123,
        )
        expected = bytes.fromhex(
            "b0000000"
            "02aabbccddee"
            "021122334455"
            "02aabbccddee"
            "3012"
            "000001000000"
        )
        self.assertEqual(frame, expected)

        parsed = parse_authentication(frame)
        self.assertEqual(parsed.header.receiver, ACCESS_POINT)
        self.assertEqual(parsed.header.transmitter, STATION)
        self.assertEqual(parsed.header.sequence_number, 0x123)
        self.assertEqual(parsed.algorithm, AuthenticationAlgorithm.OPEN_SYSTEM)
        self.assertEqual(parsed.transaction, 1)
        self.assertTrue(parsed.successful)

    def test_authentication_response_payload_is_preserved(self):
        challenge = bytes.fromhex("1003010203")
        # Independent AP-to-station fixture: receiver, transmitter, and BSSID
        # ordering does not rely on the station-request builder.
        frame = (
            bytes.fromhex("b0000000")
            + STATION
            + ACCESS_POINT
            + ACCESS_POINT
            + bytes.fromhex("0000010002000d00")
            + challenge
        )
        parsed = parse_authentication(frame)
        self.assertEqual(parsed.header.receiver, STATION)
        self.assertEqual(parsed.header.transmitter, ACCESS_POINT)
        self.assertEqual(parsed.header.bssid, ACCESS_POINT)
        self.assertEqual(parsed.payload, challenge)
        self.assertEqual(parsed.status_code, 13)
        self.assertFalse(parsed.successful)

    def test_authentication_rejects_truncation_and_wrong_subtype(self):
        frame = build_authentication(STATION, ACCESS_POINT)
        with self.assertRaises(FrameFormatError):
            parse_authentication(frame[:29])
        wrong_subtype = bytes((0x00,)) + frame[1:]
        with self.assertRaises(FrameFormatError):
            parse_authentication(wrong_subtype)

        encrypted = bytes((frame[0], frame[1] | 0x40)) + frame[2:]
        with self.assertRaisesRegex(FrameFormatError, "encrypted"):
            parse_authentication(encrypted)


class AssociationTests(unittest.TestCase):
    def test_association_request_round_trip_splits_rates_and_sets_privacy(self):
        rsn = build_rsn_element()
        frame = build_association_request(
            STATION,
            ACCESS_POINT,
            "MindRove",
            RATES,
            capability_info=Capability.ESS | Capability.SHORT_SLOT_TIME,
            listen_interval=7,
            sequence_number=9,
            extra_elements=(rsn,),
        )
        parsed = parse_association_request(frame)

        self.assertEqual(parsed.ssid, b"MindRove")
        self.assertEqual(parsed.supported_rates, bytes(RATES))
        self.assertEqual(parsed.listen_interval, 7)
        self.assertEqual(parsed.header.sequence_number, 9)
        self.assertTrue(parsed.capability_info & Capability.ESS)
        self.assertTrue(parsed.capability_info & Capability.PRIVACY)
        self.assertTrue(parsed.capability_info & Capability.SHORT_SLOT_TIME)
        self.assertEqual(
            [element.element_id for element in parsed.elements],
            [
                ElementID.SSID,
                ElementID.SUPPORTED_RATES,
                ElementID.EXTENDED_SUPPORTED_RATES,
                ElementID.RSN,
            ],
        )

    def test_association_request_fixed_fields_are_little_endian(self):
        frame = build_association_request(
            STATION,
            ACCESS_POINT,
            b"MR",
            (0x82,),
            capability_info=0x0401,
            listen_interval=0x1234,
        )
        self.assertEqual(frame[:2], b"\x00\x00")
        self.assertEqual(frame[24:28], bytes.fromhex("01043412"))
        self.assertEqual(frame[28:], bytes.fromhex("00024d52010182"))

    def test_association_response_masks_two_aid_marker_bits(self):
        frame = build_association_response(
            ACCESS_POINT,
            STATION,
            RATES,
            capability_info=Capability.ESS | Capability.PRIVACY,
            association_id=0x234,
            sequence_number=12,
        )
        parsed = parse_association_response(frame)
        self.assertTrue(parsed.successful)
        self.assertEqual(parsed.association_id_raw, 0xC234)
        self.assertEqual(parsed.association_id, 0x234)
        self.assertEqual(parsed.supported_rates, bytes(RATES))
        self.assertEqual(parsed.header.receiver, STATION)
        self.assertEqual(parsed.header.transmitter, ACCESS_POINT)

    def test_association_parser_requires_ssid_and_supported_rates(self):
        frame = build_association_request(STATION, ACCESS_POINT, b"MR", (0x82,))
        # Keep only the fixed association fields.
        with self.assertRaisesRegex(FrameFormatError, "SSID"):
            parse_association_request(frame[:28])

        # Keep SSID but remove Supported Rates.
        with self.assertRaisesRegex(FrameFormatError, "Supported Rates"):
            parse_association_request(frame[:32])

    def test_duplicate_dedicated_elements_are_rejected_by_builder(self):
        from mindrove_station import InformationElement

        with self.assertRaises(ValueError):
            build_association_request(
                STATION,
                ACCESS_POINT,
                b"MR",
                (0x82,),
                extra_elements=(InformationElement(ElementID.SSID, b"other"),),
            )

    def test_information_element_parser_rejects_truncated_body(self):
        with self.assertRaises(FrameFormatError):
            parse_information_elements(bytes.fromhex("3005010203"))


if __name__ == "__main__":
    unittest.main()
