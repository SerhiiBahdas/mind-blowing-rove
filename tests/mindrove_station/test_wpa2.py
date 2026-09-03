# SPDX-License-Identifier: GPL-2.0-only

import unittest

from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from mindrove_station.errors import HandshakeError, IntegrityError, ReplayError
from mindrove_station.wpa2 import (
    FourWayMessage,
    GroupKey,
    HandshakeState,
    KeyDescriptorVersion,
    KeyInformation,
    PairwiseKeys,
    WPA2PSKHandshake,
    build_eapol_key,
    classify_four_way_message,
    compute_eapol_mic,
    derive_pmk,
    derive_ptk,
    extract_group_key,
    extract_group_key_from_plaintext,
    parse_eapol_key,
    require_valid_eapol_mic,
    sign_eapol_key,
    unwrap_eapol_key_data,
    verify_eapol_mic,
)


ACCESS_POINT = bytes.fromhex("112233445566")
STATION = bytes.fromhex("aabbccddeeff")
ANONCE = bytes(range(32))
SNONCE = bytes(range(64, 96))
# Synthetic network parameters from the published IEEE 802.11i Annex J vector.
TEST_PASSPHRASE = "ThisIsAPassword"
TEST_SSID = "ThisIsASSID"
RSN_ELEMENT = bytes.fromhex(
    "30140100000fac040100000fac040100000fac020000"
)
SYNTHETIC_GTK = bytes(range(0xA0, 0xB0))
GTK_KDE = b"\xdd\x16\x00\x0f\xac\x01\x01\x00" + SYNTHETIC_GTK
UNWRAPPED_M3_KEY_DATA = RSN_ELEMENT + GTK_KDE + b"\xdd\x00"


class KeyDerivationTests(unittest.TestCase):
    def test_annex_j_pmk_vector(self):
        self.assertEqual(
            derive_pmk(TEST_PASSPHRASE, TEST_SSID).hex(),
            "0dc0d6eb90555ed6419756b9a15ec3e"
            "3209b63df707dd508d14581f8982721af",
        )

    def test_ptk_vector_and_split(self):
        ptk = derive_ptk(
            derive_pmk(TEST_PASSPHRASE, TEST_SSID),
            ACCESS_POINT,
            STATION,
            ANONCE,
            SNONCE,
        )
        self.assertEqual(
            ptk.hex(),
            "86dc42e22cebf3bced47d8e9fcf7de633"
            "63833da23cc98b2e39b4ecd7ae4b3efb"
            "ddf3d08255fe7751d3f653334b36966",
        )
        keys = PairwiseKeys.from_ptk(ptk)
        self.assertEqual(keys.kck, ptk[:16])
        self.assertEqual(keys.kek, ptk[16:32])
        self.assertEqual(keys.temporal_key, ptk[32:48])
        self.assertEqual(keys.encode(), ptk)

    def test_ptk_is_independent_of_pair_argument_order(self):
        pmk = bytes(range(32))
        original = derive_ptk(pmk, ACCESS_POINT, STATION, ANONCE, SNONCE)
        reversed_pairs = derive_ptk(pmk, STATION, ACCESS_POINT, SNONCE, ANONCE)
        self.assertEqual(original, reversed_pairs)

    def test_key_derivation_rejects_invalid_lengths_and_zero_nonce(self):
        with self.assertRaisesRegex(ValueError, "8 through 63"):
            derive_pmk("short", TEST_SSID)
        with self.assertRaisesRegex(ValueError, "SSID"):
            derive_pmk(TEST_PASSPHRASE, b"")
        with self.assertRaisesRegex(ValueError, "PMK"):
            derive_ptk(b"short", ACCESS_POINT, STATION, ANONCE, SNONCE)
        with self.assertRaisesRegex(ValueError, "all zero"):
            derive_ptk(bytes(32), ACCESS_POINT, STATION, bytes(32), SNONCE)


class EAPOLKeyTests(unittest.TestCase):
    def setUp(self):
        self.keys = PairwiseKeys.from_ptk(
            derive_ptk(
                derive_pmk(TEST_PASSPHRASE, TEST_SSID),
                ACCESS_POINT,
                STATION,
                ANONCE,
                SNONCE,
            )
        )

    def test_m2_wire_layout_and_known_mic(self):
        frame = build_eapol_key(
            key_information=0x010A,
            replay_counter=1,
            nonce=SNONCE,
            key_data=RSN_ELEMENT,
        )
        packet = frame.encode()
        self.assertEqual(packet[:9].hex(), "0203007502010a0000")
        self.assertEqual(packet[9:17], (1).to_bytes(8, "big"))
        self.assertEqual(packet[17:49], SNONCE)
        self.assertEqual(packet[81:97], bytes(16))
        self.assertEqual(packet[97:99], len(RSN_ELEMENT).to_bytes(2, "big"))
        self.assertEqual(
            compute_eapol_mic(self.keys.kck, frame).hex(),
            "f1ebd3859d16f9f3de8082f69110ea7f",
        )

        signed = sign_eapol_key(self.keys.kck, frame)
        self.assertTrue(verify_eapol_mic(self.keys.kck, signed))
        self.assertEqual(require_valid_eapol_mic(self.keys.kck, signed), signed)
        self.assertEqual(parse_eapol_key(signed.encode()), signed)
        self.assertEqual(classify_four_way_message(signed), FourWayMessage.M2)

    def test_tampered_eapol_mic_is_rejected(self):
        frame = build_eapol_key(
            key_information=0x010A,
            replay_counter=1,
            nonce=SNONCE,
            key_data=RSN_ELEMENT,
        )
        packet = bytearray(sign_eapol_key(self.keys.kck, frame).encode())
        packet[-1] ^= 1
        self.assertFalse(verify_eapol_mic(self.keys.kck, bytes(packet)))
        with self.assertRaises(IntegrityError):
            require_valid_eapol_mic(self.keys.kck, bytes(packet))

    def test_parser_rejects_inconsistent_lengths_and_non_key_packet(self):
        valid = build_eapol_key(
            key_information=0x008A,
            replay_counter=3,
            nonce=ANONCE,
        ).encode()
        with self.assertRaisesRegex(ValueError, "shorter"):
            parse_eapol_key(valid[:90])
        bad_body_length = valid[:2] + b"\x00\x01" + valid[4:]
        with self.assertRaisesRegex(ValueError, "body|fixed fields"):
            parse_eapol_key(bad_body_length)
        bad_key_data_length = valid[:97] + b"\x00\x01"
        with self.assertRaisesRegex(ValueError, "key-data length"):
            parse_eapol_key(bad_key_data_length)
        non_key = valid[:1] + b"\x00" + valid[2:]
        with self.assertRaisesRegex(ValueError, "not EAPOL-Key"):
            parse_eapol_key(non_key)

    def test_classifier_rejects_group_and_control_packets(self):
        group = build_eapol_key(
            key_information=int(KeyDescriptorVersion.HMAC_SHA1_AES)
            | int(KeyInformation.ACK),
            replay_counter=1,
            nonce=ANONCE,
        )
        with self.assertRaises(HandshakeError):
            classify_four_way_message(group)


class FourWayStateTests(unittest.TestCase):
    def setUp(self):
        self.handshake = WPA2PSKHandshake(
            bytes(range(32)),
            ACCESS_POINT,
            STATION,
            RSN_ELEMENT,
            snonce=SNONCE,
        )
        self.m1 = build_eapol_key(
            key_information=0x008A,
            key_length=16,
            replay_counter=7,
            nonce=ANONCE,
        )

    def _signed_m3(
        self,
        *,
        replay_counter=8,
        nonce=ANONCE,
        plaintext_key_data=UNWRAPPED_M3_KEY_DATA,
        key_rsc=bytes.fromhex("0900000000000000"),
    ):
        if self.handshake._candidate_keys is None:
            self.handshake.process_m1(self.m1)
        wrapped = aes_key_wrap(
            self.handshake._candidate_keys.kek, plaintext_key_data
        )
        m3 = build_eapol_key(
            key_information=0x13CA,
            key_length=16,
            replay_counter=replay_counter,
            nonce=nonce,
            key_rsc=key_rsc,
            key_data=wrapped,
        )
        return sign_eapol_key(self.handshake._candidate_keys.kck, m3)

    def test_valid_m1_to_m4_exchange_installs_keys(self):
        m2_packet = self.handshake.process_m1(self.m1)
        m2 = parse_eapol_key(m2_packet)
        self.assertEqual(classify_four_way_message(m2), FourWayMessage.M2)
        # RSN sets Key Length to zero in M2/M4 even though CCMP M1/M3 report
        # the 16-octet temporal-key length. This matches wpa_supplicant and
        # prevents strict authenticators from discarding M2.
        self.assertEqual(self.m1.key_length, 16)
        self.assertEqual(m2.key_length, 0)
        self.assertEqual(m2.replay_counter, self.m1.replay_counter)
        self.assertEqual(m2.nonce, SNONCE)
        self.assertEqual(m2.key_data, RSN_ELEMENT)
        self.assertIsNone(self.handshake.pairwise_keys)
        self.assertTrue(
            verify_eapol_mic(self.handshake._candidate_keys.kck, m2)
        )

        m3 = self._signed_m3()
        m4_packet = self.handshake.process_m3(m3)
        m4 = parse_eapol_key(m4_packet)
        self.assertEqual(classify_four_way_message(m4), FourWayMessage.M4)
        self.assertEqual(m3.key_length, 16)
        self.assertEqual(m4.key_length, 0)
        self.assertEqual(m4.replay_counter, m3.replay_counter)
        self.assertEqual(self.handshake.state, HandshakeState.COMPLETE)
        self.assertIsNotNone(self.handshake.pairwise_keys)
        self.assertEqual(self.handshake.group_key.key_id, 1)
        self.assertEqual(self.handshake.group_key.temporal_key, SYNTHETIC_GTK)
        self.assertEqual(
            self.handshake.group_key.receive_sequence_counter,
            bytes.fromhex("0900000000000000"),
        )
        self.assertTrue(verify_eapol_mic(self.handshake.pairwise_keys.kck, m4))

    def test_identical_m1_and_m3_retransmissions_return_cached_responses(self):
        first_m2 = self.handshake.process_m1(self.m1)
        self.assertEqual(self.handshake.process_m1(self.m1), first_m2)
        m3 = self._signed_m3()
        first_m4 = self.handshake.process_m3(m3)
        self.assertEqual(self.handshake.process_m3(m3), first_m4)

    def test_bad_m3_does_not_advance_or_install_keys(self):
        self.handshake.process_m1(self.m1)
        m3 = bytearray(self._signed_m3().encode())
        m3[81] ^= 1
        with self.assertRaises(IntegrityError):
            self.handshake.process_m3(bytes(m3))
        self.assertEqual(self.handshake.state, HandshakeState.AWAITING_M3)
        self.assertIsNone(self.handshake.pairwise_keys)
        self.assertIsNone(self.handshake.group_key)

    def test_m3_nonce_and_replay_checks(self):
        self.handshake.process_m1(self.m1)
        with self.assertRaisesRegex(HandshakeError, "ANonce"):
            self.handshake.process_m3(self._signed_m3(nonce=bytes(range(1, 33))))
        with self.assertRaises(ReplayError):
            self.handshake.process_m3(self._signed_m3(replay_counter=7))
        self.assertEqual(self.handshake.state, HandshakeState.AWAITING_M3)


class GroupKeyTests(unittest.TestCase):
    def setUp(self):
        self.keys = PairwiseKeys.from_ptk(
            derive_ptk(bytes(range(32)), ACCESS_POINT, STATION, ANONCE, SNONCE)
        )

    def _m3(self, plaintext=UNWRAPPED_M3_KEY_DATA):
        wrapped = aes_key_wrap(self.keys.kek, plaintext)
        unsigned = build_eapol_key(
            key_information=0x13CA,
            key_length=16,
            replay_counter=8,
            nonce=ANONCE,
            key_rsc=bytes.fromhex("0900000000000000"),
            key_data=wrapped,
        )
        return sign_eapol_key(self.keys.kck, unsigned)

    def test_authenticated_unwrap_and_gtk_extraction(self):
        m3 = self._m3()
        self.assertEqual(
            unwrap_eapol_key_data(self.keys.kck, self.keys.kek, m3),
            UNWRAPPED_M3_KEY_DATA,
        )
        group_key = extract_group_key(self.keys.kck, self.keys.kek, m3)
        self.assertEqual(group_key.key_id, 1)
        self.assertFalse(group_key.transmit)
        self.assertEqual(group_key.temporal_key, SYNTHETIC_GTK)
        self.assertEqual(
            group_key.receive_sequence_counter,
            bytes.fromhex("0900000000000000"),
        )
        self.assertEqual(group_key.receive_packet_number, 9)

    def test_key_objects_do_not_reveal_key_bytes_in_repr(self):
        group_key = GroupKey(1, SYNTHETIC_GTK)
        self.assertNotIn(SYNTHETIC_GTK.hex(), repr(group_key))
        self.assertNotIn(self.keys.kck.hex(), repr(self.keys))
        self.assertNotIn(self.keys.temporal_key.hex(), repr(self.keys))

    def test_mic_is_checked_before_unwrap(self):
        tampered = bytearray(self._m3().encode())
        tampered[81] ^= 1
        with self.assertRaises(IntegrityError):
            unwrap_eapol_key_data(self.keys.kck, self.keys.kek, bytes(tampered))

    def test_aes_wrap_integrity_failure_is_rejected(self):
        m3 = self._m3()
        damaged_wrapped = bytearray(m3.key_data)
        damaged_wrapped[-1] ^= 1
        resigned = sign_eapol_key(
            self.keys.kck,
            build_eapol_key(
                key_information=m3.key_information,
                key_length=m3.key_length,
                replay_counter=m3.replay_counter,
                nonce=m3.nonce,
                key_rsc=m3.key_rsc,
                key_data=bytes(damaged_wrapped),
            ),
        )
        with self.assertRaisesRegex(IntegrityError, "key-wrap"):
            extract_group_key(self.keys.kck, self.keys.kek, resigned)

    def test_duplicate_malformed_and_missing_gtk_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            extract_group_key_from_plaintext(GTK_KDE + GTK_KDE)
        bad_reserved = (
            b"\xdd\x16\x00\x0f\xac\x01\x09\x00" + SYNTHETIC_GTK
        )
        with self.assertRaisesRegex(ValueError, "reserved"):
            extract_group_key_from_plaintext(bad_reserved)
        with self.assertRaisesRegex(HandshakeError, "does not contain"):
            extract_group_key_from_plaintext(RSN_ELEMENT + b"\xdd\x00")
        with self.assertRaisesRegex(ValueError, "padding"):
            extract_group_key_from_plaintext(GTK_KDE + b"\xdd\x00\x01")


if __name__ == "__main__":
    unittest.main()
