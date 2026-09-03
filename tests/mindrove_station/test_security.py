# SPDX-License-Identifier: GPL-2.0-only

import unittest

from mindrove_station import (
    ElementID,
    FrameFormatError,
    InformationElement,
    RSNCapabilities,
    RSN_CCMP_128,
    RSN_OUI,
    RSN_PSK,
    RSN_SAE,
    SecurityMode,
    SuiteSelector,
    build_rsn_element,
    parse_rsn,
    parse_security_information,
    parse_wpa,
)


class RSNTests(unittest.TestCase):
    def test_wpa2_psk_rsn_fixture(self):
        # Version 1, CCMP group/pairwise, PSK AKM, zero capabilities.
        body = bytes.fromhex(
            "0100" "000fac04" "0100" "000fac04" "0100" "000fac02" "0000"
        )
        parsed = parse_rsn(InformationElement(ElementID.RSN, body))
        self.assertEqual(parsed.version, 1)
        self.assertEqual(parsed.group_cipher, RSN_CCMP_128)
        self.assertEqual(parsed.group_cipher.cipher_name, "CCMP-128")
        self.assertEqual(parsed.pairwise_ciphers, (RSN_CCMP_128,))
        self.assertEqual(parsed.akm_suites, (RSN_PSK,))
        self.assertEqual(parsed.akm_suites[0].akm_name, "PSK")
        self.assertEqual(parsed.capabilities, RSNCapabilities(0))

        security = parse_security_information(
            (InformationElement(ElementID.RSN, body),), privacy_capability=True
        )
        self.assertEqual(security.mode, SecurityMode.WPA2_PERSONAL)

    def test_rsn_builder_round_trip_with_pmkid_and_group_management_cipher(self):
        pmkid = bytes(range(16))
        bip_cmac = SuiteSelector(RSN_OUI, 6)
        element = build_rsn_element(
            capabilities=RSNCapabilities((1 << 6) | (1 << 7)),
            pmkids=(pmkid,),
            group_management_cipher=bip_cmac,
        )
        parsed = parse_rsn(element)
        self.assertEqual(parsed.pmkids, (pmkid,))
        self.assertEqual(parsed.group_management_cipher, bip_cmac)
        self.assertTrue(parsed.capabilities.management_frame_protection_required)
        self.assertTrue(parsed.capabilities.management_frame_protection_capable)

    def test_sae_and_transition_modes_are_distinguished(self):
        sae = build_rsn_element(akm_suites=(RSN_SAE,))
        transition = build_rsn_element(akm_suites=(RSN_PSK, RSN_SAE))
        self.assertEqual(
            parse_security_information((sae,), privacy_capability=True).mode,
            SecurityMode.WPA3_PERSONAL,
        )
        self.assertEqual(
            parse_security_information((transition,), privacy_capability=True).mode,
            SecurityMode.WPA2_WPA3_PERSONAL,
        )

    def test_unknown_suite_is_preserved(self):
        private_akm = SuiteSelector(bytes.fromhex("123456"), 99)
        element = build_rsn_element(akm_suites=(private_akm,))
        parsed = parse_rsn(element)
        self.assertEqual(parsed.akm_suites, (private_akm,))
        self.assertEqual(
            parse_security_information((element,), privacy_capability=True).mode,
            SecurityMode.RSN_UNKNOWN,
        )

    def test_rsn_rejects_bad_version_counts_and_trailing_data(self):
        valid = build_rsn_element().data
        with self.assertRaisesRegex(FrameFormatError, "version"):
            parse_rsn(bytes.fromhex("0200") + valid[2:])

        bad_pairwise_count = valid[:6] + bytes.fromhex("0200") + valid[8:]
        with self.assertRaises(FrameFormatError):
            parse_rsn(bad_pairwise_count)

        with self.assertRaisesRegex(FrameFormatError, "truncated|trailing"):
            parse_rsn(valid + b"\x00")


class WPATests(unittest.TestCase):
    def test_legacy_wpa_psk_vendor_fixture(self):
        body = bytes.fromhex(
            "0050f201" "0100" "0050f202" "0100" "0050f204" "0100" "0050f202"
        )
        element = InformationElement(ElementID.VENDOR_SPECIFIC, body)
        parsed = parse_wpa(element)
        self.assertEqual(parsed.group_cipher.cipher_name, "TKIP")
        self.assertEqual(parsed.pairwise_ciphers[0].cipher_name, "CCMP-128")
        self.assertEqual(parsed.akm_suites[0].akm_name, "PSK")
        self.assertEqual(
            parse_security_information((element,), privacy_capability=True).mode,
            SecurityMode.WPA_PERSONAL,
        )

    def test_non_wpa_vendor_ie_is_rejected(self):
        element = InformationElement(
            ElementID.VENDOR_SPECIFIC, bytes.fromhex("0050f2020100")
        )
        with self.assertRaisesRegex(FrameFormatError, "not a WPA"):
            parse_wpa(element)


class SecuritySummaryTests(unittest.TestCase):
    def test_open_and_legacy_privacy_are_conservative(self):
        self.assertEqual(parse_security_information(()).mode, SecurityMode.OPEN)
        self.assertEqual(
            parse_security_information((), privacy_capability=True).mode,
            SecurityMode.WEP_OR_UNKNOWN_PRIVACY,
        )

    def test_duplicate_security_ie_is_rejected(self):
        rsn = build_rsn_element()
        with self.assertRaisesRegex(FrameFormatError, "duplicate"):
            parse_security_information((rsn, rsn), privacy_capability=True)

    def test_rsnx_bytes_are_retained_for_future_policy_logic(self):
        rsnx = InformationElement(ElementID.RSNX, b"\x20")
        info = parse_security_information((rsnx,))
        self.assertEqual(info.rsnx, b"\x20")
        self.assertEqual(info.mode, SecurityMode.RSN_UNKNOWN)


if __name__ == "__main__":
    unittest.main()
