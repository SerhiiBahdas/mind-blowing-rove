# SPDX-License-Identifier: GPL-2.0-only

from __future__ import annotations

from dataclasses import dataclass, field
import unittest

from tools.mindrove_passive_scan.report import (
    InputError,
    Target,
    beacon_report,
    normalize_bssid,
    parse_channels,
)
from tools.mindrove_passive_scan.scanner import (
    PassiveOnlyViolation,
    ReceiveOnlyDriver,
)
from tools.mindrove_passive_scan.wifit3_compat import guard_btc_band_notifications


def _ie(element_id: int, body: bytes) -> bytes:
    return bytes((element_id, len(body))) + body


def _beacon_frame(*elements: bytes, privacy: bool = True) -> bytes:
    header = bytearray(36)
    header[0] = 0x80
    header[34:36] = (0x0010 if privacy else 0).to_bytes(2, "little")
    return bytes(header) + b"".join(elements)


@dataclass
class FakePacket:
    type: str = "beacon"
    ssid: str = "MindRove_Test_000001"
    bssid: str = "02:11:22:33:44:55"
    channel: int | None = 6
    encryption: str = "WPA2 PSK CCMP"
    pairwise_cipher: str | None = "CCMP"
    akms: list[str] = field(default_factory=lambda: ["PSK"])
    akm_suites: list[int] = field(default_factory=lambda: [2])
    wpa3: bool = False
    transition_mode: bool = False
    pmf_capable: bool = True
    pmf_required: bool = False
    beacon_protection: bool = False
    raw: bytes = b""


class ReportTests(unittest.TestCase):
    def test_target_is_exact_and_beacon_only(self) -> None:
        target = Target("MindRove_Test_000001", "02:11:22:33:44:55")
        self.assertTrue(target.matches(FakePacket()))
        self.assertFalse(target.matches(FakePacket(ssid="MindRove-OTHER")))
        self.assertFalse(target.matches(FakePacket(bssid="02:11:22:33:44:56")))
        self.assertFalse(target.matches(FakePacket(type="probe_resp")))

    def test_report_keeps_only_security_ies(self) -> None:
        ssid = _ie(0, b"MindRove_Test_000001")
        rates = _ie(1, b"\x82\x84")
        rsn = _ie(48, b"\x01\x00\x00\x0f\xac\x04")
        wpa = _ie(221, b"\x00\x50\xf2\x01\x01\x00")
        wps = _ie(221, b"\x00\x50\xf2\x04\x10\x4a\x00\x01\x20")
        rsnxe = _ie(244, b"\x20")
        ordinary_vendor = _ie(221, b"\x12\x34\x56\x78")
        packet = FakePacket(
            raw=_beacon_frame(ssid, rates, rsn, wpa, wps, rsnxe, ordinary_vendor)
        )

        report = beacon_report(packet, observed_channel=1)

        self.assertEqual(report["ssid"], "MindRove_Test_000001")
        self.assertEqual(report["bssid"], "02:11:22:33:44:55")
        self.assertEqual(report["channel"], 6)
        self.assertTrue(report["security"]["privacy"])
        self.assertEqual(
            [entry["name"] for entry in report["security_ies"]],
            ["RSN", "WPA", "WPS", "RSNXE"],
        )
        self.assertEqual(report["security_ies"][0]["hex"], rsn.hex())
        self.assertNotIn(ordinary_vendor.hex(), str(report))

    def test_observed_channel_is_fallback(self) -> None:
        packet = FakePacket(channel=None, raw=_beacon_frame(privacy=False))
        report = beacon_report(packet, observed_channel=11)
        self.assertEqual(report["channel"], 11)
        self.assertFalse(report["security"]["privacy"])

    def test_truncated_ie_is_not_reported(self) -> None:
        truncated_rsn = b"\x30\x08\x01\x00"
        packet = FakePacket(raw=_beacon_frame(truncated_rsn))
        self.assertEqual(beacon_report(packet, 1)["security_ies"], [])


class InputTests(unittest.TestCase):
    def test_parse_channels_supports_ranges_and_deduplicates(self) -> None:
        self.assertEqual(parse_channels("1-3,3,6,36"), (1, 2, 3, 6, 36))

    def test_parse_channels_rejects_unsupported_and_bad_ranges(self) -> None:
        for value in ("0", "15", "11-1", "1,,6", "abc"):
            with self.subTest(value=value), self.assertRaises(InputError):
                parse_channels(value)

    def test_bssid_validation(self) -> None:
        self.assertEqual(normalize_bssid("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff")
        with self.assertRaises(InputError):
            normalize_bssid("not-a-bssid")

    def test_ssid_limit_is_utf8_bytes(self) -> None:
        with self.assertRaises(InputError):
            Target("é" * 17)


class FakeDriver:
    def __init__(self) -> None:
        self.calls: list[object] = []

    def register_rx_callback(self, callback) -> None:
        self.calls.append("register_rx")

    def register_disconnect_callback(self, callback) -> None:
        self.calls.append("register_disconnect")

    async def connect(self) -> bool:
        self.calls.append("connect")
        return True

    async def set_channel(self, channel: int, scan: bool = False) -> bool:
        self.calls.append(("set_channel", channel, scan))
        return True

    async def close(self) -> None:
        self.calls.append("close")

    async def inject_frame(self, frame: bytes) -> bool:
        self.calls.append(("inject", frame))
        return True

    async def inject_frame_slow_retry(self, frame: bytes) -> bool:
        return await self.inject_frame(frame)

    async def _inject_frame(self, frame: bytes) -> bool:
        return await self.inject_frame(frame)

    async def enter_active_monitor(self, mac: bytes) -> bytes:
        self.calls.append(("active_monitor", mac))
        return mac


class PassiveBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_receive_only_surface_marks_tuning_as_scan(self) -> None:
        backend = FakeDriver()
        driver = ReceiveOnlyDriver(backend)
        await driver.connect()
        await driver.set_channel(6)
        await driver.close()
        self.assertEqual(backend.calls, ["connect", ("set_channel", 6, True), "close"])
        self.assertFalse(hasattr(driver, "inject_frame"))

    async def test_every_transmit_entry_point_fails_closed(self) -> None:
        backend = FakeDriver()
        ReceiveOnlyDriver(backend)
        calls = (
            backend.inject_frame(b"frame"),
            backend.inject_frame_slow_retry(b"frame"),
            backend._inject_frame(b"frame"),
            backend.enter_active_monitor(b"\x02" * 6),
        )
        for call in calls:
            with self.assertRaises(PassiveOnlyViolation):
                await call
        self.assertEqual(backend.calls, [])


class FakeBtcModule:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def switchband_notify_2g(self, _transport) -> None:
        self.calls.append("2g")

    def switchband_notify_5g(self, _transport) -> None:
        self.calls.append("5g")


@dataclass
class FakeEfuseInfo:
    bt_coexist: bool


class CompatibilityFixTests(unittest.TestCase):
    def test_wifi_only_board_skips_btc_notification(self) -> None:
        btc = FakeBtcModule()

        def upstream_set_channel(transport, _info, _channel):
            btc.switchband_notify_2g(transport)
            return "tuned"

        fixed = guard_btc_band_notifications(upstream_set_channel, btc)
        result = fixed(object(), FakeEfuseInfo(bt_coexist=False), 1)

        self.assertEqual(result, "tuned")
        self.assertEqual(btc.calls, [])

    def test_combo_board_retains_btc_notification(self) -> None:
        btc = FakeBtcModule()

        def upstream_set_channel(transport, _info, _channel):
            btc.switchband_notify_5g(transport)

        fixed = guard_btc_band_notifications(upstream_set_channel, btc)
        fixed(object(), FakeEfuseInfo(bt_coexist=True), 36)

        self.assertEqual(btc.calls, ["5g"])

    def test_btc_functions_are_restored_after_channel_failure(self) -> None:
        btc = FakeBtcModule()
        notify_2g = btc.switchband_notify_2g
        notify_5g = btc.switchband_notify_5g

        def upstream_set_channel(transport, _info, _channel):
            btc.switchband_notify_2g(transport)
            raise RuntimeError("synthetic tune failure")

        fixed = guard_btc_band_notifications(upstream_set_channel, btc)
        with self.assertRaisesRegex(RuntimeError, "synthetic tune failure"):
            fixed(object(), FakeEfuseInfo(bt_coexist=False), 1)

        self.assertEqual(btc.switchband_notify_2g, notify_2g)
        self.assertEqual(btc.switchband_notify_5g, notify_5g)


if __name__ == "__main__":
    unittest.main()
