# SPDX-License-Identifier: GPL-2.0-only

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import io
import struct
from types import SimpleNamespace
import unittest
from typing import Any

from mindrove_station.data import build_ap_data, parse_data
from mindrove_station.ccmp import CCMPHeader
from mindrove_station.ie import InformationElement
from mindrove_station.llc import EtherType
from mindrove_station.management import (
    Capability,
    build_association_response,
    build_authentication,
    parse_association_request,
)
from mindrove_station.security import build_rsn_element

from tools.mindrove_bridge.cli import (
    _load_cli_passphrase,
    _read_stdin_passphrase,
    build_parser,
)
from tools.mindrove_bridge.config import BridgeConfig, SecretValue, load_passphrase
from tools.mindrove_bridge.radio import (
    RF18_BAND_5GHZ,
    TargetFrameQueue,
    Wifit3StationRadio,
    guard_no_bt_coexist_set_channel,
)
from tools.mindrove_bridge.session import StationOrchestrator, parse_target_beacon
from tools.mindrove_bridge.wpa2_provider import (
    EXG_START_COMMAND,
    DefaultWPA2Handshake,
    SecureMindRoveDataPlane,
)


BSSID = bytes.fromhex("102030405060")
STATION = bytes.fromhex("021122334455")
SSID = "MindRove_Test_000001"


@dataclass
class Packet:
    raw: bytes


def management_frame(
    *, subtype: int, receiver: bytes, transmitter: bytes, bssid: bytes, body: bytes = b""
) -> bytes:
    return (
        struct.pack("<H", subtype << 4)
        + b"\x00\x00"
        + receiver
        + transmitter
        + bssid
        + b"\x00\x00"
        + body
    )


def target_beacon() -> bytes:
    rsn = build_rsn_element().encode()
    elements = (
        InformationElement(0, SSID.encode()).encode()
        + InformationElement(1, bytes((0x82, 0x84, 0x8B, 0x96))).encode()
        + rsn
    )
    fixed = b"\x00" * 8 + struct.pack("<HH", 100, int(Capability.ESS | Capability.PRIVACY))
    return management_frame(
        subtype=8,
        receiver=b"\xff" * 6,
        transmitter=BSSID,
        bssid=BSSID,
        body=fixed + elements,
    )


class FakeDriver:
    def __init__(self) -> None:
        self.info = type("Info", (), {"bt_coexist": False})()
        self.rx_callback = None
        self.disconnect_callback = None
        self.calls: list[Any] = []
        self.transport = type("Transport", (), {"current_band": 0})()

    def register_rx_callback(self, callback):
        self.rx_callback = callback

    def register_disconnect_callback(self, callback):
        self.disconnect_callback = callback

    async def connect(self):
        self.calls.append("connect")
        return True

    async def set_channel(self, channel, scan=False):
        self.calls.append(("channel", channel, scan))
        return True

    async def enter_active_monitor(self, mac, bssid=None):
        self.calls.append(("active", mac, bssid))
        return mac

    async def exit_active_monitor(self):
        self.calls.append("inactive")

    async def inject_frame(self, frame):
        self.calls.append(("tx", frame))
        return True

    async def close(self):
        self.calls.append("close")


class ConfigTests(unittest.TestCase):
    def test_secret_is_not_printable_and_cli_has_no_password_argument(self):
        secret = SecretValue("test-only-secret")
        self.assertNotIn("test-only", repr(secret))
        self.assertEqual(str(secret), "<redacted>")
        option_strings = {
            option
            for action in build_parser()._actions
            for option in action.option_strings
        }
        self.assertNotIn("--password", option_strings)
        self.assertNotIn("--passphrase", option_strings)

    def test_passphrase_prefers_named_environment(self):
        secret = load_passphrase(
            environment={"SAFE_NAME": "correct horse"},
            env_name="SAFE_NAME",
            prompt=lambda _prompt: self.fail("prompt should not be called"),
        )
        self.assertEqual(secret.reveal(), b"correct horse")
        secret.clear()
        self.assertEqual(secret.reveal(), b"\x00" * len(b"correct horse"))

    def test_psk_stdin_takes_precedence_without_trimming(self):
        args = build_parser().parse_args(
            [
                "--ssid",
                SSID,
                "--bssid",
                "10:20:30:40:50:60",
                "--channel",
                "6",
                "--psk-env",
                "SAFE_NAME",
                "--psk-stdin",
            ]
        )
        secret = _load_cli_passphrase(
            args,
            stdin=io.BytesIO(b"pipe secret\n"),
            environment={"SAFE_NAME": "environment secret"},
            prompt=lambda _prompt: self.fail("prompt should not be called"),
        )
        self.assertEqual(secret.reveal(), b"pipe secret\n")
        secret.clear()

    def test_psk_stdin_rejects_overlong_input_and_wipes_buffer(self):
        class TrackingReader:
            def __init__(self, value: bytes) -> None:
                self.value = value
                self.offset = 0
                self.raw_buffer: bytearray | None = None

            def readinto(self, destination: memoryview) -> int:
                buffer = destination.obj
                if not isinstance(buffer, bytearray):
                    raise TypeError("expected the bridge's mutable credential buffer")
                self.raw_buffer = buffer
                count = min(len(destination), len(self.value) - self.offset)
                destination[:count] = self.value[self.offset : self.offset + count]
                self.offset += count
                return count

        stream = TrackingReader(b"s" * 64)
        with self.assertRaisesRegex(ValueError, "exceeds 63"):
            _read_stdin_passphrase(stream)
        self.assertIsNotNone(stream.raw_buffer)
        self.assertEqual(stream.raw_buffer, bytearray(64))

    def test_psk_stdin_rejects_invalid_utf8_without_echoing_input(self):
        raw_secret = b"validpart\xff"
        with self.assertRaises(ValueError) as raised:
            _read_stdin_passphrase(io.BytesIO(raw_secret))
        self.assertNotIn(repr(raw_secret), str(raised.exception))
        self.assertIn("not valid UTF-8", str(raised.exception))

    def test_config_requires_loopback(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            BridgeConfig(SSID, BSSID, 6, loopback_host="192.168.4.2")

    def test_active_bridge_is_target_and_us_channel_scoped(self):
        with self.assertRaisesRegex(ValueError, "MindRove SSID"):
            BridgeConfig("Unrelated_AP", BSSID, 6)
        with self.assertRaisesRegex(ValueError, "channels 1 through 11"):
            BridgeConfig(SSID, BSSID, 12)


class CompatibilityTests(unittest.TestCase):
    def test_bt_notifications_are_skipped_only_for_no_bt_board(self):
        calls: list[str] = []

        class Btc:
            @staticmethod
            def switchband_notify_2g(_transport):
                calls.append("2g")

            @staticmethod
            def switchband_notify_5g(_transport):
                calls.append("5g")

        def original(transport, _info, _channel):
            Btc.switchband_notify_2g(transport)
            return "ok"

        guarded = guard_no_bt_coexist_set_channel(original, Btc)
        no_bt = type("Info", (), {"bt_coexist": False})()
        with_bt = type("Info", (), {"bt_coexist": True})()
        self.assertEqual(guarded(object(), no_bt, 6), "ok")
        self.assertEqual(calls, [])
        self.assertEqual(guarded(object(), with_bt, 6), "ok")
        self.assertEqual(calls, ["2g"])


class AsyncBridgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_target_queue_filters_and_bounds(self):
        queue = TargetFrameQueue(BSSID, STATION, maxsize=1)
        unrelated = management_frame(
            subtype=8,
            receiver=b"\xff" * 6,
            transmitter=bytes.fromhex("aabbccddeeff"),
            bssid=bytes.fromhex("aabbccddeeff"),
        )
        queue.packet_callback(Packet(unrelated))
        queue.packet_callback(Packet(target_beacon()))
        direct = management_frame(
            subtype=11, receiver=STATION, transmitter=BSSID, bssid=BSSID
        )
        queue.packet_callback(Packet(direct))
        await asyncio.sleep(0)
        received = await queue.receive(0.1)
        self.assertEqual(received.raw, direct)
        self.assertEqual(queue.dropped, 1)

    async def test_radio_retries_stuck_rf18_and_activates_mac(self):
        driver = FakeDriver()
        reads = iter((RF18_BAND_5GHZ | 6, 6))
        retries = []
        compatibility = []

        async def retry_hook(_driver, event):
            retries.append(event)

        radio = Wifit3StationRadio(
            driver,
            bssid=BSSID,
            station_mac=STATION,
            compatibility_hook=lambda: compatibility.append(True),
            rf18_reader=lambda _driver: next(reads),
            retry_hook=retry_hook,
        )
        await radio.connect()
        rf18 = await radio.tune_fixed(6)
        await radio.activate_station()
        self.assertEqual(rf18, 6)
        self.assertEqual(len(retries), 1)
        self.assertEqual(compatibility, [True])
        self.assertEqual(driver.calls.count(("channel", 6, False)), 2)
        self.assertIn(("active", STATION, BSSID), driver.calls)
        await radio.close()

    async def test_default_retry_marks_next_tune_for_band_bounce(self):
        driver = FakeDriver()
        bounce_flags = []

        async def fixed_tuner(fake_driver, channel):
            bounce_flags.append(
                bool(
                    getattr(
                        fake_driver.transport,
                        "_mindrove_force_band_bounce",
                        False,
                    )
                )
            )
            return channel if len(bounce_flags) > 1 else RF18_BAND_5GHZ | channel

        radio = Wifit3StationRadio(
            driver,
            bssid=BSSID,
            station_mac=STATION,
            fixed_tuner=fixed_tuner,
        )
        await radio.connect()
        await radio.tune_fixed(6)
        self.assertEqual(bounce_flags, [False, True])
        await radio.close()

    async def test_auth_and_wpa2_assoc_exchange_is_targeted(self):
        driver = FakeDriver()
        radio = Wifit3StationRadio(
            driver,
            bssid=BSSID,
            station_mac=STATION,
            rf18_reader=lambda _driver: 6,
        )
        config = BridgeConfig(SSID, BSSID, 6, attempts=1)
        orchestrator = StationOrchestrator(radio, config)

        async def responses():
            while (
                driver.rx_callback is None
                or ("channel", 6, False) not in driver.calls
            ):
                await asyncio.sleep(0)
            driver.calls.append("target-beacon")
            driver.rx_callback(Packet(target_beacon()))
            while len([c for c in driver.calls if isinstance(c, tuple) and c[0] == "tx"]) < 1:
                await asyncio.sleep(0)
            auth_response = build_authentication(
                STATION,
                BSSID,
                transaction=2,
                status_code=0,
            )
            # Fixture builder is station->AP; swap the three address fields to AP->station.
            auth_response = (
                auth_response[:4] + STATION + BSSID + BSSID + auth_response[22:]
            )
            driver.rx_callback(Packet(auth_response))
            while len([c for c in driver.calls if isinstance(c, tuple) and c[0] == "tx"]) < 2:
                await asyncio.sleep(0)
            assoc_response = build_association_response(
                BSSID, STATION, (0x82, 0x84), status_code=0
            )
            driver.rx_callback(Packet(assoc_response))

        feeder = asyncio.create_task(responses())
        exchange = await orchestrator.prepare(beacon_timeout=0.5)
        await feeder
        self.assertEqual(exchange.station_mac, STATION)
        self.assertLess(
            driver.calls.index("target-beacon"),
            next(
                index
                for index, call in enumerate(driver.calls)
                if isinstance(call, tuple) and call[0] == "active"
            ),
            "the target beacon must be validated before active-monitor mode",
        )
        transmitted = [call[1] for call in driver.calls if isinstance(call, tuple) and call[0] == "tx"]
        association = parse_association_request(transmitted[1])
        self.assertEqual(association.header.receiver, BSSID)
        self.assertEqual(association.header.transmitter, STATION)
        self.assertTrue(
            any(element.element_id == 48 for element in association.elements),
            "association must select an RSN suite",
        )
        await orchestrator.close()

    async def test_beacon_profile_selects_psk_ccmp(self):
        profile = parse_target_beacon(
            target_beacon(), expected_ssid=SSID, expected_bssid=BSSID
        )
        self.assertEqual(profile.ssid, SSID)
        self.assertEqual(profile.rsn_element.element_id, 48)

    async def test_default_handshake_wraps_m2_m4_and_starts_arp(self):
        profile = parse_target_beacon(
            target_beacon(), expected_ssid=SSID, expected_bssid=BSSID
        )
        config = BridgeConfig(SSID, BSSID, 6)

        class Exchange:
            def __init__(self):
                self.config = config
                self.profile = profile
                self.station_mac = STATION
                self.frames = [
                    build_ap_data(
                        BSSID,
                        STATION,
                        BSSID,
                        b"\x02\x03\x00\x02m1",
                        EtherType.EAPOL,
                        sequence_number=1,
                    ),
                    build_ap_data(
                        BSSID,
                        STATION,
                        BSSID,
                        b"\x02\x03\x00\x02m3",
                        EtherType.EAPOL,
                        sequence_number=2,
                    ),
                ]
                self.sent = []

            async def receive_frame(self, _timeout=None):
                return self.frames.pop(0)

            async def send_frame(self, frame):
                self.sent.append(frame)

        class FakeHandshake:
            def __init__(self, _pmk, _bssid, _station, rsn):
                self.complete = False
                self.pairwise_keys = None
                self.group_key = None
                self.rsn = rsn
                self.count = 0

            def process(self, payload):
                self.count += 1
                if self.count == 1:
                    self.assert_payload = payload
                    return b"m2"
                self.complete = True
                self.pairwise_keys = SimpleNamespace(temporal_key=b"K" * 16)
                self.group_key = SimpleNamespace(
                    key_id=1,
                    temporal_key=b"G" * 16,
                    receive_packet_number=0,
                )
                return b"m4"

        class FakePlane:
            def __init__(self, exchange, handshake):
                self.exchange = exchange
                self.handshake = handshake
                self.lease_acquired = False
                self.arp_started = False

            async def acquire_lease(self):
                self.lease_acquired = True

            async def request_peer_mac(self):
                if not self.lease_acquired:
                    raise AssertionError("DHCP must complete before ARP")
                self.arp_started = True

            async def __call__(self, _frame):
                return None

        exchange = Exchange()
        provider = DefaultWPA2Handshake(
            handshake_factory=FakeHandshake,
            plane_factory=FakePlane,
        )
        secret = SecretValue("test-only-secret")
        plane = await provider(exchange, secret)  # type: ignore[arg-type]
        self.assertTrue(plane.lease_acquired)
        self.assertTrue(plane.arp_started)
        self.assertEqual(len(exchange.sent), 2)
        self.assertEqual(parse_data(exchange.sent[0]).llc.payload, b"m2")
        self.assertEqual(parse_data(exchange.sent[1]).llc.payload, b"m4")
        self.assertEqual(exchange.sent[0][4:10], BSSID)
        self.assertEqual(exchange.sent[0][10:16], STATION)
        secret.clear()

    async def test_exg_start_command_is_sent_once_after_arp_learning(self):
        config = BridgeConfig(SSID, BSSID, 6)
        profile = parse_target_beacon(
            target_beacon(), expected_ssid=SSID, expected_bssid=BSSID
        )

        class Exchange:
            def __init__(self):
                self.config = config
                self.profile = profile
                self.station_mac = STATION
                self.sent = []

            async def send_frame(self, frame):
                self.sent.append(frame)

        class Receiver:
            def __init__(self, _key):
                pass

            def decrypt(self, _raw):
                plaintext = build_ap_data(
                    BSSID,
                    STATION,
                    BSSID,
                    b"\x00" * 28,
                    EtherType.ARP,
                    sequence_number=3,
                )
                return SimpleNamespace(frame=plaintext)

        class Transmitter:
            def __init__(self, _key):
                self.plaintexts = []

            def encrypt(self, plaintext):
                self.plaintexts.append(plaintext)
                return plaintext

        class Network:
            def __init__(self, _local_mac):
                self.peer_mac = None

            def handle_arp(self, _payload):
                self.peer_mac = BSSID
                return None

            def build_udp(self, payload, **_kwargs):
                self.last_udp = payload
                self.last_udp_options = _kwargs
                return b"ipv4-packet"

            def build_arp_request(self):
                return b"arp-request"

        handshake = SimpleNamespace(
            complete=True,
            pairwise_keys=SimpleNamespace(temporal_key=b"K" * 16),
        )
        exchange = Exchange()
        plane = SecureMindRoveDataPlane(
            exchange,  # type: ignore[arg-type]
            handshake,  # type: ignore[arg-type]
            receiver_factory=Receiver,
            transmitter_factory=Transmitter,
            network_factory=Network,
            ephemeral_port_factory=lambda: 60000,
        )
        protected_outer = bytearray(
            build_ap_data(
                BSSID,
                STATION,
                BSSID,
                b"",
                EtherType.ARP,
                sequence_number=4,
            )[:24]
            + CCMPHeader(packet_number=1, key_id=0).encode()
            + b"ciphertext-and-mic"
        )
        protected_outer[1] |= 0x40
        await plane(bytes(protected_outer))
        await plane(bytes(protected_outer))
        self.assertEqual(len(exchange.sent), 1)
        self.assertEqual(plane.network.last_udp, EXG_START_COMMAND)
        self.assertEqual(plane.network.last_udp_options["source_port"], 60000)
        self.assertEqual(plane.network.last_udp_options["destination_port"], 4210)
        sent = parse_data(exchange.sent[0])
        self.assertEqual(sent.llc.ethertype, int(EtherType.IPV4))
        self.assertEqual(sent.llc.payload, b"ipv4-packet")

    async def test_group_ccmp_uses_authenticated_m3_gtk(self):
        config = BridgeConfig(SSID, BSSID, 6)
        profile = parse_target_beacon(
            target_beacon(), expected_ssid=SSID, expected_bssid=BSSID
        )

        class Exchange:
            def __init__(self):
                self.config = config
                self.profile = profile
                self.station_mac = STATION

            async def send_frame(self, _frame):
                self.fail = "unexpected transmit"

        class Receiver:
            instances = {}

            def __init__(
                self, key, *, expected_key_id=0, initial_packet_number=0
            ):
                self.calls = 0
                self.expected_key_id = expected_key_id
                self.initial_packet_number = initial_packet_number
                self.instances[key] = self

            def decrypt(self, _raw):
                self.calls += 1
                ipv4 = b"\x45\x00\x00\x14" + b"\x00" * 16
                plaintext = build_ap_data(
                    BSSID,
                    b"\xff" * 6,
                    BSSID,
                    ipv4,
                    EtherType.IPV4,
                    sequence_number=5,
                )
                return SimpleNamespace(frame=plaintext)

        class Transmitter:
            def __init__(self, _key):
                pass

        class Network:
            def __init__(self, _local_mac):
                self.peer_mac = BSSID

            def receive_ipv4(self, _packet):
                return SimpleNamespace(payload=b"group-stream")

        handshake = SimpleNamespace(
            complete=True,
            pairwise_keys=SimpleNamespace(temporal_key=b"P" * 16),
            group_key=SimpleNamespace(
                key_id=1,
                temporal_key=b"G" * 16,
                receive_packet_number=7,
            ),
        )
        plane = SecureMindRoveDataPlane(
            Exchange(),  # type: ignore[arg-type]
            handshake,  # type: ignore[arg-type]
            receiver_factory=Receiver,
            transmitter_factory=Transmitter,
            network_factory=Network,
        )
        frame = bytearray(
            build_ap_data(
                BSSID,
                b"\xff" * 6,
                BSSID,
                b"",
                EtherType.IPV4,
                sequence_number=5,
            )[:24]
            + CCMPHeader(packet_number=1, key_id=1).encode()
            + b"ciphertext-and-mic"
        )
        frame[1] |= 0x40

        payload = await plane(bytes(frame))

        self.assertEqual(payload, b"group-stream")
        self.assertEqual(Receiver.instances[b"P" * 16].calls, 0)
        self.assertEqual(Receiver.instances[b"G" * 16].calls, 1)
        self.assertEqual(Receiver.instances[b"G" * 16].expected_key_id, 1)
        self.assertEqual(Receiver.instances[b"G" * 16].initial_packet_number, 7)


if __name__ == "__main__":
    unittest.main()
