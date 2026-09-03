# SPDX-License-Identifier: GPL-2.0-only
"""Targeted authentication/association and pluggable WPA2 packet pipeline."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import socket
import struct
import time
from typing import Callable, Optional, Protocol

from mindrove_station.common import FrameControl, mac_bytes
from mindrove_station.ie import ElementID, InformationElement, first_element, parse_information_elements
from mindrove_station.management import (
    AuthenticationAlgorithm,
    Capability,
    build_association_request,
    build_authentication,
    parse_association_response,
    parse_authentication,
)
from mindrove_station.security import (
    RSN_CCMP_128,
    RSN_OUI,
    RSN_PSK,
    SecurityMode,
    build_rsn_element,
    parse_security_information,
)

from .config import BridgeConfig, SecretValue
from .radio import Wifit3StationRadio


DEFAULT_RATES = (0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24)
DEFAULT_BEACON_TIMEOUT = 10.0


class AssociationError(RuntimeError):
    """The target AP profile or auth/association exchange was rejected."""


@dataclass(frozen=True)
class AccessPointProfile:
    ssid: str
    bssid: bytes
    capability_info: int
    supported_rates: tuple
    rsn_element: InformationElement


def parse_target_beacon(
    raw: bytes, *, expected_ssid: str, expected_bssid: bytes
) -> AccessPointProfile:
    """Parse and validate one target Beacon/Probe Response without wifit3 types."""
    if len(raw) < 36:
        raise AssociationError("target beacon is truncated")
    frame_control = FrameControl.decode(raw[:2])
    if frame_control.frame_type != 0 or frame_control.subtype not in (5, 8):
        raise AssociationError("frame is not a Beacon or Probe Response")
    bssid = mac_bytes(expected_bssid)
    if raw[10:16] != bssid or raw[16:22] != bssid:
        raise AssociationError("beacon does not belong to the requested BSSID")
    capability_info = struct.unpack_from("<H", raw, 34)[0]
    elements = parse_information_elements(raw[36:])
    ssid_element = first_element(elements, ElementID.SSID)
    if ssid_element is None:
        raise AssociationError("target beacon has no SSID element")
    try:
        ssid = ssid_element.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AssociationError("target SSID is not valid UTF-8") from exc
    if ssid != expected_ssid:
        raise AssociationError("beacon SSID does not match the requested network")

    rates = b"".join(
        element.data
        for element in elements
        if element.element_id
        in (int(ElementID.SUPPORTED_RATES), int(ElementID.EXTENDED_SUPPORTED_RATES))
    )
    if not rates:
        rates = bytes(DEFAULT_RATES)
    security = parse_security_information(
        elements, privacy_capability=bool(capability_info & int(Capability.PRIVACY))
    )
    if security.mode not in (SecurityMode.WPA2_PERSONAL, SecurityMode.WPA2_WPA3_PERSONAL):
        raise AssociationError(
            "target must advertise WPA2-Personal; observed %s" % security.mode.value
        )
    if security.rsn is None:
        raise AssociationError("target did not advertise an RSN element")
    if RSN_CCMP_128 not in security.rsn.pairwise_ciphers:
        raise AssociationError("target does not advertise CCMP-128 pairwise encryption")
    if not any(
        suite.oui == RSN_OUI and suite.suite_type == RSN_PSK.suite_type
        for suite in security.rsn.akm_suites
    ):
        raise AssociationError("target does not advertise WPA2-PSK authentication")
    if (
        security.rsn.capabilities is not None
        and security.rsn.capabilities.management_frame_protection_required
    ):
        raise AssociationError("management-frame protection is required but not implemented")

    # Select one conservative suite instead of reflecting every AP-offered mode
    # (notably SAE from a WPA2/WPA3 transition beacon).
    rsn_element = build_rsn_element(
        group_cipher=security.rsn.group_cipher,
        pairwise_ciphers=(RSN_CCMP_128,),
        akm_suites=(RSN_PSK,),
        capabilities=0,
    )
    return AccessPointProfile(ssid, bssid, capability_info, tuple(rates), rsn_element)


class Decoder(Protocol):
    """A completed handshake's protected-frame decoder.

    Return the MindRove UDP payload for delivery, or ``None`` for frames that
    are valid but not application data (rekeys, ARP, keepalives, etc.).
    """

    async def __call__(self, frame: bytes) -> Optional[bytes]: ...


class PacketCallback(Protocol):
    async def __call__(self, payload: bytes) -> None: ...


class HandshakeCallback(Protocol):
    async def __call__(
        self, exchange: "StationExchange", passphrase: SecretValue
    ) -> Decoder: ...

class StationExchange:
    """Minimal send/receive surface passed to an independent WPA2 engine."""

    def __init__(
        self,
        radio: Wifit3StationRadio,
        config: BridgeConfig,
        profile: AccessPointProfile,
        *,
        status: Callable[[str], None] = lambda _message: None,
    ) -> None:
        self.radio = radio
        self.config = config
        self.profile = profile
        self._status = status

    @property
    def station_mac(self) -> bytes:
        return self.radio.station_mac

    async def send_frame(self, frame: bytes) -> None:
        await self.radio.send(frame)

    async def receive_frame(self, timeout: Optional[float] = None) -> bytes:
        return (await self.radio.receive(timeout)).raw

    def report_status(self, message: str) -> None:
        """Emit a non-secret live-data-path diagnostic."""
        self._status(message)


class StationOrchestrator:
    """Bring up one c811, associate to one BSSID, and dispatch decoded data."""

    def __init__(
        self,
        radio: Wifit3StationRadio,
        config: BridgeConfig,
        *,
        status: Callable[[str], None] = lambda _message: None,
    ) -> None:
        if radio.bssid != config.bssid:
            raise ValueError("radio and bridge configuration BSSID differ")
        self.radio = radio
        self.config = config
        self._status = status
        self.profile: Optional[AccessPointProfile] = None
        self.exchange: Optional[StationExchange] = None

    async def prepare(
        self, *, beacon_timeout: float = DEFAULT_BEACON_TIMEOUT
    ) -> StationExchange:
        """Cold-connect, verify channel, activate MAC, and complete auth/assoc."""
        self._status("claiming exact USB adapter 0bda:c811")
        await self.radio.connect()
        self._status("radio firmware and MAC/BB/RF bring-up complete")
        await self.radio.tune_fixed(self.config.channel)
        self._status("2.4-GHz channel verified by RF18 readback")
        # A beacon is broadcast traffic and does not require the station MAC to
        # be programmed.  Validate it while the adapter is still in the same
        # passive-monitor state used by the target scanner.  Doing this before
        # REG_MACID programming also separates target discovery failures from
        # active-station authentication failures.
        profile = await self._wait_for_profile(beacon_timeout)
        self._status("target WPA2-PSK/CCMP beacon validated")
        await self.radio.activate_station()
        self._status("target-only active station MAC enabled")
        await self._authenticate(profile)
        await self._associate(profile)
        self._status("Open System authentication and WPA2 association complete")
        self.profile = profile
        self.exchange = StationExchange(
            self.radio,
            self.config,
            profile,
            status=self._status,
        )
        return self.exchange

    async def _wait_for_profile(self, timeout: float) -> AccessPointProfile:
        deadline = time.monotonic() + timeout
        last_error: Optional[Exception] = None
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                received = await self.radio.receive(remaining)
                return parse_target_beacon(
                    received.raw,
                    expected_ssid=self.config.ssid,
                    expected_bssid=self.config.bssid,
                )
            except TimeoutError:
                break
            except AssociationError as exc:
                # Target-origin traffic other than a beacon is expected while
                # waiting, so retain only the last useful diagnostic.
                last_error = exc
        detail = ": %s" % last_error if last_error is not None else ""
        raise AssociationError("no usable target beacon before timeout" + detail)

    async def _authenticate(self, _profile: AccessPointProfile) -> None:
        request = build_authentication(
            self.radio.station_mac,
            self.config.bssid,
            algorithm=AuthenticationAlgorithm.OPEN_SYSTEM,
            transaction=1,
        )
        for _ in range(self.config.attempts):
            self.radio.frames.drain()
            await self.radio.send(request)
            deadline = time.monotonic() + self.config.auth_timeout
            while time.monotonic() < deadline:
                try:
                    frame = await self.radio.receive(deadline - time.monotonic())
                except TimeoutError:
                    break
                try:
                    response = parse_authentication(frame.raw)
                except Exception:
                    continue
                if response.algorithm != int(AuthenticationAlgorithm.OPEN_SYSTEM):
                    continue
                if response.transaction != 2:
                    continue
                if response.status_code != 0:
                    raise AssociationError(
                        "Open System authentication rejected with status %d"
                        % response.status_code
                    )
                return
        raise AssociationError("target did not answer Open System authentication")

    async def _associate(self, profile: AccessPointProfile) -> None:
        safe_capabilities = int(Capability.ESS)
        for optional in (Capability.SHORT_PREAMBLE, Capability.SHORT_SLOT_TIME):
            if profile.capability_info & int(optional):
                safe_capabilities |= int(optional)
        request = build_association_request(
            self.radio.station_mac,
            self.config.bssid,
            self.config.ssid,
            profile.supported_rates,
            capability_info=safe_capabilities,
            listen_interval=10,
            extra_elements=(profile.rsn_element,),
        )
        for _ in range(self.config.attempts):
            await self.radio.send(request)
            deadline = time.monotonic() + self.config.association_timeout
            while time.monotonic() < deadline:
                try:
                    frame = await self.radio.receive(deadline - time.monotonic())
                except TimeoutError:
                    break
                try:
                    response = parse_association_response(frame.raw)
                except Exception:
                    continue
                if response.status_code != 0:
                    raise AssociationError(
                        "association rejected with status %d" % response.status_code
                    )
                return
        raise AssociationError("target did not answer the WPA2 association request")

    async def run(
        self,
        *,
        passphrase: SecretValue,
        handshake: HandshakeCallback,
        packet_callback: PacketCallback,
        stop: Optional[asyncio.Event] = None,
    ) -> None:
        """Prepare, delegate WPA2 key exchange, then dispatch decoded payloads."""
        exchange = await self.prepare()
        self._status("starting WPA2 four-way handshake")
        decoder = await handshake(exchange, passphrase)
        if not callable(decoder):
            raise TypeError("handshake callback must return a frame decoder")
        self._status(
            "pairwise and group CCMP keys installed; forwarding UDP/4210 to loopback"
        )
        while stop is None or not stop.is_set():
            try:
                received = await self.radio.receive(0.25 if stop is not None else None)
            except TimeoutError:
                continue
            payload = await decoder(received.raw)
            if payload is not None:
                await packet_callback(bytes(payload))

    async def close(self) -> None:
        await self.radio.close()


class LoopbackUdpSink:
    """Deliver decoded MindRove datagrams only to a local UDP consumer."""

    def __init__(self, host: str = "127.0.0.1", port: int = 4210) -> None:
        # Reuse BridgeConfig's strict loopback/port validation without retaining
        # an artificial station target.
        import ipaddress

        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("UDP sink must be a loopback address")
        if not 1 <= port <= 65535:
            raise ValueError("UDP port must be between 1 and 65535")
        self.destination = (host, port)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._socket = socket.socket(family, socket.SOCK_DGRAM)
        self._socket.setblocking(False)

    async def __call__(self, payload: bytes) -> None:
        await asyncio.get_running_loop().sock_sendto(
            self._socket, bytes(payload), self.destination
        )

    def close(self) -> None:
        self._socket.close()
