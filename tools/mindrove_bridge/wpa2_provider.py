# SPDX-License-Identifier: GPL-2.0-only
"""Concrete WPA2-PSK/CCMP and minimal MindRove ARP/IPv4/UDP data plane."""

from __future__ import annotations

from ipaddress import IPv4Address
import secrets
import time
from typing import Any, Callable, Optional, cast

from mindrove_station.ccmp import CCMPHeader, CCMPReceiver, CCMPTransmitter
from mindrove_station.data import build_station_data, parse_data
from mindrove_station.errors import (
    FrameFormatError,
    HandshakeError,
    IntegrityError,
    ReplayError,
)
from mindrove_station.llc import EtherType
from mindrove_station.network import (
    ARP_ETHERNET_IPV4_LENGTH,
    IP_PROTOCOL_UDP,
    MINDROVE_NETWORK,
    MindRoveNetworkState,
    MindRoveStaticConfig,
    build_ipv4,
    build_udp,
    parse_ipv4_udp,
)
from mindrove_station.wpa2 import WPA2PSKHandshake, derive_pmk

from .config import SecretValue
from .dhcp import (
    DHCP_CLIENT_PORT,
    DHCP_SERVER_PORT,
    DHCPError,
    DHCPLease,
    DHCPOffer,
    MindRoveDHCPClient,
)
from .session import Decoder, StationExchange


EXG_START_COMMAND = b"\x00\x00\x00\x00\x00"
EPHEMERAL_PORT_MIN = 49152
EPHEMERAL_PORT_MAX = 65535
_ZERO_IP = IPv4Address("0.0.0.0")
_LIMITED_BROADCAST = IPv4Address("255.255.255.255")


class WPA2Timeout(HandshakeError):
    """The AP did not complete its four-way handshake in time."""


class DHCPTimeout(TimeoutError):
    """The MindRove did not complete DHCP acquisition within bounded retries."""


def _random_ephemeral_port() -> int:
    width = EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN + 1
    return EPHEMERAL_PORT_MIN + secrets.randbelow(width)


class _SequenceNumbers:
    def __init__(self) -> None:
        self._next = 0

    def take(self) -> int:
        value = self._next
        self._next = (self._next + 1) & 0xFFF
        return value


def _eapol_from_ap(frame: bytes) -> Optional[bytes]:
    try:
        parsed = parse_data(frame, decode_llc=False)
    except (FrameFormatError, ValueError):
        return None
    if not parsed.frame_control.from_ds or parsed.frame_control.to_ds:
        return None
    # Some Realtek RX paths expose up to three alignment octets between a QoS
    # MAC header and LLC. wifit3 itself window-scans this signature; mirror that
    # narrowly instead of accepting an LLC marker anywhere in attacker data.
    signature = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
    offset = parsed.body[: len(signature) + 3].find(signature)
    if offset < 0:
        return None
    payload = parsed.body[offset + len(signature) :]
    if len(payload) < 4:
        return None
    packet_length = int.from_bytes(payload[2:4], "big") + 4
    if packet_length > len(payload):
        return None
    return payload[:packet_length]


class SecureMindRoveDataPlane:
    """Pairwise CCMP plus the fixed MindRove ARP/IPv4/UDP profile."""

    def __init__(
        self,
        exchange: StationExchange,
        handshake: WPA2PSKHandshake,
        *,
        receiver_factory: Callable[..., Any] = CCMPReceiver,
        group_receiver_factory: Optional[Callable[..., Any]] = None,
        transmitter_factory: Callable[[bytes], Any] = CCMPTransmitter,
        network_factory: Callable[[bytes], Any] = MindRoveNetworkState,
        dhcp_factory: Callable[..., Any] = MindRoveDHCPClient,
        ephemeral_port_factory: Callable[[], int] = _random_ephemeral_port,
    ) -> None:
        if not handshake.complete or handshake.pairwise_keys is None:
            raise HandshakeError("pairwise keys are unavailable before completed M3")
        self.exchange = exchange
        self.handshake = handshake
        key = handshake.pairwise_keys.temporal_key
        self.receiver = receiver_factory(key)
        self.group_receiver = None
        self.group_key_id: Optional[int] = None
        group_key = getattr(handshake, "group_key", None)
        if group_key is not None:
            make_group_receiver = group_receiver_factory or receiver_factory
            self.group_key_id = group_key.key_id
            self.group_receiver = make_group_receiver(
                group_key.temporal_key,
                expected_key_id=group_key.key_id,
                initial_packet_number=group_key.receive_packet_number,
            )
        self.transmitter = transmitter_factory(key)
        self.network = network_factory(exchange.station_mac)
        self._dhcp_factory = dhcp_factory
        self._sequence = _SequenceNumbers()
        self._startup_sent = False
        self._reported_status: set[str] = set()
        self.lease: Optional[DHCPLease] = None
        self.command_source_port = int(ephemeral_port_factory())
        if not EPHEMERAL_PORT_MIN <= self.command_source_port <= EPHEMERAL_PORT_MAX:
            raise ValueError("EXG command source port must be in the dynamic port range")

    def _report_once(self, event: str, message: str) -> None:
        if event in self._reported_status:
            return
        self._reported_status.add(event)
        reporter = getattr(self.exchange, "report_status", None)
        if callable(reporter):
            reporter(message)

    async def _send_network(
        self, payload: bytes, ethertype: EtherType, destination: bytes
    ) -> None:
        plaintext = build_station_data(
            self.exchange.station_mac,
            self.exchange.config.bssid,
            destination,
            payload,
            ethertype,
            sequence_number=self._sequence.take(),
        )
        await self.exchange.send_frame(self.transmitter.encrypt(plaintext))

    async def request_peer_mac(self) -> None:
        """Send a protected ARP request for the fixed peer 192.168.4.1."""
        await self._send_network(
            self.network.build_arp_request(), EtherType.ARP, b"\xff" * 6
        )
        self._report_once("arp-request", "protected ARP request sent to 192.168.4.1")

    async def send_udp(
        self,
        payload: bytes,
        *,
        source_port: int = 4210,
        destination_port: int = 4210,
    ) -> None:
        """Send one UDP payload to the MindRove after its MAC is learned."""
        if self.network.peer_mac is None:
            raise RuntimeError("MindRove MAC is not learned; await the ARP reply")
        packet = self.network.build_udp(
            payload,
            source_port=source_port,
            destination_port=destination_port,
        )
        await self._send_network(packet, EtherType.IPV4, self.network.peer_mac)

    async def _handle_unprotected_eapol(self, raw: bytes) -> None:
        payload = _eapol_from_ap(raw)
        if payload is None:
            return
        # A byte-identical M3 retransmission after completion safely produces
        # the cached M4. A changed/rekey message fails closed.
        try:
            response = self.handshake.process(payload)
        except (HandshakeError, ReplayError):
            return
        plaintext = build_station_data(
            self.exchange.station_mac,
            self.exchange.config.bssid,
            self.exchange.config.bssid,
            response,
            EtherType.EAPOL,
            sequence_number=self._sequence.take(),
        )
        await self.exchange.send_frame(plaintext)

    async def _decode_ap_data(self, raw: bytes) -> Optional[Any]:
        """Validate AP origin, select pairwise/GTK CCMP, and decode LLC."""
        try:
            outer = parse_data(raw, decode_llc=False)
        except (FrameFormatError, ValueError):
            return None
        if (
            not outer.frame_control.from_ds
            or outer.frame_control.to_ds
            or outer.transmitter != self.exchange.config.bssid
            or outer.bssid != self.exchange.config.bssid
        ):
            return None
        if not outer.frame_control.protected:
            await self._handle_unprotected_eapol(raw)
            return None
        is_group = bool(outer.receiver[0] & 1)
        try:
            ccmp_header = CCMPHeader.parse(outer.body[:8])
        except (FrameFormatError, ReplayError, ValueError):
            return None
        if is_group:
            if self.group_receiver is None or ccmp_header.key_id != self.group_key_id:
                self._report_once(
                    "group-key-mismatch",
                    "received group CCMP traffic with an uninstalled key ID",
                )
                return None
            receiver = self.group_receiver
        else:
            if outer.receiver != self.exchange.station_mac or ccmp_header.key_id != 0:
                return None
            receiver = self.receiver
        try:
            plaintext = receiver.decrypt(raw).frame
            data = parse_data(plaintext)
        except (FrameFormatError, IntegrityError, ReplayError, ValueError):
            kind = "group" if is_group else "pairwise"
            self._report_once(
                kind + "-ccmp-rejected",
                "received %s CCMP traffic but authentication/replay checks rejected it"
                % kind,
            )
            return None
        kind = "group" if is_group else "pairwise"
        self._report_once(
            kind + "-ccmp-authenticated",
            "authenticated first %s CCMP data frame" % kind,
        )
        return data

    async def _send_dhcp(self, payload: bytes) -> None:
        udp = build_udp(
            payload,
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            _ZERO_IP,
            _LIMITED_BROADCAST,
        )
        ipv4 = build_ipv4(
            udp,
            _ZERO_IP,
            _LIMITED_BROADCAST,
            IP_PROTOCOL_UDP,
        )
        await self._send_network(ipv4, EtherType.IPV4, b"\xff" * 6)

    @staticmethod
    def _dhcp_ipv4_payload(data: Any) -> Optional[bytes]:
        if data.llc is None or data.llc.ethertype != int(EtherType.IPV4):
            return None
        packet = data.llc.payload
        if len(packet) < 4:
            return None
        total_length = int.from_bytes(packet[2:4], "big")
        if total_length < 20 or total_length > len(packet):
            return None
        return packet[:total_length]

    async def _wait_for_offer(
        self,
        client: MindRoveDHCPClient,
        timeout: float,
    ) -> DHCPOffer:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for DHCPOFFER")
            try:
                raw = await self.exchange.receive_frame(remaining)
            except TimeoutError as exc:
                raise TimeoutError("timed out waiting for DHCPOFFER") from exc
            data = await self._decode_ap_data(raw)
            if data is None:
                continue
            packet = self._dhcp_ipv4_payload(data)
            if packet is None:
                continue
            try:
                ipv4, udp = parse_ipv4_udp(packet)
                if (
                    udp.source_port != DHCP_SERVER_PORT
                    or udp.destination_port != DHCP_CLIENT_PORT
                ):
                    continue
                offer = client.parse_offer(udp.payload, source_ip=ipv4.source)
                if ipv4.destination not in (
                    offer.address,
                    MINDROVE_NETWORK.broadcast_address,
                    _LIMITED_BROADCAST,
                ):
                    raise DHCPError("DHCPOFFER has an unrelated IPv4 destination")
                return offer
            except (DHCPError, FrameFormatError, IntegrityError, ValueError):
                self._report_once(
                    "dhcp-invalid-offer",
                    "ignored malformed DHCPOFFER or lease other than required "
                    "192.168.4.2",
                )

    async def _wait_for_ack(
        self,
        client: MindRoveDHCPClient,
        offer: DHCPOffer,
        timeout: float,
    ) -> DHCPLease:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for DHCPACK")
            try:
                raw = await self.exchange.receive_frame(remaining)
            except TimeoutError as exc:
                raise TimeoutError("timed out waiting for DHCPACK") from exc
            data = await self._decode_ap_data(raw)
            if data is None:
                continue
            packet = self._dhcp_ipv4_payload(data)
            if packet is None:
                continue
            try:
                ipv4, udp = parse_ipv4_udp(packet)
                if (
                    udp.source_port != DHCP_SERVER_PORT
                    or udp.destination_port != DHCP_CLIENT_PORT
                ):
                    continue
                lease = client.parse_ack(
                    udp.payload,
                    offer,
                    source_ip=ipv4.source,
                )
                if ipv4.destination not in (
                    lease.address,
                    MINDROVE_NETWORK.broadcast_address,
                    _LIMITED_BROADCAST,
                ):
                    raise DHCPError("DHCPACK has an unrelated IPv4 destination")
                return lease
            except (DHCPError, FrameFormatError, IntegrityError, ValueError):
                self._report_once(
                    "dhcp-invalid-ack",
                    "ignored malformed DHCPACK or lease other than required "
                    "192.168.4.2",
                )

    async def acquire_lease(
        self,
        *,
        attempts: int = 4,
        offer_timeout: float = 2.0,
        ack_timeout: float = 2.0,
    ) -> DHCPLease:
        """Acquire and install one narrow DHCP lease before ARP begins."""
        if attempts <= 0 or offer_timeout <= 0 or ack_timeout <= 0:
            raise ValueError("DHCP attempts and timeouts must be positive")
        client = self._dhcp_factory(self.exchange.station_mac)
        for attempt in range(1, attempts + 1):
            self.exchange.report_status(
                "sending protected DHCPDISCOVER (attempt %d/%d)"
                % (attempt, attempts)
            )
            await self._send_dhcp(client.discover())
            try:
                offer = await self._wait_for_offer(client, offer_timeout)
            except TimeoutError:
                continue
            self.exchange.report_status("accepted DHCPOFFER for %s" % offer.address)
            await self._send_dhcp(client.request(offer))
            self.exchange.report_status("sent protected DHCPREQUEST")
            try:
                lease = await self._wait_for_ack(client, offer, ack_timeout)
            except TimeoutError:
                continue
            self.network.config = MindRoveStaticConfig(host_ip=lease.address)
            self.lease = lease
            self.exchange.report_status("installed DHCP lease %s/24" % lease.address)
            return lease
        raise DHCPTimeout(
            "MindRove did not complete DHCP after %d attempts" % attempts
        )

    async def __call__(self, raw: bytes) -> Optional[bytes]:
        """Decrypt one AP frame and return only a valid UDP/4210 payload."""
        data = await self._decode_ap_data(raw)
        if data is None:
            return None
        if data.llc is None:
            return None
        if data.llc.ethertype == int(EtherType.ARP):
            # 802.11 implementations may append zero padding. The ARP parser
            # intentionally requires its exact fixed length.
            if len(data.llc.payload) < ARP_ETHERNET_IPV4_LENGTH:
                return None
            arp_payload = data.llc.payload[:ARP_ETHERNET_IPV4_LENGTH]
            try:
                had_peer = self.network.peer_mac is not None
                reply = self.network.handle_arp(arp_payload)
            except (FrameFormatError, ValueError):
                return None
            if not had_peer and self.network.peer_mac is not None:
                self._report_once("arp-learned", "MindRove peer MAC learned by ARP")
            if reply is not None and self.network.peer_mac is not None:
                await self._send_network(reply, EtherType.ARP, self.network.peer_mac)
            if self.network.peer_mac is not None and not self._startup_sent:
                # Captured stock-client behavior: a single five-zero-byte UDP
                # datagram on 4210 selects the EXG configuration. Delay it until
                # protected ARP has resolved the peer so it cannot be sent to a
                # guessed layer-2 destination.
                await self.send_udp(
                    EXG_START_COMMAND,
                    source_port=self.command_source_port,
                )
                self._startup_sent = True
                self._report_once(
                    "exg-start",
                    "protected five-byte EXG configuration sent on UDP/4210",
                )
            return None
        if data.llc.ethertype != int(EtherType.IPV4):
            return None
        ip_payload = data.llc.payload
        if len(ip_payload) < 4:
            return None
        total_length = int.from_bytes(ip_payload[2:4], "big")
        if total_length < 20 or total_length > len(ip_payload):
            return None
        try:
            datagram = self.network.receive_ipv4(ip_payload[:total_length])
        except (FrameFormatError, IntegrityError, ValueError):
            return None
        if datagram is None:
            return None
        self._report_once(
            "udp-delivered",
            "validated first MindRove UDP/4210 payload for loopback delivery",
        )
        return datagram.payload


class DefaultWPA2Handshake:
    """Concrete four-way handshake callback used by the CLI."""

    def __init__(
        self,
        *,
        timeout: float = 8.0,
        handshake_factory: Callable[..., WPA2PSKHandshake] = WPA2PSKHandshake,
        plane_factory: Callable[..., SecureMindRoveDataPlane] = SecureMindRoveDataPlane,
    ) -> None:
        if timeout <= 0:
            raise ValueError("WPA2 handshake timeout must be positive")
        self.timeout = timeout
        self._handshake_factory = handshake_factory
        self._plane_factory = plane_factory
        self.data_plane: Optional[SecureMindRoveDataPlane] = None

    async def __call__(
        self, exchange: StationExchange, passphrase: SecretValue
    ) -> Decoder:
        pmk = derive_pmk(passphrase.reveal(), exchange.config.ssid)
        handshake = self._handshake_factory(
            pmk,
            exchange.config.bssid,
            exchange.station_mac,
            exchange.profile.rsn_element.encode(),
        )
        sequence = _SequenceNumbers()
        deadline = time.monotonic() + self.timeout
        while not handshake.complete:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WPA2Timeout("MindRove did not complete the WPA2 four-way handshake")
            try:
                raw = await exchange.receive_frame(remaining)
            except TimeoutError as exc:
                raise WPA2Timeout(
                    "MindRove did not complete the WPA2 four-way handshake"
                ) from exc
            eapol = _eapol_from_ap(raw)
            if eapol is None:
                continue
            response = handshake.process(eapol)
            plaintext = build_station_data(
                exchange.station_mac,
                exchange.config.bssid,
                exchange.config.bssid,
                response,
                EtherType.EAPOL,
                sequence_number=sequence.take(),
            )
            await exchange.send_frame(plaintext)

        if handshake.group_key is None:
            raise HandshakeError(
                "authenticated M3 did not install the group key needed for "
                "MindRove broadcast data"
            )
        plane = self._plane_factory(exchange, handshake)
        await plane.acquire_lease()
        await plane.request_peer_mac()
        self.data_plane = plane
        return cast(Decoder, plane)
