# SPDX-License-Identifier: GPL-2.0-only
"""Minimal ARP, IPv4, and UDP support for the MindRove station.

This module deliberately implements a small, auditable network subset rather
than a general-purpose IP stack.  It accepts only unfragmented IPv4 datagrams
without options, Ethernet/IPv4 ARP packets, and UDP.  The state helper fixes
the peer at MindRove's documented ``192.168.4.1`` endpoint while allowing the
host to choose an unused address from ``192.168.4.2`` through
``192.168.4.254``.

All parsers require an exact packet length.  Callers must remove link-layer
padding, FCS bytes, or encryption trailers before using them.
"""

from dataclasses import dataclass
from enum import IntEnum
from ipaddress import AddressValueError, IPv4Address, IPv4Network, NetmaskValueError
import struct
from typing import Optional, Tuple, Union

from .common import MACAddressInput, mac_bytes
from .errors import FrameFormatError, IntegrityError


IPv4AddressInput = Union[str, int, bytes, bytearray, memoryview, IPv4Address]

IPV4_HEADER_LENGTH = 20
UDP_HEADER_LENGTH = 8
ARP_ETHERNET_IPV4_LENGTH = 28

IP_PROTOCOL_UDP = 17
ETHERNET_HARDWARE_TYPE = 1
IPV4_ETHERTYPE = 0x0800

MINDROVE_NETWORK = IPv4Network("192.168.4.0/24")
MINDROVE_PEER_IP = IPv4Address("192.168.4.1")
MINDROVE_STREAM_PORT = 4210
LIMITED_BROADCAST = IPv4Address("255.255.255.255")

ZERO_MAC = b"\x00" * 6
BROADCAST_MAC = b"\xff" * 6


def _ipv4_address(value: IPv4AddressInput, field_name: str) -> IPv4Address:
    if isinstance(value, (bytearray, memoryview)):
        value = bytes(value)
    try:
        address = IPv4Address(value)
    except (AddressValueError, NetmaskValueError, ValueError, TypeError) as exc:
        raise ValueError("%s must be an IPv4 address" % field_name) from exc
    return address


def _uint(value: int, bits: int, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("%s must be an integer" % field_name)
    if not 0 <= value < (1 << bits):
        raise ValueError("%s must fit in %d bits" % (field_name, bits))
    return value


def internet_checksum(data: bytes) -> int:
    """Return the RFC 1071 one's-complement checksum for *data*.

    A correct packet that includes its checksum field produces zero when the
    entire protected region is passed to this function.
    """

    octets = bytes(data)
    if len(octets) & 1:
        octets += b"\x00"
    total = 0
    for offset in range(0, len(octets), 2):
        total += (octets[offset] << 8) | octets[offset + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


@dataclass(frozen=True)
class IPv4Packet:
    source: IPv4Address
    destination: IPv4Address
    protocol: int
    payload: bytes
    identification: int
    ttl: int
    dscp_ecn: int
    dont_fragment: bool
    header_checksum: int


def build_ipv4(
    payload: bytes,
    source: IPv4AddressInput,
    destination: IPv4AddressInput,
    protocol: int,
    *,
    identification: int = 0,
    ttl: int = 64,
    dscp_ecn: int = 0,
    dont_fragment: bool = True,
) -> bytes:
    """Build one unfragmented, option-free IPv4 datagram."""

    payload_value = bytes(payload)
    source_value = _ipv4_address(source, "source")
    destination_value = _ipv4_address(destination, "destination")
    protocol_value = _uint(protocol, 8, "protocol")
    identification_value = _uint(identification, 16, "identification")
    ttl_value = _uint(ttl, 8, "TTL")
    dscp_ecn_value = _uint(dscp_ecn, 8, "DSCP/ECN")
    total_length = IPV4_HEADER_LENGTH + len(payload_value)
    if total_length > 0xFFFF:
        raise ValueError("IPv4 payload is too large for one unfragmented datagram")

    flags_fragment = 0x4000 if dont_fragment else 0
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        dscp_ecn_value,
        total_length,
        identification_value,
        flags_fragment,
        ttl_value,
        protocol_value,
        0,
        source_value.packed,
        destination_value.packed,
    )
    checksum = internet_checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + payload_value


def parse_ipv4(packet: bytes) -> IPv4Packet:
    """Parse and checksum one complete, unfragmented IPv4 datagram."""

    packet_value = bytes(packet)
    if len(packet_value) < IPV4_HEADER_LENGTH:
        raise FrameFormatError("IPv4 packet is shorter than 20 bytes")

    version_ihl = packet_value[0]
    if version_ihl >> 4 != 4:
        raise FrameFormatError("packet is not IPv4")
    ihl = version_ihl & 0x0F
    if ihl < 5:
        raise FrameFormatError("IPv4 IHL is shorter than the minimum header")
    if ihl != 5:
        raise FrameFormatError("IPv4 options are not supported")

    (
        _version_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        header_checksum,
        source,
        destination,
    ) = struct.unpack_from("!BBHHHBBH4s4s", packet_value)

    if total_length < IPV4_HEADER_LENGTH:
        raise FrameFormatError("IPv4 total length is shorter than its header")
    if total_length != len(packet_value):
        raise FrameFormatError(
            "IPv4 total length does not match the supplied packet length"
        )
    if flags_fragment & 0x8000:
        raise FrameFormatError("IPv4 reserved flag is set")
    if flags_fragment & 0x2000 or flags_fragment & 0x1FFF:
        raise FrameFormatError("fragmented IPv4 datagrams are not supported")
    if internet_checksum(packet_value[:IPV4_HEADER_LENGTH]) != 0:
        raise IntegrityError("invalid IPv4 header checksum")

    return IPv4Packet(
        source=IPv4Address(source),
        destination=IPv4Address(destination),
        protocol=protocol,
        payload=bytes(packet_value[IPV4_HEADER_LENGTH:]),
        identification=identification,
        ttl=ttl,
        dscp_ecn=dscp_ecn,
        dont_fragment=bool(flags_fragment & 0x4000),
        header_checksum=header_checksum,
    )


@dataclass(frozen=True)
class UDPSegment:
    source_port: int
    destination_port: int
    payload: bytes
    checksum: int

    @property
    def checksum_present(self) -> bool:
        return self.checksum != 0


def _udp_pseudo_header(
    source: IPv4Address, destination: IPv4Address, udp_length: int
) -> bytes:
    return struct.pack(
        "!4s4sBBH",
        source.packed,
        destination.packed,
        0,
        IP_PROTOCOL_UDP,
        udp_length,
    )


def build_udp(
    payload: bytes,
    source_port: int,
    destination_port: int,
    source_ip: IPv4AddressInput,
    destination_ip: IPv4AddressInput,
) -> bytes:
    """Build a UDP segment with the mandatory-for-this-builder IPv4 checksum."""

    payload_value = bytes(payload)
    source_port_value = _uint(source_port, 16, "UDP source port")
    destination_port_value = _uint(destination_port, 16, "UDP destination port")
    source_value = _ipv4_address(source_ip, "source IP")
    destination_value = _ipv4_address(destination_ip, "destination IP")
    length = UDP_HEADER_LENGTH + len(payload_value)
    if length > 0xFFFF:
        raise ValueError("UDP payload is too large")

    segment = (
        struct.pack(
            "!HHHH",
            source_port_value,
            destination_port_value,
            length,
            0,
        )
        + payload_value
    )
    checksum = internet_checksum(
        _udp_pseudo_header(source_value, destination_value, length) + segment
    )
    # RFC 768 transmits an all-zero computed checksum as all ones; zero on the
    # wire means that an IPv4 sender omitted the checksum.
    if checksum == 0:
        checksum = 0xFFFF
    return segment[:6] + struct.pack("!H", checksum) + segment[8:]


def parse_udp(
    segment: bytes,
    source_ip: IPv4AddressInput,
    destination_ip: IPv4AddressInput,
    *,
    allow_zero_checksum: bool = True,
) -> UDPSegment:
    """Parse one complete UDP segment and validate any transmitted checksum.

    IPv4 permits a zero UDP checksum.  It is accepted by default for device
    interoperability and reported through :attr:`UDPSegment.checksum_present`.
    Set ``allow_zero_checksum`` to false when integrity is required.
    """

    segment_value = bytes(segment)
    if len(segment_value) < UDP_HEADER_LENGTH:
        raise FrameFormatError("UDP segment is shorter than 8 bytes")
    source_port, destination_port, length, checksum = struct.unpack_from(
        "!HHHH", segment_value
    )
    if length < UDP_HEADER_LENGTH:
        raise FrameFormatError("UDP length is shorter than its header")
    if length != len(segment_value):
        raise FrameFormatError("UDP length does not match the supplied segment length")

    source_value = _ipv4_address(source_ip, "source IP")
    destination_value = _ipv4_address(destination_ip, "destination IP")
    if checksum == 0:
        if not allow_zero_checksum:
            raise IntegrityError("UDP checksum is absent")
    elif (
        internet_checksum(
            _udp_pseudo_header(source_value, destination_value, length) + segment_value
        )
        != 0
    ):
        raise IntegrityError("invalid UDP checksum")

    return UDPSegment(
        source_port=source_port,
        destination_port=destination_port,
        payload=bytes(segment_value[UDP_HEADER_LENGTH:]),
        checksum=checksum,
    )


def parse_ipv4_udp(
    packet: bytes, *, allow_zero_udp_checksum: bool = True
) -> Tuple[IPv4Packet, UDPSegment]:
    """Parse a complete IPv4/UDP datagram and validate both checksums."""

    ipv4 = parse_ipv4(packet)
    if ipv4.protocol != IP_PROTOCOL_UDP:
        raise FrameFormatError("IPv4 payload is not UDP")
    udp = parse_udp(
        ipv4.payload,
        ipv4.source,
        ipv4.destination,
        allow_zero_checksum=allow_zero_udp_checksum,
    )
    return ipv4, udp


class ARPOperation(IntEnum):
    REQUEST = 1
    REPLY = 2


@dataclass(frozen=True)
class ARPPacket:
    operation: ARPOperation
    sender_hardware: bytes
    sender_protocol: IPv4Address
    target_hardware: bytes
    target_protocol: IPv4Address


def _build_arp(
    operation: ARPOperation,
    sender_hardware: MACAddressInput,
    sender_protocol: IPv4AddressInput,
    target_hardware: MACAddressInput,
    target_protocol: IPv4AddressInput,
) -> bytes:
    return (
        struct.pack(
            "!HHBBH",
            ETHERNET_HARDWARE_TYPE,
            IPV4_ETHERTYPE,
            6,
            4,
            int(operation),
        )
        + mac_bytes(sender_hardware)
        + _ipv4_address(sender_protocol, "ARP sender protocol address").packed
        + mac_bytes(target_hardware)
        + _ipv4_address(target_protocol, "ARP target protocol address").packed
    )


def build_arp_request(
    sender_hardware: MACAddressInput,
    sender_protocol: IPv4AddressInput,
    target_protocol: IPv4AddressInput,
) -> bytes:
    """Build an Ethernet/IPv4 ARP request with an unknown target MAC."""

    return _build_arp(
        ARPOperation.REQUEST,
        sender_hardware,
        sender_protocol,
        ZERO_MAC,
        target_protocol,
    )


def build_arp_reply(
    sender_hardware: MACAddressInput,
    sender_protocol: IPv4AddressInput,
    target_hardware: MACAddressInput,
    target_protocol: IPv4AddressInput,
) -> bytes:
    """Build an Ethernet/IPv4 ARP reply."""

    return _build_arp(
        ARPOperation.REPLY,
        sender_hardware,
        sender_protocol,
        target_hardware,
        target_protocol,
    )


def parse_arp(packet: bytes) -> ARPPacket:
    """Parse the fixed 28-byte Ethernet/IPv4 ARP format."""

    packet_value = bytes(packet)
    if len(packet_value) != ARP_ETHERNET_IPV4_LENGTH:
        raise FrameFormatError("Ethernet/IPv4 ARP packet must be exactly 28 bytes")
    hardware_type, protocol_type, hlen, plen, operation = struct.unpack_from(
        "!HHBBH", packet_value
    )
    if hardware_type != ETHERNET_HARDWARE_TYPE:
        raise FrameFormatError("unsupported ARP hardware type")
    if protocol_type != IPV4_ETHERTYPE:
        raise FrameFormatError("unsupported ARP protocol type")
    if hlen != 6 or plen != 4:
        raise FrameFormatError("ARP address lengths are not Ethernet/IPv4")
    try:
        operation_value = ARPOperation(operation)
    except ValueError as exc:
        raise FrameFormatError("unsupported ARP operation") from exc

    return ARPPacket(
        operation=operation_value,
        sender_hardware=bytes(packet_value[8:14]),
        sender_protocol=IPv4Address(packet_value[14:18]),
        target_hardware=bytes(packet_value[18:24]),
        target_protocol=IPv4Address(packet_value[24:28]),
    )


@dataclass(frozen=True)
class MindRoveStaticConfig:
    """Static host parameters for the isolated MindRove ``/24`` network."""

    host_ip: IPv4Address = IPv4Address("192.168.4.2")

    def __post_init__(self) -> None:
        host = _ipv4_address(self.host_ip, "host IP")
        if host not in MINDROVE_NETWORK:
            raise ValueError("host IP must be inside 192.168.4.0/24")
        if host in (
            MINDROVE_NETWORK.network_address,
            MINDROVE_PEER_IP,
            MINDROVE_NETWORK.broadcast_address,
        ):
            raise ValueError("host IP must be in 192.168.4.2 through 192.168.4.254")
        object.__setattr__(self, "host_ip", host)

    @property
    def peer_ip(self) -> IPv4Address:
        return MINDROVE_PEER_IP

    @property
    def prefix_length(self) -> int:
        return MINDROVE_NETWORK.prefixlen

    @property
    def stream_port(self) -> int:
        return MINDROVE_STREAM_PORT

    def accepts_destination(self, destination: IPv4AddressInput) -> bool:
        address = _ipv4_address(destination, "destination")
        return address in (
            self.host_ip,
            MINDROVE_NETWORK.broadcast_address,
            LIMITED_BROADCAST,
        )


@dataclass(frozen=True)
class MindRoveDatagram:
    """Validated UDP/4210 payload plus metadata needed by acquisition code."""

    source_ip: IPv4Address
    destination_ip: IPv4Address
    source_port: int
    destination_port: int
    payload: bytes
    identification: int
    ttl: int
    udp_checksum_present: bool


class MindRoveNetworkState:
    """Small ARP cache and IPv4/UDP gate for one MindRove peer."""

    def __init__(
        self,
        local_mac: MACAddressInput,
        config: Optional[MindRoveStaticConfig] = None,
    ) -> None:
        self.local_mac = mac_bytes(local_mac)
        self.config = config if config is not None else MindRoveStaticConfig()
        self.peer_mac = None  # type: Optional[bytes]
        self._next_identification = 0

    def build_arp_request(self) -> bytes:
        return build_arp_request(
            self.local_mac, self.config.host_ip, self.config.peer_ip
        )

    def handle_arp(self, packet: bytes) -> Optional[bytes]:
        """Learn the peer's MAC and optionally return a reply for our host IP.

        Packets unrelated to the fixed peer/host pair are ignored.  A peer MAC
        is learned only from a structurally valid unicast sender address.
        """

        arp = parse_arp(packet)
        from_peer = arp.sender_protocol == self.config.peer_ip
        valid_sender = _is_unicast_mac(arp.sender_hardware)
        directed_to_host = arp.target_protocol == self.config.host_ip

        if from_peer and directed_to_host and valid_sender:
            if arp.operation == ARPOperation.REPLY:
                if arp.target_hardware != self.local_mac:
                    return None
                self.peer_mac = arp.sender_hardware
                return None
            if arp.operation == ARPOperation.REQUEST:
                self.peer_mac = arp.sender_hardware
                return build_arp_reply(
                    self.local_mac,
                    self.config.host_ip,
                    arp.sender_hardware,
                    arp.sender_protocol,
                )
        return None

    def build_udp(
        self,
        payload: bytes,
        *,
        source_port: int = MINDROVE_STREAM_PORT,
        destination_port: int = MINDROVE_STREAM_PORT,
        ttl: int = 64,
    ) -> bytes:
        """Build an IPv4/UDP datagram directed only to ``192.168.4.1``."""

        udp = build_udp(
            payload,
            source_port,
            destination_port,
            self.config.host_ip,
            self.config.peer_ip,
        )
        identification = self._next_identification
        self._next_identification = (identification + 1) & 0xFFFF
        return build_ipv4(
            udp,
            self.config.host_ip,
            self.config.peer_ip,
            IP_PROTOCOL_UDP,
            identification=identification,
            ttl=ttl,
        )

    def receive_ipv4(
        self, packet: bytes, *, allow_zero_udp_checksum: bool = True
    ) -> Optional[MindRoveDatagram]:
        """Validate and return only peer-originated UDP/4210 stream payloads."""

        ipv4 = parse_ipv4(packet)
        if ipv4.source != self.config.peer_ip:
            return None
        if not self.config.accepts_destination(ipv4.destination):
            return None
        if ipv4.protocol != IP_PROTOCOL_UDP:
            return None
        udp = parse_udp(
            ipv4.payload,
            ipv4.source,
            ipv4.destination,
            allow_zero_checksum=allow_zero_udp_checksum,
        )
        if udp.destination_port != self.config.stream_port:
            return None
        return MindRoveDatagram(
            source_ip=ipv4.source,
            destination_ip=ipv4.destination,
            source_port=udp.source_port,
            destination_port=udp.destination_port,
            payload=udp.payload,
            identification=ipv4.identification,
            ttl=ipv4.ttl,
            udp_checksum_present=udp.checksum_present,
        )


def _is_unicast_mac(address: bytes) -> bool:
    return address not in (ZERO_MAC, BROADCAST_MAC) and not bool(address[0] & 1)


__all__ = [
    "ARPOperation",
    "ARPPacket",
    "IP_PROTOCOL_UDP",
    "IPv4Packet",
    "LIMITED_BROADCAST",
    "MINDROVE_NETWORK",
    "MINDROVE_PEER_IP",
    "MINDROVE_STREAM_PORT",
    "MindRoveDatagram",
    "MindRoveNetworkState",
    "MindRoveStaticConfig",
    "UDPSegment",
    "build_arp_reply",
    "build_arp_request",
    "build_ipv4",
    "build_udp",
    "internet_checksum",
    "parse_arp",
    "parse_ipv4",
    "parse_ipv4_udp",
    "parse_udp",
]
