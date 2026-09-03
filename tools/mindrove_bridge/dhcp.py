# SPDX-License-Identifier: GPL-2.0-only
"""Narrow DHCPv4 client messages for the isolated MindRove network.

This is deliberately not a general DHCP stack. It accepts only direct
Ethernet/IPv4 replies for one transaction and one client MAC, and constrains
the resulting lease to the documented ``192.168.4.0/24`` device network.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from ipaddress import IPv4Address
import secrets
import struct
from typing import Dict, Optional

from mindrove_station.common import mac_bytes
from mindrove_station.network import MINDROVE_PEER_IP


BOOTP_FIXED_LENGTH = 236
DHCP_MINIMUM_LENGTH = 300
DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"
DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67

_OPTION_PAD = 0
_OPTION_SUBNET_MASK = 1
_OPTION_ROUTER = 3
_OPTION_REQUESTED_IP = 50
_OPTION_LEASE_TIME = 51
_OPTION_OVERLOAD = 52
_OPTION_MESSAGE_TYPE = 53
_OPTION_SERVER_IDENTIFIER = 54
_OPTION_PARAMETER_REQUEST = 55
_OPTION_MAXIMUM_MESSAGE_SIZE = 57
_OPTION_CLIENT_IDENTIFIER = 61
_OPTION_END = 255

_ZERO_IP = IPv4Address("0.0.0.0")
_EXPECTED_MASK = IPv4Address("255.255.255.0")
_STREAM_DESTINATION = IPv4Address("192.168.4.2")


class DHCPError(ValueError):
    """A DHCP packet is malformed or outside the MindRove profile."""


class DHCPMessageType(IntEnum):
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6


@dataclass(frozen=True)
class DHCPOffer:
    address: IPv4Address
    server: IPv4Address
    subnet_mask: Optional[IPv4Address]
    router: Optional[IPv4Address]
    lease_seconds: Optional[int]


@dataclass(frozen=True)
class DHCPLease:
    address: IPv4Address
    server: IPv4Address
    subnet_mask: IPv4Address
    router: IPv4Address
    lease_seconds: Optional[int]


@dataclass(frozen=True)
class _Reply:
    message_type: DHCPMessageType
    address: IPv4Address
    server: IPv4Address
    subnet_mask: Optional[IPv4Address]
    router: Optional[IPv4Address]
    lease_seconds: Optional[int]


def _option(code: int, value: bytes) -> bytes:
    if not value or len(value) > 255:
        raise ValueError("DHCP option value must contain 1 through 255 octets")
    return bytes((code, len(value))) + bytes(value)


def _request_packet(
    mac: bytes,
    transaction_id: int,
    message_type: DHCPMessageType,
    extra_options: bytes = b"",
) -> bytes:
    # BOOTREQUEST, Ethernet, hlen=6, no relay hops, broadcast flag.
    fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,
        1,
        6,
        0,
        transaction_id,
        0,
        0x8000,
        bytes(4),
        bytes(4),
        bytes(4),
        bytes(4),
        mac + bytes(10),
        bytes(64),
        bytes(128),
    )
    options = b"".join(
        (
            _option(_OPTION_MESSAGE_TYPE, bytes((int(message_type),))),
            _option(_OPTION_CLIENT_IDENTIFIER, b"\x01" + mac),
            extra_options,
            _option(
                _OPTION_PARAMETER_REQUEST,
                bytes(
                    (
                        _OPTION_SUBNET_MASK,
                        _OPTION_ROUTER,
                        _OPTION_LEASE_TIME,
                        _OPTION_SERVER_IDENTIFIER,
                    )
                ),
            ),
            _option(_OPTION_MAXIMUM_MESSAGE_SIZE, struct.pack("!H", 1500)),
            bytes((_OPTION_END,)),
        )
    )
    packet = fixed + DHCP_MAGIC_COOKIE + options
    return packet + bytes(max(0, DHCP_MINIMUM_LENGTH - len(packet)))


def _parse_options(data: bytes) -> Dict[int, bytes]:
    options: Dict[int, bytes] = {}
    offset = 0
    saw_end = False
    while offset < len(data):
        code = data[offset]
        offset += 1
        if code == _OPTION_PAD:
            continue
        if code == _OPTION_END:
            saw_end = True
            # Only standard PAD/END octets may follow END. Rejecting hidden
            # trailing TLVs avoids accepting two conflicting option streams.
            if any(octet not in (_OPTION_PAD, _OPTION_END) for octet in data[offset:]):
                raise DHCPError("DHCP options contain data after END")
            break
        if offset >= len(data):
            raise DHCPError("DHCP option is missing its length")
        length = data[offset]
        offset += 1
        if offset + length > len(data):
            raise DHCPError("DHCP option value is truncated")
        if code in options:
            raise DHCPError("duplicate DHCP option %d" % code)
        options[code] = bytes(data[offset : offset + length])
        offset += length
    if not saw_end:
        raise DHCPError("DHCP options have no END marker")
    if _OPTION_OVERLOAD in options:
        raise DHCPError("overloaded DHCP option areas are not supported")
    return options


def _single_ipv4_option(
    options: Dict[int, bytes], code: int, name: str
) -> Optional[IPv4Address]:
    value = options.get(code)
    if value is None:
        return None
    if len(value) != 4:
        raise DHCPError("DHCP %s option must contain one IPv4 address" % name)
    return IPv4Address(value)


def _parse_reply(
    payload: bytes,
    *,
    transaction_id: int,
    client_mac: bytes,
    source_ip: IPv4Address,
) -> _Reply:
    packet = bytes(payload)
    if len(packet) < BOOTP_FIXED_LENGTH + len(DHCP_MAGIC_COOKIE) + 1:
        raise DHCPError("DHCP reply is truncated")
    if packet[0:4] != b"\x02\x01\x06\x00":
        raise DHCPError("DHCP reply is not a direct Ethernet BOOTREPLY")
    if int.from_bytes(packet[4:8], "big") != transaction_id:
        raise DHCPError("DHCP transaction ID does not match")
    if packet[28:34] != client_mac:
        raise DHCPError("DHCP client hardware address does not match")
    if packet[34:44] != bytes(10):
        raise DHCPError("DHCP chaddr padding is nonzero")
    if packet[12:16] != bytes(4) or packet[24:28] != bytes(4):
        raise DHCPError("DHCP ciaddr/giaddr must be zero during acquisition")
    if packet[BOOTP_FIXED_LENGTH : BOOTP_FIXED_LENGTH + 4] != DHCP_MAGIC_COOKIE:
        raise DHCPError("DHCP magic cookie is invalid")
    options = _parse_options(packet[BOOTP_FIXED_LENGTH + 4 :])

    raw_type = options.get(_OPTION_MESSAGE_TYPE)
    if raw_type is None or len(raw_type) != 1:
        raise DHCPError("DHCP message-type option is missing or malformed")
    try:
        message_type = DHCPMessageType(raw_type[0])
    except ValueError as exc:
        raise DHCPError("DHCP message type is unknown") from exc
    if message_type not in (
        DHCPMessageType.OFFER,
        DHCPMessageType.ACK,
        DHCPMessageType.NAK,
    ):
        raise DHCPError("packet is not a DHCP server acquisition reply")

    if source_ip != MINDROVE_PEER_IP:
        raise DHCPError("DHCP IPv4 source is not the MindRove peer")
    server_option = _single_ipv4_option(
        options, _OPTION_SERVER_IDENTIFIER, "server identifier"
    )
    siaddr = IPv4Address(packet[20:24])
    for advertised in (server_option, None if siaddr == _ZERO_IP else siaddr):
        if advertised is not None and advertised != MINDROVE_PEER_IP:
            raise DHCPError("DHCP server identity is inconsistent with 192.168.4.1")
    server = server_option or (siaddr if siaddr != _ZERO_IP else source_ip)

    address = IPv4Address(packet[16:20])
    if message_type is DHCPMessageType.NAK:
        if address != _ZERO_IP:
            raise DHCPError("DHCPNAK yiaddr must be zero")
    elif address != _STREAM_DESTINATION:
        raise DHCPError(
            "MindRove stream firmware requires DHCP address 192.168.4.2"
        )

    subnet_mask = _single_ipv4_option(options, _OPTION_SUBNET_MASK, "subnet mask")
    if subnet_mask is not None and subnet_mask != _EXPECTED_MASK:
        raise DHCPError("MindRove DHCP subnet mask is not /24")
    router_value = options.get(_OPTION_ROUTER)
    router = None
    if router_value is not None:
        if len(router_value) != 4:
            raise DHCPError("MindRove DHCP must advertise exactly one router")
        router = IPv4Address(router_value)
        if router != MINDROVE_PEER_IP:
            raise DHCPError("MindRove DHCP router is not 192.168.4.1")
    lease_value = options.get(_OPTION_LEASE_TIME)
    lease_seconds = None
    if lease_value is not None:
        if len(lease_value) != 4:
            raise DHCPError("DHCP lease-time option must be four octets")
        lease_seconds = int.from_bytes(lease_value, "big")
        if lease_seconds == 0:
            raise DHCPError("DHCP lease time must be positive")
    return _Reply(
        message_type,
        address,
        server,
        subnet_mask,
        router,
        lease_seconds,
    )


class MindRoveDHCPClient:
    """One INIT→SELECTING→REQUESTING transaction with a fixed identity."""

    def __init__(self, client_mac: bytes, *, transaction_id: Optional[int] = None) -> None:
        self.client_mac = mac_bytes(client_mac)
        if self.client_mac[0] & 1:
            raise ValueError("DHCP client MAC must be an individual address")
        xid = secrets.randbits(32) if transaction_id is None else transaction_id
        if not isinstance(xid, int) or isinstance(xid, bool) or not 0 <= xid <= 0xFFFFFFFF:
            raise ValueError("DHCP transaction ID must fit in 32 bits")
        self.transaction_id = xid

    def discover(self) -> bytes:
        # The acquisition firmware sends to this literal address rather than
        # the current DHCP lease. Request it explicitly and reject any other
        # offer, otherwise association appears healthy but samples disappear.
        return _request_packet(
            self.client_mac,
            self.transaction_id,
            DHCPMessageType.DISCOVER,
            _option(_OPTION_REQUESTED_IP, _STREAM_DESTINATION.packed),
        )

    def parse_offer(self, payload: bytes, *, source_ip: IPv4Address) -> DHCPOffer:
        reply = _parse_reply(
            payload,
            transaction_id=self.transaction_id,
            client_mac=self.client_mac,
            source_ip=source_ip,
        )
        if reply.message_type is not DHCPMessageType.OFFER:
            raise DHCPError("expected DHCPOFFER")
        return DHCPOffer(
            reply.address,
            reply.server,
            reply.subnet_mask,
            reply.router,
            reply.lease_seconds,
        )

    def request(self, offer: DHCPOffer) -> bytes:
        if offer.server != MINDROVE_PEER_IP:
            raise ValueError("DHCP offer is not from the MindRove peer")
        extra = _option(_OPTION_REQUESTED_IP, offer.address.packed) + _option(
            _OPTION_SERVER_IDENTIFIER, offer.server.packed
        )
        return _request_packet(
            self.client_mac,
            self.transaction_id,
            DHCPMessageType.REQUEST,
            extra,
        )

    def parse_ack(
        self,
        payload: bytes,
        offer: DHCPOffer,
        *,
        source_ip: IPv4Address,
    ) -> DHCPLease:
        reply = _parse_reply(
            payload,
            transaction_id=self.transaction_id,
            client_mac=self.client_mac,
            source_ip=source_ip,
        )
        if reply.message_type is DHCPMessageType.NAK:
            raise DHCPError("MindRove DHCP server rejected the requested lease")
        if reply.message_type is not DHCPMessageType.ACK:
            raise DHCPError("expected DHCPACK")
        if reply.address != offer.address or reply.server != offer.server:
            raise DHCPError("DHCPACK does not match the selected DHCPOFFER")
        if (
            reply.subnet_mask is not None
            and offer.subnet_mask is not None
            and reply.subnet_mask != offer.subnet_mask
        ):
            raise DHCPError("DHCPACK changed the offered subnet mask")
        if (
            reply.router is not None
            and offer.router is not None
            and reply.router != offer.router
        ):
            raise DHCPError("DHCPACK changed the offered router")
        return DHCPLease(
            reply.address,
            reply.server,
            reply.subnet_mask or offer.subnet_mask or _EXPECTED_MASK,
            reply.router or offer.router or MINDROVE_PEER_IP,
            reply.lease_seconds
            if reply.lease_seconds is not None
            else offer.lease_seconds,
        )


__all__ = [
    "DHCP_CLIENT_PORT",
    "DHCP_SERVER_PORT",
    "DHCPError",
    "DHCPLease",
    "DHCPMessageType",
    "DHCPOffer",
    "MindRoveDHCPClient",
]
