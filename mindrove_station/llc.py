# SPDX-License-Identifier: GPL-2.0-only
"""RFC 1042 LLC/SNAP encapsulation used by IEEE 802.11 data frames."""

from dataclasses import dataclass
from enum import IntEnum
import struct
from typing import Union

from .errors import FrameFormatError


RFC1042_OUI = b"\x00\x00\x00"
LLC_SNAP_PREFIX = b"\xaa\xaa\x03"


class EtherType(IntEnum):
    IPV4 = 0x0800
    ARP = 0x0806
    EAPOL = 0x888E


@dataclass(frozen=True)
class LLCFrame:
    oui: bytes
    ethertype: int
    payload: bytes


def encapsulate(
    payload: bytes, ethertype: Union[int, EtherType], oui: bytes = RFC1042_OUI
) -> bytes:
    """Wrap a network-layer packet in an LLC/SNAP header."""

    ethertype_value = int(ethertype)
    if not 0 <= ethertype_value <= 0xFFFF:
        raise ValueError("EtherType must fit in 16 bits")
    oui_value = bytes(oui)
    if len(oui_value) != 3:
        raise ValueError("SNAP OUI must be exactly 3 bytes")
    return (
        LLC_SNAP_PREFIX
        + oui_value
        + struct.pack("!H", ethertype_value)
        + bytes(payload)
    )


def encapsulate_ipv4(packet: bytes) -> bytes:
    return encapsulate(packet, EtherType.IPV4)


def encapsulate_arp(packet: bytes) -> bytes:
    return encapsulate(packet, EtherType.ARP)


def decapsulate(frame_body: bytes, *, require_rfc1042_oui: bool = True) -> LLCFrame:
    """Decode one LLC/SNAP protocol data unit.

    Only the eight-byte unnumbered-information SNAP form is accepted.  The
    caller retains responsibility for interpreting the network-layer packet.
    """

    if len(frame_body) < 8:
        raise FrameFormatError("LLC/SNAP frame is shorter than 8 bytes")
    if frame_body[:3] != LLC_SNAP_PREFIX:
        raise FrameFormatError("unsupported LLC header (expected AA:AA:03)")
    oui = bytes(frame_body[3:6])
    if require_rfc1042_oui and oui != RFC1042_OUI:
        raise FrameFormatError("unsupported SNAP OUI %s" % oui.hex(":"))
    ethertype = struct.unpack_from("!H", frame_body, 6)[0]
    return LLCFrame(oui=oui, ethertype=ethertype, payload=bytes(frame_body[8:]))
