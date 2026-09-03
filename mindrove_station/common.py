# SPDX-License-Identifier: GPL-2.0-only
"""Common IEEE 802.11 MAC primitives.

The bit positions follow the IEEE 802.11 MAC frame-control field.  This module
is intentionally independent of radiotap, USB descriptors, and a particular
radio implementation.
"""

from dataclasses import dataclass
import re
import struct
from typing import Union

from .errors import FrameFormatError


MACAddressInput = Union[str, bytes, bytearray, memoryview]

MANAGEMENT_FRAME_TYPE = 0
CONTROL_FRAME_TYPE = 1
DATA_FRAME_TYPE = 2

_MAC_PATTERN = re.compile(
    r"^[0-9a-fA-F]{2}(?P<sep>[:-])[0-9a-fA-F]{2}(?:(?P=sep)[0-9a-fA-F]{2}){4}$"
)


def mac_bytes(value: MACAddressInput) -> bytes:
    """Return a six-byte MAC address, rejecting ambiguous representations."""

    if isinstance(value, str):
        if not _MAC_PATTERN.fullmatch(value):
            raise ValueError(
                "MAC address must contain six colon- or hyphen-separated octets"
            )
        return bytes.fromhex(value.replace(":", "").replace("-", ""))

    result = bytes(value)
    if len(result) != 6:
        raise ValueError("MAC address must be exactly 6 bytes")
    return result


def format_mac(value: MACAddressInput) -> str:
    """Format a MAC address in lower-case, colon-separated notation."""

    return ":".join("%02x" % octet for octet in mac_bytes(value))


@dataclass(frozen=True)
class FrameControl:
    """Decoded 16-bit IEEE 802.11 frame-control field."""

    value: int

    def __post_init__(self) -> None:
        if not 0 <= self.value <= 0xFFFF:
            raise ValueError("frame-control value must fit in 16 bits")

    @property
    def protocol_version(self) -> int:
        return self.value & 0x3

    @property
    def frame_type(self) -> int:
        return (self.value >> 2) & 0x3

    @property
    def subtype(self) -> int:
        return (self.value >> 4) & 0xF

    @property
    def to_ds(self) -> bool:
        return bool(self.value & (1 << 8))

    @property
    def from_ds(self) -> bool:
        return bool(self.value & (1 << 9))

    @property
    def more_fragments(self) -> bool:
        return bool(self.value & (1 << 10))

    @property
    def retry(self) -> bool:
        return bool(self.value & (1 << 11))

    @property
    def power_management(self) -> bool:
        return bool(self.value & (1 << 12))

    @property
    def more_data(self) -> bool:
        return bool(self.value & (1 << 13))

    @property
    def protected(self) -> bool:
        return bool(self.value & (1 << 14))

    @property
    def order(self) -> bool:
        return bool(self.value & (1 << 15))

    def encode(self) -> bytes:
        return struct.pack("<H", self.value)

    @classmethod
    def build(
        cls,
        frame_type: int,
        subtype: int,
        *,
        to_ds: bool = False,
        from_ds: bool = False,
        more_fragments: bool = False,
        retry: bool = False,
        power_management: bool = False,
        more_data: bool = False,
        protected: bool = False,
        order: bool = False,
    ) -> "FrameControl":
        if not 0 <= frame_type <= 3:
            raise ValueError("frame type must fit in 2 bits")
        if not 0 <= subtype <= 15:
            raise ValueError("frame subtype must fit in 4 bits")
        value = (frame_type << 2) | (subtype << 4)
        value |= int(to_ds) << 8
        value |= int(from_ds) << 9
        value |= int(more_fragments) << 10
        value |= int(retry) << 11
        value |= int(power_management) << 12
        value |= int(more_data) << 13
        value |= int(protected) << 14
        value |= int(order) << 15
        return cls(value)

    @classmethod
    def decode(cls, data: bytes) -> "FrameControl":
        if len(data) < 2:
            raise FrameFormatError("frame is missing its frame-control field")
        frame_control = cls(struct.unpack_from("<H", data)[0])
        if frame_control.protocol_version != 0:
            raise FrameFormatError("unsupported IEEE 802.11 protocol version")
        return frame_control


def encode_sequence_control(sequence_number: int, fragment_number: int = 0) -> bytes:
    """Encode a 12-bit sequence number and 4-bit fragment number."""

    if not 0 <= sequence_number <= 0xFFF:
        raise ValueError("sequence number must fit in 12 bits")
    if not 0 <= fragment_number <= 0xF:
        raise ValueError("fragment number must fit in 4 bits")
    return struct.pack("<H", (sequence_number << 4) | fragment_number)


def decode_sequence_control(value: int) -> tuple:
    """Return ``(sequence_number, fragment_number)`` from a 16-bit field."""

    return value >> 4, value & 0xF
