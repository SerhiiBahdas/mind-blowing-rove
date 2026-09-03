# SPDX-License-Identifier: GPL-2.0-only
"""IEEE 802.11 information-element encoding and strict parsing."""

from dataclasses import dataclass
from enum import IntEnum
from typing import Iterable, Iterator, Optional, Sequence, Union

from .errors import FrameFormatError


class ElementID(IntEnum):
    SSID = 0
    SUPPORTED_RATES = 1
    RSN = 48
    EXTENDED_SUPPORTED_RATES = 50
    VENDOR_SPECIFIC = 221
    RSNX = 244


@dataclass(frozen=True)
class InformationElement:
    """A single one-byte-ID, one-byte-length information element."""

    element_id: int
    data: bytes

    def __post_init__(self) -> None:
        if not 0 <= int(self.element_id) <= 0xFF:
            raise ValueError("information-element ID must fit in one byte")
        normalized = bytes(self.data)
        if len(normalized) > 0xFF:
            raise ValueError("information-element body cannot exceed 255 bytes")
        object.__setattr__(self, "element_id", int(self.element_id))
        object.__setattr__(self, "data", normalized)

    def encode(self) -> bytes:
        return bytes((self.element_id, len(self.data))) + self.data


def parse_information_elements(data: bytes) -> tuple:
    """Parse an IE byte string.

    Truncated element headers and bodies are rejected instead of silently
    accepting a partial security or association configuration.
    """

    elements = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 2:
            raise FrameFormatError(
                "truncated information-element header at offset %d" % offset
            )
        element_id = data[offset]
        length = data[offset + 1]
        offset += 2
        end = offset + length
        if end > len(data):
            raise FrameFormatError(
                "information element %d declares %d bytes but only %d remain"
                % (element_id, length, len(data) - offset)
            )
        elements.append(InformationElement(element_id, data[offset:end]))
        offset = end
    return tuple(elements)


def encode_information_elements(elements: Iterable[InformationElement]) -> bytes:
    return b"".join(element.encode() for element in elements)


def first_element(
    elements: Sequence[InformationElement], element_id: Union[int, ElementID]
) -> Optional[InformationElement]:
    wanted = int(element_id)
    return next((element for element in elements if element.element_id == wanted), None)


def iter_elements(
    elements: Sequence[InformationElement], element_id: Union[int, ElementID]
) -> Iterator[InformationElement]:
    wanted = int(element_id)
    return (element for element in elements if element.element_id == wanted)


def ssid_element(ssid: Union[str, bytes]) -> InformationElement:
    value = ssid.encode("utf-8") if isinstance(ssid, str) else bytes(ssid)
    if len(value) > 32:
        raise ValueError("SSID cannot exceed 32 octets")
    return InformationElement(ElementID.SSID, value)


def rate_elements(encoded_rates: Sequence[int]) -> tuple:
    """Build Supported Rates and, when needed, Extended Supported Rates IEs.

    Each input is the on-wire 500-kbit/s rate octet; bit 7 is therefore
    preserved as the basic-rate marker.
    """

    if not encoded_rates:
        raise ValueError("at least one supported rate is required")
    rates = bytes(encoded_rates)
    result = [InformationElement(ElementID.SUPPORTED_RATES, rates[:8])]
    if len(rates) > 8:
        result.append(InformationElement(ElementID.EXTENDED_SUPPORTED_RATES, rates[8:]))
    return tuple(result)
