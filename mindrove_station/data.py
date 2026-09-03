# SPDX-License-Identifier: GPL-2.0-only
"""IEEE 802.11 data headers and LLC/SNAP network-packet carriage.

The builders produce MPDUs without radiotap metadata, hardware encryption
headers, or a trailing FCS.  Those are transport/crypto responsibilities.  The
parser supports the three-address station/AP cases, four-address WDS frames,
and the optional QoS/HT-control header lengths needed to locate the payload.
"""

from dataclasses import dataclass
import struct
from typing import Optional, Union

from .common import (
    DATA_FRAME_TYPE,
    FrameControl,
    MACAddressInput,
    decode_sequence_control,
    encode_sequence_control,
    mac_bytes,
)
from .errors import FrameFormatError
from .llc import EtherType, LLCFrame, decapsulate, encapsulate


DATA_SUBTYPE = 0
QOS_DATA_SUBTYPE = 8
BASE_DATA_HEADER_LENGTH = 24


@dataclass(frozen=True)
class DataFrame:
    frame_control: FrameControl
    duration: int
    address1: bytes
    address2: bytes
    address3: bytes
    address4: Optional[bytes]
    sequence_number: int
    fragment_number: int
    qos_control: Optional[int]
    ht_control: Optional[int]
    body: bytes
    llc: Optional[LLCFrame]

    @property
    def receiver(self) -> bytes:
        return self.address1

    @property
    def transmitter(self) -> bytes:
        return self.address2

    @property
    def source(self) -> bytes:
        if self.frame_control.to_ds and self.frame_control.from_ds:
            if self.address4 is None:
                raise FrameFormatError("four-address data frame has no source address")
            return self.address4
        if self.frame_control.from_ds:
            return self.address3
        return self.address2

    @property
    def destination(self) -> bytes:
        if self.frame_control.to_ds:
            return self.address3
        return self.address1

    @property
    def bssid(self) -> Optional[bytes]:
        if self.frame_control.to_ds and self.frame_control.from_ds:
            return None
        if self.frame_control.to_ds:
            return self.address1
        if self.frame_control.from_ds:
            return self.address2
        return self.address3

    @property
    def qos_tid(self) -> Optional[int]:
        return None if self.qos_control is None else self.qos_control & 0xF

    @property
    def a_msdu_present(self) -> bool:
        return self.qos_control is not None and bool(self.qos_control & (1 << 7))


def _encode_data_header(
    frame_control: FrameControl,
    duration: int,
    address1: MACAddressInput,
    address2: MACAddressInput,
    address3: MACAddressInput,
    sequence_number: int,
    fragment_number: int,
    *,
    address4: Optional[MACAddressInput] = None,
    qos_control: Optional[int] = None,
    ht_control: Optional[int] = None,
) -> bytes:
    if frame_control.frame_type != DATA_FRAME_TYPE:
        raise ValueError("data header requires a data frame-control type")
    if not 0 <= duration <= 0xFFFF:
        raise ValueError("duration must fit in 16 bits")
    has_address4 = frame_control.to_ds and frame_control.from_ds
    if has_address4 != (address4 is not None):
        raise ValueError(
            "address4 is required exactly when To DS and From DS are both set"
        )
    is_qos = bool(frame_control.subtype & 0x8)
    if is_qos != (qos_control is not None):
        raise ValueError("QoS control is required exactly for QoS data subtypes")
    if qos_control is not None and not 0 <= qos_control <= 0xFFFF:
        raise ValueError("QoS control must fit in 16 bits")
    has_ht_control = is_qos and frame_control.order
    if has_ht_control != (ht_control is not None):
        raise ValueError("HT control is required exactly for ordered QoS data frames")
    if ht_control is not None and not 0 <= ht_control <= 0xFFFFFFFF:
        raise ValueError("HT control must fit in 32 bits")

    result = bytearray(frame_control.encode())
    result.extend(struct.pack("<H", duration))
    result.extend(mac_bytes(address1))
    result.extend(mac_bytes(address2))
    result.extend(mac_bytes(address3))
    result.extend(encode_sequence_control(sequence_number, fragment_number))
    if address4 is not None:
        result.extend(mac_bytes(address4))
    if qos_control is not None:
        result.extend(struct.pack("<H", qos_control))
    if ht_control is not None:
        result.extend(struct.pack("<I", ht_control))
    return bytes(result)


def build_station_data(
    station: MACAddressInput,
    bssid: MACAddressInput,
    destination: MACAddressInput,
    network_payload: bytes,
    ethertype: Union[int, EtherType],
    *,
    sequence_number: int,
    fragment_number: int = 0,
    duration: int = 0,
    qos_tid: Optional[int] = None,
    retry: bool = False,
    more_fragments: bool = False,
    power_management: bool = False,
) -> bytes:
    """Build an unencrypted station-to-DS data MPDU.

    For a protected network, pass the resulting LLC/SNAP bytes through the
    negotiated CCMP/GCMP layer and use ``build_raw_data`` to set Protected.
    Setting the bit on plaintext here would create a malformed frame, so this
    convenience builder intentionally has no ``protected`` switch.
    """

    if qos_tid is not None and not 0 <= qos_tid <= 15:
        raise ValueError("QoS TID must fit in 4 bits")
    subtype = QOS_DATA_SUBTYPE if qos_tid is not None else DATA_SUBTYPE
    frame_control = FrameControl.build(
        DATA_FRAME_TYPE,
        subtype,
        to_ds=True,
        retry=retry,
        more_fragments=more_fragments,
        power_management=power_management,
    )
    header = _encode_data_header(
        frame_control,
        duration,
        address1=bssid,
        address2=station,
        address3=destination,
        sequence_number=sequence_number,
        fragment_number=fragment_number,
        qos_control=qos_tid,
    )
    return header + encapsulate(network_payload, ethertype)


def build_ap_data(
    access_point: MACAddressInput,
    station: MACAddressInput,
    source: MACAddressInput,
    network_payload: bytes,
    ethertype: Union[int, EtherType],
    *,
    sequence_number: int,
    fragment_number: int = 0,
    duration: int = 0,
    qos_tid: Optional[int] = None,
    retry: bool = False,
    more_fragments: bool = False,
) -> bytes:
    """Build an unencrypted AP-to-station data MPDU, useful for fixtures."""

    if qos_tid is not None and not 0 <= qos_tid <= 15:
        raise ValueError("QoS TID must fit in 4 bits")
    subtype = QOS_DATA_SUBTYPE if qos_tid is not None else DATA_SUBTYPE
    frame_control = FrameControl.build(
        DATA_FRAME_TYPE,
        subtype,
        from_ds=True,
        retry=retry,
        more_fragments=more_fragments,
    )
    header = _encode_data_header(
        frame_control,
        duration,
        address1=station,
        address2=access_point,
        address3=source,
        sequence_number=sequence_number,
        fragment_number=fragment_number,
        qos_control=qos_tid,
    )
    return header + encapsulate(network_payload, ethertype)


def build_raw_data(
    *,
    frame_control: FrameControl,
    duration: int,
    address1: MACAddressInput,
    address2: MACAddressInput,
    address3: MACAddressInput,
    sequence_number: int,
    body: bytes,
    fragment_number: int = 0,
    address4: Optional[MACAddressInput] = None,
    qos_control: Optional[int] = None,
    ht_control: Optional[int] = None,
) -> bytes:
    """Build a data MPDU around an already prepared plaintext/ciphertext body."""

    return _encode_data_header(
        frame_control,
        duration,
        address1,
        address2,
        address3,
        sequence_number,
        fragment_number,
        address4=address4,
        qos_control=qos_control,
        ht_control=ht_control,
    ) + bytes(body)


def parse_data(frame: bytes, *, decode_llc: bool = True) -> DataFrame:
    """Parse a data MPDU that does not include radiotap or FCS bytes."""

    if len(frame) < BASE_DATA_HEADER_LENGTH:
        raise FrameFormatError("data frame is shorter than 24 bytes")
    frame_control = FrameControl.decode(frame[:2])
    if frame_control.frame_type != DATA_FRAME_TYPE:
        raise FrameFormatError("frame is not an IEEE 802.11 data frame")
    duration = struct.unpack_from("<H", frame, 2)[0]
    address1 = bytes(frame[4:10])
    address2 = bytes(frame[10:16])
    address3 = bytes(frame[16:22])
    sequence_control = struct.unpack_from("<H", frame, 22)[0]
    sequence_number, fragment_number = decode_sequence_control(sequence_control)
    offset = BASE_DATA_HEADER_LENGTH

    address4 = None
    if frame_control.to_ds and frame_control.from_ds:
        if len(frame) < offset + 6:
            raise FrameFormatError("four-address data frame is missing address4")
        address4 = bytes(frame[offset : offset + 6])
        offset += 6

    qos_control = None
    if frame_control.subtype & 0x8:
        if len(frame) < offset + 2:
            raise FrameFormatError("QoS data frame is missing QoS control")
        qos_control = struct.unpack_from("<H", frame, offset)[0]
        offset += 2

    ht_control = None
    if qos_control is not None and frame_control.order:
        if len(frame) < offset + 4:
            raise FrameFormatError("ordered QoS data frame is missing HT control")
        ht_control = struct.unpack_from("<I", frame, offset)[0]
        offset += 4

    body = bytes(frame[offset:])
    null_data_subtype = bool(frame_control.subtype & 0x4)
    a_msdu = qos_control is not None and bool(qos_control & (1 << 7))
    llc = None
    if (
        decode_llc
        and body
        and not frame_control.protected
        and not null_data_subtype
        and not a_msdu
        and fragment_number == 0
    ):
        llc = decapsulate(body)

    return DataFrame(
        frame_control=frame_control,
        duration=duration,
        address1=address1,
        address2=address2,
        address3=address3,
        address4=address4,
        sequence_number=sequence_number,
        fragment_number=fragment_number,
        qos_control=qos_control,
        ht_control=ht_control,
        body=body,
        llc=llc,
    )
