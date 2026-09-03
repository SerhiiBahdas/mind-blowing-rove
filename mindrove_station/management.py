# SPDX-License-Identifier: GPL-2.0-only
"""Build and parse the management frames needed by a narrow Wi-Fi station.

This module covers the MAC portions of Open System authentication and
association.  WPA key establishment (EAPOL) deliberately lives outside this
layer; a WPA2-Personal station still starts with Open System authentication.
Frames are returned without radiotap metadata or a trailing FCS because those
details belong to the radio transport.
"""

from dataclasses import dataclass
from enum import IntEnum, IntFlag
import struct
from typing import Iterable, Optional, Sequence, Union

from .common import (
    MANAGEMENT_FRAME_TYPE,
    FrameControl,
    MACAddressInput,
    decode_sequence_control,
    encode_sequence_control,
    mac_bytes,
)
from .errors import FrameFormatError
from .ie import (
    ElementID,
    InformationElement,
    encode_information_elements,
    first_element,
    parse_information_elements,
    rate_elements,
    ssid_element,
)


MANAGEMENT_HEADER_LENGTH = 24
BROADCAST = b"\xff" * 6


class ManagementSubtype(IntEnum):
    ASSOCIATION_REQUEST = 0
    ASSOCIATION_RESPONSE = 1
    REASSOCIATION_REQUEST = 2
    REASSOCIATION_RESPONSE = 3
    PROBE_REQUEST = 4
    PROBE_RESPONSE = 5
    BEACON = 8
    DISASSOCIATION = 10
    AUTHENTICATION = 11
    DEAUTHENTICATION = 12
    ACTION = 13


class AuthenticationAlgorithm(IntEnum):
    OPEN_SYSTEM = 0
    SHARED_KEY = 1
    FAST_BSS_TRANSITION = 2
    SAE = 3


class Capability(IntFlag):
    ESS = 1 << 0
    IBSS = 1 << 1
    CF_POLLABLE = 1 << 2
    CF_POLL_REQUEST = 1 << 3
    PRIVACY = 1 << 4
    SHORT_PREAMBLE = 1 << 5
    SPECTRUM_MANAGEMENT = 1 << 8
    QOS = 1 << 9
    SHORT_SLOT_TIME = 1 << 10
    APSD = 1 << 11
    RADIO_MEASUREMENT = 1 << 12
    DSSS_OFDM = 1 << 13
    DELAYED_BLOCK_ACK = 1 << 14
    IMMEDIATE_BLOCK_ACK = 1 << 15


@dataclass(frozen=True)
class ManagementHeader:
    frame_control: FrameControl
    duration: int
    receiver: bytes
    transmitter: bytes
    bssid: bytes
    sequence_number: int
    fragment_number: int = 0

    def __post_init__(self) -> None:
        if self.frame_control.frame_type != MANAGEMENT_FRAME_TYPE:
            raise ValueError(
                "management header requires a management frame-control type"
            )
        if not 0 <= self.duration <= 0xFFFF:
            raise ValueError("duration must fit in 16 bits")
        object.__setattr__(self, "receiver", mac_bytes(self.receiver))
        object.__setattr__(self, "transmitter", mac_bytes(self.transmitter))
        object.__setattr__(self, "bssid", mac_bytes(self.bssid))
        encode_sequence_control(self.sequence_number, self.fragment_number)

    def encode(self) -> bytes:
        return b"".join(
            (
                self.frame_control.encode(),
                struct.pack("<H", self.duration),
                self.receiver,
                self.transmitter,
                self.bssid,
                encode_sequence_control(self.sequence_number, self.fragment_number),
            )
        )


@dataclass(frozen=True)
class AuthenticationFrame:
    header: ManagementHeader
    algorithm: int
    transaction: int
    status_code: int
    payload: bytes

    @property
    def successful(self) -> bool:
        return self.status_code == 0


@dataclass(frozen=True)
class AssociationRequest:
    header: ManagementHeader
    capability_info: int
    listen_interval: int
    elements: tuple

    @property
    def ssid(self) -> Optional[bytes]:
        element = first_element(self.elements, ElementID.SSID)
        return None if element is None else element.data

    @property
    def supported_rates(self) -> bytes:
        rates = first_element(self.elements, ElementID.SUPPORTED_RATES)
        extended = first_element(self.elements, ElementID.EXTENDED_SUPPORTED_RATES)
        return (b"" if rates is None else rates.data) + (
            b"" if extended is None else extended.data
        )


@dataclass(frozen=True)
class AssociationResponse:
    header: ManagementHeader
    capability_info: int
    status_code: int
    association_id_raw: int
    elements: tuple

    @property
    def successful(self) -> bool:
        return self.status_code == 0

    @property
    def association_id(self) -> int:
        # Bits 14 and 15 are set in the on-wire AID field and are not part of
        # the station identifier.
        return self.association_id_raw & 0x3FFF

    @property
    def supported_rates(self) -> bytes:
        rates = first_element(self.elements, ElementID.SUPPORTED_RATES)
        extended = first_element(self.elements, ElementID.EXTENDED_SUPPORTED_RATES)
        return (b"" if rates is None else rates.data) + (
            b"" if extended is None else extended.data
        )


def _build_header(
    subtype: Union[int, ManagementSubtype],
    receiver: MACAddressInput,
    transmitter: MACAddressInput,
    bssid: MACAddressInput,
    sequence_number: int,
    *,
    duration: int = 0,
    retry: bool = False,
    protected: bool = False,
) -> ManagementHeader:
    return ManagementHeader(
        frame_control=FrameControl.build(
            MANAGEMENT_FRAME_TYPE,
            int(subtype),
            retry=retry,
            protected=protected,
        ),
        duration=duration,
        receiver=mac_bytes(receiver),
        transmitter=mac_bytes(transmitter),
        bssid=mac_bytes(bssid),
        sequence_number=sequence_number,
    )


def parse_management_header(
    frame: bytes, expected_subtype: Optional[int] = None
) -> ManagementHeader:
    if len(frame) < MANAGEMENT_HEADER_LENGTH:
        raise FrameFormatError("management frame is shorter than 24 bytes")
    frame_control = FrameControl.decode(frame[:2])
    if frame_control.frame_type != MANAGEMENT_FRAME_TYPE:
        raise FrameFormatError("frame is not an IEEE 802.11 management frame")
    if frame_control.to_ds or frame_control.from_ds:
        raise FrameFormatError("management frame unexpectedly has To DS or From DS set")
    if expected_subtype is not None and frame_control.subtype != int(expected_subtype):
        raise FrameFormatError(
            "unexpected management subtype %d (wanted %d)"
            % (frame_control.subtype, int(expected_subtype))
        )
    duration, sequence_control = struct.unpack_from("<H18xH", frame, 2)
    sequence_number, fragment_number = decode_sequence_control(sequence_control)
    return ManagementHeader(
        frame_control=frame_control,
        duration=duration,
        receiver=frame[4:10],
        transmitter=frame[10:16],
        bssid=frame[16:22],
        sequence_number=sequence_number,
        fragment_number=fragment_number,
    )


def build_authentication(
    station: MACAddressInput,
    bssid: MACAddressInput,
    *,
    algorithm: Union[
        int, AuthenticationAlgorithm
    ] = AuthenticationAlgorithm.OPEN_SYSTEM,
    transaction: int = 1,
    status_code: int = 0,
    sequence_number: int = 0,
    payload: bytes = b"",
) -> bytes:
    """Build an authentication management frame from station to AP."""

    for name, value in (
        ("algorithm", int(algorithm)),
        ("transaction", transaction),
        ("status", status_code),
    ):
        if not 0 <= value <= 0xFFFF:
            raise ValueError("%s must fit in 16 bits" % name)
    header = _build_header(
        ManagementSubtype.AUTHENTICATION,
        receiver=bssid,
        transmitter=station,
        bssid=bssid,
        sequence_number=sequence_number,
    )
    return (
        header.encode()
        + struct.pack("<HHH", int(algorithm), transaction, status_code)
        + bytes(payload)
    )


def parse_authentication(frame: bytes) -> AuthenticationFrame:
    header = parse_management_header(frame, ManagementSubtype.AUTHENTICATION)
    if header.frame_control.protected:
        raise FrameFormatError("cannot parse an encrypted authentication body")
    if len(frame) < MANAGEMENT_HEADER_LENGTH + 6:
        raise FrameFormatError("authentication frame is missing fixed fields")
    algorithm, transaction, status_code = struct.unpack_from(
        "<HHH", frame, MANAGEMENT_HEADER_LENGTH
    )
    return AuthenticationFrame(
        header=header,
        algorithm=algorithm,
        transaction=transaction,
        status_code=status_code,
        payload=bytes(frame[MANAGEMENT_HEADER_LENGTH + 6 :]),
    )


def _association_elements(
    ssid: Union[str, bytes],
    supported_rates: Sequence[int],
    extra_elements: Iterable[InformationElement],
) -> tuple:
    extra = tuple(extra_elements)
    reserved = {
        int(ElementID.SSID),
        int(ElementID.SUPPORTED_RATES),
        int(ElementID.EXTENDED_SUPPORTED_RATES),
    }
    if any(element.element_id in reserved for element in extra):
        raise ValueError(
            "SSID and rate elements must be supplied through their dedicated arguments"
        )
    return (ssid_element(ssid),) + rate_elements(supported_rates) + extra


def _contains_security_element(elements: Sequence[InformationElement]) -> bool:
    for element in elements:
        if element.element_id == int(ElementID.RSN):
            return True
        if element.element_id == int(
            ElementID.VENDOR_SPECIFIC
        ) and element.data.startswith(b"\x00\x50\xf2\x01"):
            return True
    return False


def build_association_request(
    station: MACAddressInput,
    bssid: MACAddressInput,
    ssid: Union[str, bytes],
    supported_rates: Sequence[int],
    *,
    capability_info: Union[int, Capability] = Capability.ESS,
    listen_interval: int = 10,
    sequence_number: int = 0,
    extra_elements: Iterable[InformationElement] = (),
) -> bytes:
    """Build a station-to-AP association request.

    If an RSN or WPA IE is included, the Privacy capability is set
    automatically.  Radio-specific HT/VHT/HE and WMM elements may be supplied
    through ``extra_elements`` after copying the AP's advertised constraints.
    """

    if not 0 <= int(capability_info) <= 0xFFFF:
        raise ValueError("capability information must fit in 16 bits")
    if not 1 <= listen_interval <= 0xFFFF:
        raise ValueError("listen interval must be between 1 and 65535 beacon intervals")
    elements = _association_elements(ssid, supported_rates, extra_elements)
    capabilities = int(capability_info)
    if _contains_security_element(elements):
        capabilities |= int(Capability.PRIVACY)
    header = _build_header(
        ManagementSubtype.ASSOCIATION_REQUEST,
        receiver=bssid,
        transmitter=station,
        bssid=bssid,
        sequence_number=sequence_number,
    )
    return (
        header.encode()
        + struct.pack("<HH", capabilities, listen_interval)
        + encode_information_elements(elements)
    )


def parse_association_request(frame: bytes) -> AssociationRequest:
    header = parse_management_header(frame, ManagementSubtype.ASSOCIATION_REQUEST)
    if header.frame_control.protected:
        raise FrameFormatError("cannot parse an encrypted association-request body")
    if len(frame) < MANAGEMENT_HEADER_LENGTH + 4:
        raise FrameFormatError("association request is missing fixed fields")
    capability_info, listen_interval = struct.unpack_from(
        "<HH", frame, MANAGEMENT_HEADER_LENGTH
    )
    elements = parse_information_elements(frame[MANAGEMENT_HEADER_LENGTH + 4 :])
    if first_element(elements, ElementID.SSID) is None:
        raise FrameFormatError("association request has no SSID element")
    if first_element(elements, ElementID.SUPPORTED_RATES) is None:
        raise FrameFormatError("association request has no Supported Rates element")
    return AssociationRequest(header, capability_info, listen_interval, elements)


def build_association_response(
    access_point: MACAddressInput,
    station: MACAddressInput,
    supported_rates: Sequence[int],
    *,
    capability_info: Union[int, Capability] = Capability.ESS,
    status_code: int = 0,
    association_id: int = 1,
    sequence_number: int = 0,
    extra_elements: Iterable[InformationElement] = (),
) -> bytes:
    """Build an AP-to-station association response, primarily for fixtures."""

    if not 0 <= int(capability_info) <= 0xFFFF:
        raise ValueError("capability information must fit in 16 bits")
    if not 0 <= status_code <= 0xFFFF:
        raise ValueError("status code must fit in 16 bits")
    if not 0 <= association_id <= 0x3FFF:
        raise ValueError("association ID must fit in 14 bits")
    elements = rate_elements(supported_rates) + tuple(extra_elements)
    header = _build_header(
        ManagementSubtype.ASSOCIATION_RESPONSE,
        receiver=station,
        transmitter=access_point,
        bssid=access_point,
        sequence_number=sequence_number,
    )
    association_id_raw = association_id | 0xC000 if status_code == 0 else association_id
    return (
        header.encode()
        + struct.pack("<HHH", int(capability_info), status_code, association_id_raw)
        + encode_information_elements(elements)
    )


def parse_association_response(frame: bytes) -> AssociationResponse:
    header = parse_management_header(frame, ManagementSubtype.ASSOCIATION_RESPONSE)
    if header.frame_control.protected:
        raise FrameFormatError("cannot parse an encrypted association-response body")
    if len(frame) < MANAGEMENT_HEADER_LENGTH + 6:
        raise FrameFormatError("association response is missing fixed fields")
    capability_info, status_code, association_id_raw = struct.unpack_from(
        "<HHH", frame, MANAGEMENT_HEADER_LENGTH
    )
    elements = parse_information_elements(frame[MANAGEMENT_HEADER_LENGTH + 6 :])
    return AssociationResponse(
        header, capability_info, status_code, association_id_raw, elements
    )
