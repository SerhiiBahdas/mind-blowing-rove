# SPDX-License-Identifier: GPL-2.0-only
"""Software CCMP-128 protection for IEEE 802.11 data MPDUs.

The input and output are raw 802.11 MPDUs without radiotap metadata or FCS.
AES-CCM is delegated to the audited ``cryptography`` package; this module is
responsible only for the 802.11 CCMP header, nonce, AAD, and packet-number
state.
"""

from dataclasses import dataclass
import threading
from typing import Dict, Optional, Tuple

from .common import DATA_FRAME_TYPE, FrameControl
from .data import DataFrame, parse_data
from .errors import (
    CryptoDependencyError,
    FrameFormatError,
    IntegrityError,
    ReplayError,
)


CCMP_HEADER_LENGTH = 8
CCMP_MIC_LENGTH = 8
CCMP_TK_LENGTH = 16
CCMP_PN_MAX = (1 << 48) - 1

_PROTECTED_FLAG = 1 << 14
_RETRY_FLAG = 1 << 11
_POWER_MANAGEMENT_FLAG = 1 << 12
_MORE_DATA_FLAG = 1 << 13
_ORDER_FLAG = 1 << 15


def _crypto_types():
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    except ImportError as error:
        raise CryptoDependencyError(
            "CCMP needs the optional 'cryptography' package; install "
            "mindrove_station/requirements.txt"
        ) from error
    return AESCCM, InvalidTag


def _validate_temporal_key(temporal_key: bytes) -> bytes:
    key = bytes(temporal_key)
    if len(key) != CCMP_TK_LENGTH:
        raise ValueError("CCMP-128 temporal key must be exactly 16 bytes")
    return key


@dataclass(frozen=True)
class CCMPHeader:
    packet_number: int
    key_id: int = 0

    def __post_init__(self) -> None:
        if not 1 <= self.packet_number <= CCMP_PN_MAX:
            raise ValueError("CCMP packet number must be between 1 and 2^48 - 1")
        if not 0 <= self.key_id <= 3:
            raise ValueError("CCMP key ID must fit in 2 bits")

    def encode(self) -> bytes:
        # pn_be is PN5 || PN4 || ... || PN0.  The CCMP header puts the two
        # least-significant octets first and the remaining octets after KeyID.
        pn_be = self.packet_number.to_bytes(6, "big")
        return bytes(
            (
                pn_be[5],
                pn_be[4],
                0,
                0x20 | (self.key_id << 6),
                pn_be[3],
                pn_be[2],
                pn_be[1],
                pn_be[0],
            )
        )

    @classmethod
    def parse(cls, value: bytes) -> "CCMPHeader":
        data = bytes(value)
        if len(data) != CCMP_HEADER_LENGTH:
            raise FrameFormatError("CCMP header must be exactly 8 bytes")
        if data[2] != 0:
            raise FrameFormatError("CCMP header reserved octet is nonzero")
        if data[3] & 0x3F != 0x20:
            raise FrameFormatError("CCMP header has invalid ExtIV or reserved bits")
        pn_be = bytes((data[7], data[6], data[5], data[4], data[1], data[0]))
        packet_number = int.from_bytes(pn_be, "big")
        if packet_number == 0:
            raise ReplayError("CCMP packet number zero is invalid")
        return cls(packet_number=packet_number, key_id=data[3] >> 6)


@dataclass(frozen=True)
class CCMPDecryptionResult:
    """Authenticated plaintext and its replay-domain metadata."""

    frame: bytes
    plaintext_body: bytes
    packet_number: int
    key_id: int
    qos_tid: Optional[int]
    transmitter: bytes


def _parsed_header_length(frame: bytes, parsed: Optional[DataFrame] = None) -> int:
    data = parsed if parsed is not None else parse_data(frame, decode_llc=False)
    return len(frame) - len(data.body)


def _protected_header(frame: bytes, header_length: int) -> bytes:
    frame_control = FrameControl.decode(frame[:2])
    protected_control = FrameControl(frame_control.value | _PROTECTED_FLAG)
    return protected_control.encode() + bytes(frame[2:header_length])


def _plaintext_header(frame: bytes, header_length: int) -> bytes:
    frame_control = FrameControl.decode(frame[:2])
    plaintext_control = FrameControl(frame_control.value & ~_PROTECTED_FLAG)
    return plaintext_control.encode() + bytes(frame[2:header_length])


def ccmp_aad(protected_frame: bytes) -> bytes:
    """Build the variable-length CCMP additional authenticated data.

    The two-byte CCM AAD length encoding is performed internally by AESCCM and
    is therefore not included in the returned bytes.
    """

    parsed = parse_data(protected_frame, decode_llc=False)
    control = parsed.frame_control
    if control.frame_type != DATA_FRAME_TYPE or not control.protected:
        raise FrameFormatError("CCMP AAD requires a protected data frame")
    if parsed.a_msdu_present:
        raise FrameFormatError("A-MSDU CCMP is outside the narrow station profile")

    masked_control = control.value
    masked_control &= ~(_RETRY_FLAG | _POWER_MANAGEMENT_FLAG | _MORE_DATA_FLAG)
    # For data frames, subtype bits 4..6 are mutable and excluded.  Subtype bit
    # 7 distinguishes QoS and remains authenticated.
    masked_control &= ~0x0070
    if parsed.qos_control is not None:
        masked_control &= ~_ORDER_FLAG
    masked_control |= _PROTECTED_FLAG

    aad = bytearray(FrameControl(masked_control).encode())
    aad.extend(parsed.address1)
    aad.extend(parsed.address2)
    aad.extend(parsed.address3)
    aad.extend(bytes((parsed.fragment_number, 0)))
    if parsed.address4 is not None:
        aad.extend(parsed.address4)
    if parsed.qos_control is not None:
        aad.extend(bytes((parsed.qos_tid or 0, 0)))
    return bytes(aad)


def ccmp_nonce(protected_frame: bytes, packet_number: int) -> bytes:
    """Return Priority || transmitter-address || PN5..PN0 (13 octets)."""

    if not 1 <= packet_number <= CCMP_PN_MAX:
        raise ValueError("CCMP packet number must be between 1 and 2^48 - 1")
    parsed = parse_data(protected_frame, decode_llc=False)
    if not parsed.frame_control.protected:
        raise FrameFormatError("CCMP nonce requires a protected data frame")
    priority = parsed.qos_tid or 0
    return bytes((priority,)) + parsed.transmitter + packet_number.to_bytes(6, "big")


def encrypt_ccmp(
    plaintext_frame: bytes,
    temporal_key: bytes,
    packet_number: int,
    *,
    key_id: int = 0,
) -> bytes:
    """Protect one plaintext 802.11 data MPDU with CCMP-128.

    The caller is responsible for assigning a never-reused packet number.  For
    normal use, :class:`CCMPTransmitter` owns this state and is safer.
    """

    key = _validate_temporal_key(temporal_key)
    parsed = parse_data(plaintext_frame, decode_llc=False)
    if parsed.frame_control.protected:
        raise FrameFormatError("refusing to encrypt an already protected frame")
    if parsed.a_msdu_present:
        raise FrameFormatError("A-MSDU CCMP is outside the narrow station profile")
    if len(parsed.body) > 0xFFFF:
        raise ValueError("CCMP plaintext exceeds the 16-bit CCM length limit")
    header_length = _parsed_header_length(plaintext_frame, parsed)
    header = _protected_header(plaintext_frame, header_length)
    ccmp_header = CCMPHeader(packet_number, key_id).encode()
    protected_stub = header + ccmp_header
    nonce = ccmp_nonce(protected_stub, packet_number)
    aad = ccmp_aad(protected_stub)
    AESCCM, _ = _crypto_types()
    ciphertext_and_mic = AESCCM(key, tag_length=CCMP_MIC_LENGTH).encrypt(
        nonce, parsed.body, aad
    )
    return header + ccmp_header + ciphertext_and_mic


def decrypt_ccmp(protected_frame: bytes, temporal_key: bytes) -> CCMPDecryptionResult:
    """Authenticate and decrypt one CCMP MPDU without maintaining replay state.

    Use :class:`CCMPReceiver` for live traffic.  This stateless primitive is
    exposed for packet fixtures and deliberately cannot claim replay safety.
    """

    key = _validate_temporal_key(temporal_key)
    parsed = parse_data(protected_frame, decode_llc=False)
    if not parsed.frame_control.protected:
        raise FrameFormatError("CCMP decryption requires a protected frame")
    if parsed.a_msdu_present:
        raise FrameFormatError("A-MSDU CCMP is outside the narrow station profile")
    minimum = CCMP_HEADER_LENGTH + CCMP_MIC_LENGTH
    if len(parsed.body) < minimum:
        raise FrameFormatError("protected frame is too short for CCMP header and MIC")
    header_length = _parsed_header_length(protected_frame, parsed)
    ccmp_header = CCMPHeader.parse(parsed.body[:CCMP_HEADER_LENGTH])
    nonce = ccmp_nonce(protected_frame, ccmp_header.packet_number)
    aad = ccmp_aad(protected_frame)
    AESCCM, InvalidTag = _crypto_types()
    try:
        plaintext = AESCCM(key, tag_length=CCMP_MIC_LENGTH).decrypt(
            nonce, parsed.body[CCMP_HEADER_LENGTH:], aad
        )
    except InvalidTag as error:
        # Avoid exposing a backend-specific exception in this package's API.
        raise IntegrityError("CCMP MIC verification failed") from error
    header = _plaintext_header(protected_frame, header_length)
    return CCMPDecryptionResult(
        frame=header + plaintext,
        plaintext_body=plaintext,
        packet_number=ccmp_header.packet_number,
        key_id=ccmp_header.key_id,
        qos_tid=parsed.qos_tid,
        transmitter=parsed.transmitter,
    )


class CCMPTransmitter:
    """Thread-safe owner of a monotonically increasing CCMP transmit PN."""

    def __init__(
        self, temporal_key: bytes, *, key_id: int = 0, first_packet_number: int = 1
    ) -> None:
        self._key = _validate_temporal_key(temporal_key)
        if not 0 <= key_id <= 3:
            raise ValueError("CCMP key ID must fit in 2 bits")
        if not 1 <= first_packet_number <= CCMP_PN_MAX:
            raise ValueError("first CCMP packet number is outside the 48-bit range")
        self.key_id = key_id
        self._next_packet_number = first_packet_number
        self._lock = threading.Lock()

    @property
    def next_packet_number(self) -> int:
        with self._lock:
            return self._next_packet_number

    def encrypt(self, plaintext_frame: bytes) -> bytes:
        with self._lock:
            packet_number = self._next_packet_number
            if packet_number > CCMP_PN_MAX:
                raise OverflowError("CCMP packet-number space is exhausted; rekey required")
            protected = encrypt_ccmp(
                plaintext_frame,
                self._key,
                packet_number,
                key_id=self.key_id,
            )
            self._next_packet_number += 1
            return protected


class CCMPReceiver:
    """Authenticate CCMP frames and enforce replay counters per traffic class.

    Receive PNs are separated by transmitter, key ID, and QoS TID.  A counter
    is committed only after AES-CCM authentication succeeds.
    """

    def __init__(
        self,
        temporal_key: bytes,
        *,
        expected_key_id: Optional[int] = 0,
        initial_packet_number: int = 0,
    ) -> None:
        self._key = _validate_temporal_key(temporal_key)
        if expected_key_id is not None and not 0 <= expected_key_id <= 3:
            raise ValueError("expected CCMP key ID must fit in 2 bits")
        if not 0 <= initial_packet_number <= CCMP_PN_MAX:
            raise ValueError("initial CCMP receive PN is outside the 48-bit range")
        self.expected_key_id = expected_key_id
        self.initial_packet_number = initial_packet_number
        self._last_packet_numbers: Dict[
            Tuple[bytes, int, Optional[int]], int
        ] = {}
        self._lock = threading.Lock()

    def last_packet_number(
        self, transmitter: bytes, qos_tid: Optional[int] = None, key_id: int = 0
    ) -> Optional[int]:
        domain = (bytes(transmitter), key_id, qos_tid)
        with self._lock:
            value = self._last_packet_numbers.get(domain)
            if value is None and self.initial_packet_number:
                return self.initial_packet_number
            return value

    def decrypt(self, protected_frame: bytes) -> CCMPDecryptionResult:
        parsed = parse_data(protected_frame, decode_llc=False)
        if not parsed.frame_control.protected:
            raise FrameFormatError("CCMP decryption requires a protected frame")
        if len(parsed.body) < CCMP_HEADER_LENGTH + CCMP_MIC_LENGTH:
            raise FrameFormatError("protected frame is too short for CCMP")
        header = CCMPHeader.parse(parsed.body[:CCMP_HEADER_LENGTH])
        if self.expected_key_id is not None and header.key_id != self.expected_key_id:
            raise FrameFormatError(
                "CCMP frame uses key ID %d, expected %d"
                % (header.key_id, self.expected_key_id)
            )
        # Non-QoS traffic has a separate replay domain from QoS TID 0 even
        # though both encode nonce Priority as zero.
        domain = (parsed.transmitter, header.key_id, parsed.qos_tid)
        with self._lock:
            previous = self._last_packet_numbers.get(
                domain, self.initial_packet_number
            )
            if header.packet_number <= previous:
                raise ReplayError(
                    "CCMP packet number %d is not newer than %d"
                    % (header.packet_number, previous)
                )
            result = decrypt_ccmp(protected_frame, self._key)
            self._last_packet_numbers[domain] = header.packet_number
            return result
