# SPDX-License-Identifier: GPL-2.0-only
"""WPA2-Personal key derivation and EAPOL-Key handshake primitives.

This module is deliberately independent of USB and radio I/O.  It implements
the WPA2-PSK/CCMP path used by the MindRove access point: PBKDF2-HMAC-SHA1 PMK
derivation, the WPA pairwise-key expansion PRF, strict EAPOL-Key framing, and a
small supplicant-side four-way-handshake state machine.

All EAPOL multi-byte fields use network byte order.  MIC calculations cover
the complete 802.1X packet (starting at Protocol Version) with the 16-byte MIC
field zeroed.
"""

from dataclasses import dataclass, field, replace
from enum import Enum, IntEnum, IntFlag
import hashlib
import hmac
import secrets
import struct
from typing import Optional, Union

from .common import MACAddressInput, mac_bytes
from .errors import (
    CryptoDependencyError,
    FrameFormatError,
    HandshakeError,
    IntegrityError,
    ReplayError,
)


EAPOL_PACKET_TYPE_KEY = 3
RSN_KEY_DESCRIPTOR_TYPE = 2
EAPOL_KEY_FIXED_LENGTH = 99
EAPOL_KEY_MIC_OFFSET = 81
EAPOL_KEY_MIC_LENGTH = 16
WPA_NONCE_LENGTH = 32
PMK_LENGTH = 32
KCK_LENGTH = 16
KEK_LENGTH = 16
CCMP_TK_LENGTH = 16
CCMP_PTK_LENGTH = KCK_LENGTH + KEK_LENGTH + CCMP_TK_LENGTH
WPA_PTK_LENGTH = CCMP_PTK_LENGTH + 16

_ZERO_NONCE = bytes(WPA_NONCE_LENGTH)
_ZERO_MIC = bytes(EAPOL_KEY_MIC_LENGTH)
_PAIRWISE_EXPANSION_LABEL = b"Pairwise key expansion"


class KeyDescriptorVersion(IntEnum):
    """Algorithm encoded in Key Information bits 0..2."""

    HMAC_MD5_RC4 = 1
    HMAC_SHA1_AES = 2
    AES_128_CMAC = 3


class KeyInformation(IntFlag):
    """The non-version bits of the EAPOL-Key Key Information field."""

    KEY_TYPE_PAIRWISE = 1 << 3
    INSTALL = 1 << 6
    ACK = 1 << 7
    MIC = 1 << 8
    SECURE = 1 << 9
    ERROR = 1 << 10
    REQUEST = 1 << 11
    ENCRYPTED_KEY_DATA = 1 << 12
    SMK_MESSAGE = 1 << 13


class FourWayMessage(IntEnum):
    M1 = 1
    M2 = 2
    M3 = 3
    M4 = 4


class HandshakeState(Enum):
    AWAITING_M1 = "awaiting-m1"
    AWAITING_M3 = "awaiting-m3"
    COMPLETE = "complete"


@dataclass(frozen=True)
class PairwiseKeys:
    """The named portions of a WPA PTK.

    CCMP uses KCK || KEK || TK (48 bytes).  When a 64-byte WPA/TKIP PTK is
    supplied, the final two eight-byte Michael MIC keys are retained as well.
    """

    kck: bytes = field(repr=False)
    kek: bytes = field(repr=False)
    temporal_key: bytes = field(repr=False)
    tx_michael_key: bytes = field(default=b"", repr=False)
    rx_michael_key: bytes = field(default=b"", repr=False)

    def __post_init__(self) -> None:
        expected = (
            ("KCK", self.kck, KCK_LENGTH),
            ("KEK", self.kek, KEK_LENGTH),
            ("temporal key", self.temporal_key, CCMP_TK_LENGTH),
        )
        for label, value, length in expected:
            normalized = bytes(value)
            if len(normalized) != length:
                raise ValueError("%s must be %d bytes" % (label, length))
            object.__setattr__(self, label.lower().replace(" ", "_"), normalized)
        for field_name in ("tx_michael_key", "rx_michael_key"):
            value = bytes(getattr(self, field_name))
            if len(value) not in (0, 8):
                raise ValueError("%s must be empty or 8 bytes" % field_name)
            object.__setattr__(self, field_name, value)

    @classmethod
    def from_ptk(cls, ptk: bytes) -> "PairwiseKeys":
        value = bytes(ptk)
        if len(value) not in (CCMP_PTK_LENGTH, WPA_PTK_LENGTH):
            raise ValueError("PTK must be 48 bytes for CCMP or 64 bytes for WPA/TKIP")
        return cls(
            kck=value[:16],
            kek=value[16:32],
            temporal_key=value[32:48],
            tx_michael_key=value[48:56],
            rx_michael_key=value[56:64],
        )

    def encode(self) -> bytes:
        return (
            self.kck
            + self.kek
            + self.temporal_key
            + self.tx_michael_key
            + self.rx_michael_key
        )


@dataclass(frozen=True)
class GroupKey:
    """A CCMP GTK recovered from authenticated EAPOL-Key M3 data.

    The generated representation intentionally omits both the key bytes and
    receive sequence counter so routine diagnostics cannot disclose them.
    """

    key_id: int
    temporal_key: bytes = field(repr=False)
    transmit: bool = False
    receive_sequence_counter: bytes = field(default=bytes(8), repr=False)

    def __post_init__(self) -> None:
        if not 0 <= self.key_id <= 3:
            raise ValueError("GTK key ID must fit in 2 bits")
        key = bytes(self.temporal_key)
        if len(key) != CCMP_TK_LENGTH:
            raise ValueError("CCMP GTK must be exactly 16 bytes")
        rsc = bytes(self.receive_sequence_counter)
        if len(rsc) != 8:
            raise ValueError("GTK receive sequence counter must be exactly 8 bytes")
        object.__setattr__(self, "temporal_key", key)
        object.__setattr__(self, "receive_sequence_counter", rsc)

    @property
    def receive_packet_number(self) -> int:
        """Initial CCMP receive PN encoded by M3's little-endian Key RSC."""

        return int.from_bytes(self.receive_sequence_counter[:6], "little")


def _credential_bytes(value: Union[str, bytes], name: str) -> bytes:
    if isinstance(value, str):
        try:
            return value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("%s cannot be encoded as UTF-8" % name) from error
    return bytes(value)


def derive_pmk(passphrase: Union[str, bytes], ssid: Union[str, bytes]) -> bytes:
    """Derive a 256-bit PMK using the WPA-Personal PBKDF2 construction.

    ``passphrase`` is the 8..63-octet WPA passphrase, not a 64-character raw
    hexadecimal PSK.  Raw PMKs should be passed directly to :func:`derive_ptk`.
    """

    passphrase_bytes = _credential_bytes(passphrase, "passphrase")
    ssid_bytes = _credential_bytes(ssid, "SSID")
    if not 8 <= len(passphrase_bytes) <= 63:
        raise ValueError("WPA passphrase must contain 8 through 63 octets")
    if not 1 <= len(ssid_bytes) <= 32:
        raise ValueError("SSID must contain 1 through 32 octets")
    return hashlib.pbkdf2_hmac(
        "sha1", passphrase_bytes, ssid_bytes, 4096, dklen=PMK_LENGTH
    )


def _wpa_prf(key: bytes, label: bytes, data: bytes, length: int) -> bytes:
    if not 1 <= length <= 256 * hashlib.sha1().digest_size:
        raise ValueError("PRF output length is outside the one-byte counter range")
    result = bytearray()
    counter = 0
    while len(result) < length:
        result.extend(
            hmac.new(
                key,
                label + b"\x00" + data + bytes((counter,)),
                hashlib.sha1,
            ).digest()
        )
        counter += 1
    return bytes(result[:length])


def derive_ptk(
    pmk: bytes,
    authenticator_address: MACAddressInput,
    supplicant_address: MACAddressInput,
    authenticator_nonce: bytes,
    supplicant_nonce: bytes,
    *,
    length: int = CCMP_PTK_LENGTH,
) -> bytes:
    """Expand a PMK into the PTK shared by an AP and a station.

    Address and nonce pairs are independently sorted lexicographically, as
    required by the WPA Pairwise Key Expansion construction.
    """

    pmk_bytes = bytes(pmk)
    if len(pmk_bytes) != PMK_LENGTH:
        raise ValueError("PMK must be exactly 32 bytes")
    if length not in (CCMP_PTK_LENGTH, WPA_PTK_LENGTH):
        raise ValueError("PTK length must be 48 (CCMP) or 64 (WPA/TKIP) bytes")
    aa = mac_bytes(authenticator_address)
    spa = mac_bytes(supplicant_address)
    anonce = bytes(authenticator_nonce)
    snonce = bytes(supplicant_nonce)
    if len(anonce) != WPA_NONCE_LENGTH or len(snonce) != WPA_NONCE_LENGTH:
        raise ValueError("WPA nonces must be exactly 32 bytes")
    if anonce == _ZERO_NONCE or snonce == _ZERO_NONCE:
        raise ValueError("WPA nonces must not be all zero")
    context = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(
        anonce, snonce
    )
    return _wpa_prf(pmk_bytes, _PAIRWISE_EXPANSION_LABEL, context, length)


def derive_pairwise_keys(
    pmk: bytes,
    authenticator_address: MACAddressInput,
    supplicant_address: MACAddressInput,
    authenticator_nonce: bytes,
    supplicant_nonce: bytes,
) -> PairwiseKeys:
    return PairwiseKeys.from_ptk(
        derive_ptk(
            pmk,
            authenticator_address,
            supplicant_address,
            authenticator_nonce,
            supplicant_nonce,
        )
    )


@dataclass(frozen=True)
class EAPOLKeyFrame:
    protocol_version: int
    descriptor_type: int
    key_information: int
    key_length: int
    replay_counter: int
    nonce: bytes
    key_iv: bytes = bytes(16)
    key_rsc: bytes = bytes(8)
    key_id: bytes = bytes(8)
    mic: bytes = _ZERO_MIC
    key_data: bytes = b""

    def __post_init__(self) -> None:
        integer_fields = (
            ("protocol version", self.protocol_version, 0xFF),
            ("descriptor type", self.descriptor_type, 0xFF),
            ("key information", self.key_information, 0xFFFF),
            ("key length", self.key_length, 0xFFFF),
            ("replay counter", self.replay_counter, 0xFFFFFFFFFFFFFFFF),
        )
        for integer_name, integer_value, maximum in integer_fields:
            if not 0 <= integer_value <= maximum:
                raise ValueError(
                    "%s is outside its wire-field range" % integer_name
                )
        fixed_fields = (
            ("nonce", self.nonce, WPA_NONCE_LENGTH),
            ("key IV", self.key_iv, 16),
            ("key RSC", self.key_rsc, 8),
            ("key ID", self.key_id, 8),
            ("MIC", self.mic, EAPOL_KEY_MIC_LENGTH),
        )
        for field_name, field_value, length in fixed_fields:
            normalized = bytes(field_value)
            if len(normalized) != length:
                raise ValueError(
                    "%s must be exactly %d bytes" % (field_name, length)
                )
            object.__setattr__(
                self, field_name.lower().replace(" ", "_"), normalized
            )
        key_data = bytes(self.key_data)
        if len(key_data) > 0xFFFF:
            raise ValueError("EAPOL key data cannot exceed 65535 bytes")
        object.__setattr__(self, "key_data", key_data)

    @property
    def descriptor_version(self) -> int:
        return self.key_information & 0x7

    @property
    def information(self) -> KeyInformation:
        return KeyInformation(self.key_information & ~0x7)

    def has(self, flag: KeyInformation) -> bool:
        return bool(self.key_information & int(flag))

    def encode(self, *, zero_mic: bool = False) -> bytes:
        mic = _ZERO_MIC if zero_mic else self.mic
        body = b"".join(
            (
                bytes((self.descriptor_type,)),
                struct.pack("!H", self.key_information),
                struct.pack("!H", self.key_length),
                struct.pack("!Q", self.replay_counter),
                self.nonce,
                self.key_iv,
                self.key_rsc,
                self.key_id,
                mic,
                struct.pack("!H", len(self.key_data)),
                self.key_data,
            )
        )
        return bytes((self.protocol_version, EAPOL_PACKET_TYPE_KEY)) + struct.pack(
            "!H", len(body)
        ) + body

    def with_mic(self, mic: bytes) -> "EAPOLKeyFrame":
        return replace(self, mic=bytes(mic))


def parse_eapol_key(packet: bytes) -> EAPOLKeyFrame:
    """Parse exactly one complete 802.1X EAPOL-Key packet."""

    value = bytes(packet)
    if len(value) < EAPOL_KEY_FIXED_LENGTH:
        raise FrameFormatError("EAPOL-Key packet is shorter than 99 bytes")
    protocol_version, packet_type, body_length = struct.unpack_from("!BBH", value)
    if packet_type != EAPOL_PACKET_TYPE_KEY:
        raise FrameFormatError("802.1X packet is not EAPOL-Key")
    if body_length < EAPOL_KEY_FIXED_LENGTH - 4:
        raise FrameFormatError("EAPOL-Key body is shorter than its fixed fields")
    if len(value) != body_length + 4:
        raise FrameFormatError(
            "EAPOL body length %d does not match packet length %d"
            % (body_length, len(value) - 4)
        )
    key_data_length = struct.unpack_from("!H", value, 97)[0]
    if key_data_length != len(value) - EAPOL_KEY_FIXED_LENGTH:
        raise FrameFormatError(
            "EAPOL key-data length %d does not match available bytes %d"
            % (key_data_length, len(value) - EAPOL_KEY_FIXED_LENGTH)
        )
    return EAPOLKeyFrame(
        protocol_version=protocol_version,
        descriptor_type=value[4],
        key_information=struct.unpack_from("!H", value, 5)[0],
        key_length=struct.unpack_from("!H", value, 7)[0],
        replay_counter=struct.unpack_from("!Q", value, 9)[0],
        nonce=value[17:49],
        key_iv=value[49:65],
        key_rsc=value[65:73],
        key_id=value[73:81],
        mic=value[EAPOL_KEY_MIC_OFFSET : EAPOL_KEY_MIC_OFFSET + 16],
        key_data=value[EAPOL_KEY_FIXED_LENGTH:],
    )


def build_eapol_key(
    *,
    key_information: int,
    replay_counter: int,
    nonce: bytes,
    key_length: int = 0,
    key_data: bytes = b"",
    protocol_version: int = 2,
    descriptor_type: int = RSN_KEY_DESCRIPTOR_TYPE,
    key_iv: bytes = bytes(16),
    key_rsc: bytes = bytes(8),
    key_id: bytes = bytes(8),
    mic: bytes = _ZERO_MIC,
) -> EAPOLKeyFrame:
    return EAPOLKeyFrame(
        protocol_version=protocol_version,
        descriptor_type=descriptor_type,
        key_information=int(key_information),
        key_length=key_length,
        replay_counter=replay_counter,
        nonce=nonce,
        key_iv=key_iv,
        key_rsc=key_rsc,
        key_id=key_id,
        mic=mic,
        key_data=key_data,
    )


def _coerce_eapol_key(packet: Union[bytes, EAPOLKeyFrame]) -> EAPOLKeyFrame:
    return packet if isinstance(packet, EAPOLKeyFrame) else parse_eapol_key(packet)


def compute_eapol_mic(
    kck: bytes, packet: Union[bytes, EAPOLKeyFrame]
) -> bytes:
    """Calculate the 16-byte MIC selected by Key Descriptor Version."""

    key = bytes(kck)
    if len(key) != KCK_LENGTH:
        raise ValueError("KCK must be exactly 16 bytes")
    frame = _coerce_eapol_key(packet)
    authenticated = frame.encode(zero_mic=True)
    if frame.descriptor_version == KeyDescriptorVersion.HMAC_MD5_RC4:
        return hmac.new(key, authenticated, hashlib.md5).digest()
    if frame.descriptor_version == KeyDescriptorVersion.HMAC_SHA1_AES:
        return hmac.new(key, authenticated, hashlib.sha1).digest()[:16]
    if frame.descriptor_version == KeyDescriptorVersion.AES_128_CMAC:
        try:
            from cryptography.hazmat.primitives import cmac
            from cryptography.hazmat.primitives.ciphers import algorithms
        except ImportError as error:
            raise CryptoDependencyError(
                "AES-CMAC needs the optional 'cryptography' package"
            ) from error
        calculator = cmac.CMAC(algorithms.AES(key))
        calculator.update(authenticated)
        return calculator.finalize()
    raise HandshakeError(
        "unsupported EAPOL Key Descriptor Version %d" % frame.descriptor_version
    )


def sign_eapol_key(
    kck: bytes, packet: Union[bytes, EAPOLKeyFrame]
) -> EAPOLKeyFrame:
    frame = _coerce_eapol_key(packet)
    if not frame.has(KeyInformation.MIC):
        raise HandshakeError("cannot sign EAPOL-Key packet without the MIC flag")
    return frame.with_mic(compute_eapol_mic(kck, frame))


def verify_eapol_mic(
    kck: bytes, packet: Union[bytes, EAPOLKeyFrame]
) -> bool:
    frame = _coerce_eapol_key(packet)
    if not frame.has(KeyInformation.MIC):
        return False
    return hmac.compare_digest(frame.mic, compute_eapol_mic(kck, frame))


def require_valid_eapol_mic(
    kck: bytes, packet: Union[bytes, EAPOLKeyFrame]
) -> EAPOLKeyFrame:
    frame = _coerce_eapol_key(packet)
    if not verify_eapol_mic(kck, frame):
        raise IntegrityError("EAPOL-Key MIC verification failed")
    return frame


def _aes_unwrap_key_data(kek: bytes, wrapped_key_data: bytes) -> bytes:
    key = bytes(kek)
    wrapped = bytes(wrapped_key_data)
    if len(key) != KEK_LENGTH:
        raise ValueError("KEK must be exactly 16 bytes")
    if len(wrapped) < 16 or len(wrapped) % 8:
        raise FrameFormatError(
            "AES-wrapped EAPOL key data must be at least 16 bytes and a multiple of 8"
        )
    try:
        from cryptography.hazmat.primitives.keywrap import (
            InvalidUnwrap,
            aes_key_unwrap,
        )
    except ImportError as error:
        raise CryptoDependencyError(
            "EAPOL AES key unwrap needs the optional 'cryptography' package"
        ) from error
    try:
        return aes_key_unwrap(key, wrapped)
    except InvalidUnwrap as error:
        raise IntegrityError("EAPOL AES key-wrap integrity check failed") from error


def unwrap_eapol_key_data(
    kck: bytes,
    kek: bytes,
    packet: Union[bytes, EAPOLKeyFrame],
) -> bytes:
    """Authenticate M3 and unwrap its RFC 3394 AES-wrapped Key Data.

    Requiring both KCK and KEK makes the public operation fail closed: wrapped
    data is never interpreted before the EAPOL MIC has been validated.
    """

    frame = _coerce_eapol_key(packet)
    if classify_four_way_message(frame) is not FourWayMessage.M3:
        raise HandshakeError("encrypted EAPOL key data is expected only in M3")
    if frame.descriptor_version != KeyDescriptorVersion.HMAC_SHA1_AES:
        raise HandshakeError("AES key unwrap requires descriptor version 2")
    if not frame.has(KeyInformation.ENCRYPTED_KEY_DATA):
        raise HandshakeError("M3 does not mark its key data as encrypted")
    require_valid_eapol_mic(kck, frame)
    return _aes_unwrap_key_data(kek, frame.key_data)


def extract_group_key_from_plaintext(
    key_data: bytes,
    *,
    receive_sequence_counter: bytes = bytes(8),
) -> GroupKey:
    """Strictly extract one CCMP GTK KDE from unwrapped EAPOL Key Data.

    Other well-formed information elements (normally the AP's RSNE) are
    skipped. A duplicate GTK KDE, malformed element, nonzero GTK reserved bit,
    or non-CCMP key length rejects the entire field.
    """

    data = bytes(key_data)
    offset = 0
    group_key: Optional[GroupKey] = None
    gtk_selector = b"\x00\x0f\xac\x01"
    while offset < len(data):
        remaining = data[offset:]
        if remaining[0] == 0xDD and (
            len(remaining) == 1 or (len(remaining) >= 2 and remaining[1] == 0)
        ):
            padding_tail = remaining[1:]
            if any(padding_tail):
                raise FrameFormatError("EAPOL key-data padding contains nonzero bytes")
            break
        if len(remaining) < 2:
            raise FrameFormatError("truncated EAPOL key-data information element")
        element_length = remaining[1]
        total_length = 2 + element_length
        if total_length > len(remaining):
            raise FrameFormatError(
                "EAPOL key-data information element exceeds remaining bytes"
            )
        body = remaining[2:total_length]
        if remaining[0] == 0xDD and body.startswith(gtk_selector):
            if group_key is not None:
                raise FrameFormatError("duplicate GTK KDE in EAPOL key data")
            if len(body) != 4 + 2 + CCMP_TK_LENGTH:
                raise FrameFormatError("GTK KDE does not contain one 16-byte CCMP key")
            key_information = body[4]
            if key_information & 0xF8 or body[5] != 0:
                raise FrameFormatError("GTK KDE reserved bits are nonzero")
            group_key = GroupKey(
                key_id=key_information & 0x03,
                transmit=bool(key_information & 0x04),
                temporal_key=body[6:],
                receive_sequence_counter=receive_sequence_counter,
            )
        offset += total_length
    if group_key is None:
        raise HandshakeError("authenticated M3 key data does not contain a GTK KDE")
    return group_key


def extract_group_key(
    kck: bytes,
    kek: bytes,
    packet: Union[bytes, EAPOLKeyFrame],
) -> GroupKey:
    """Authenticate M3, unwrap its key data, and return its CCMP group key."""

    frame = _coerce_eapol_key(packet)
    plaintext = unwrap_eapol_key_data(kck, kek, frame)
    return extract_group_key_from_plaintext(
        plaintext,
        receive_sequence_counter=frame.key_rsc,
    )


def classify_four_way_message(
    packet: Union[bytes, EAPOLKeyFrame]
) -> FourWayMessage:
    """Classify a pairwise EAPOL-Key packet as M1, M2, M3, or M4.

    Classification is intentionally strict for the four-way exchange.  Error,
    Request, SMK, and group-key messages are rejected rather than guessed.
    """

    frame = _coerce_eapol_key(packet)
    if frame.descriptor_type != RSN_KEY_DESCRIPTOR_TYPE:
        raise HandshakeError("four-way handshake requires an RSN key descriptor")
    if frame.descriptor_version not in tuple(version.value for version in KeyDescriptorVersion):
        raise HandshakeError("unsupported Key Descriptor Version")
    if not frame.has(KeyInformation.KEY_TYPE_PAIRWISE):
        raise HandshakeError("group-key packet is not part of the four-way handshake")
    if frame.information & (
        KeyInformation.ERROR | KeyInformation.REQUEST | KeyInformation.SMK_MESSAGE
    ):
        raise HandshakeError("EAPOL-Key control packet is not a four-way message")

    flags = frame.key_information & ~0x7
    nonce_is_zero = frame.nonce == _ZERO_NONCE
    m1_flags = int(KeyInformation.KEY_TYPE_PAIRWISE | KeyInformation.ACK)
    m2_flags = int(KeyInformation.KEY_TYPE_PAIRWISE | KeyInformation.MIC)
    m3_flags = int(
        KeyInformation.KEY_TYPE_PAIRWISE
        | KeyInformation.INSTALL
        | KeyInformation.ACK
        | KeyInformation.MIC
        | KeyInformation.SECURE
    )
    m4_flags = int(
        KeyInformation.KEY_TYPE_PAIRWISE | KeyInformation.MIC | KeyInformation.SECURE
    )

    if flags == m1_flags and not nonce_is_zero:
        return FourWayMessage.M1
    if flags == m2_flags and not nonce_is_zero:
        return FourWayMessage.M2
    if flags in (
        m3_flags,
        m3_flags | int(KeyInformation.ENCRYPTED_KEY_DATA),
    ) and not nonce_is_zero:
        if frame.has(KeyInformation.ENCRYPTED_KEY_DATA) and not frame.key_data:
            raise HandshakeError("M3 marks empty key data as encrypted")
        return FourWayMessage.M3
    if flags == m4_flags and nonce_is_zero and not frame.key_data:
        return FourWayMessage.M4
    raise HandshakeError("EAPOL-Key flags and nonce do not form M1, M2, M3, or M4")


class WPA2PSKHandshake:
    """Minimal, replay-safe supplicant state for WPA2-PSK/CCMP.

    The caller transmits the returned EAPOL packets inside ordinary unprotected
    802.11 data frames.  PTK installation is exposed only after M3 has a valid
    MIC, a fresh replay counter, and the original ANonce.  A byte-identical M3
    retransmission returns the cached M4 without deriving or reinstalling keys.
    """

    def __init__(
        self,
        pmk: bytes,
        authenticator_address: MACAddressInput,
        supplicant_address: MACAddressInput,
        association_rsn_element: bytes,
        *,
        snonce: Optional[bytes] = None,
    ) -> None:
        self._pmk = bytes(pmk)
        if len(self._pmk) != PMK_LENGTH:
            raise ValueError("PMK must be exactly 32 bytes")
        self.authenticator_address = mac_bytes(authenticator_address)
        self.supplicant_address = mac_bytes(supplicant_address)
        self.association_rsn_element = bytes(association_rsn_element)
        if len(self.association_rsn_element) < 2 or self.association_rsn_element[0] != 48:
            raise ValueError("association RSN element must include element ID 48")
        if self.association_rsn_element[1] != len(self.association_rsn_element) - 2:
            raise ValueError("association RSN element length is inconsistent")
        self.snonce = secrets.token_bytes(32) if snonce is None else bytes(snonce)
        if len(self.snonce) != WPA_NONCE_LENGTH or self.snonce == _ZERO_NONCE:
            raise ValueError("SNonce must be a nonzero 32-byte value")
        self.state = HandshakeState.AWAITING_M1
        self.pairwise_keys: Optional[PairwiseKeys] = None
        self.group_key: Optional[GroupKey] = None
        self._candidate_keys: Optional[PairwiseKeys] = None
        self.anonce: Optional[bytes] = None
        self._m1_replay: Optional[int] = None
        self._m1_fingerprint: Optional[bytes] = None
        self._m2: Optional[bytes] = None
        self._m3_replay: Optional[int] = None
        self._m3_fingerprint: Optional[bytes] = None
        self._m4: Optional[bytes] = None

    @property
    def complete(self) -> bool:
        return self.state is HandshakeState.COMPLETE

    def process_m1(self, packet: Union[bytes, EAPOLKeyFrame]) -> bytes:
        frame = _coerce_eapol_key(packet)
        if classify_four_way_message(frame) is not FourWayMessage.M1:
            raise HandshakeError("expected four-way handshake M1")
        encoded = frame.encode()
        if self.state is HandshakeState.AWAITING_M3:
            if hmac.compare_digest(encoded, self._m1_fingerprint or b""):
                if self._m2 is None:
                    raise HandshakeError("handshake has no cached M2")
                return self._m2
            raise ReplayError("changed M1 received while waiting for M3")
        if self.state is not HandshakeState.AWAITING_M1:
            raise ReplayError("M1 received after pairwise keys were installed")
        if frame.descriptor_version != KeyDescriptorVersion.HMAC_SHA1_AES:
            raise HandshakeError("MindRove WPA2-PSK/CCMP requires descriptor version 2")
        if frame.replay_counter == 0xFFFFFFFFFFFFFFFF:
            raise ReplayError("M1 replay counter cannot be advanced")

        keys = derive_pairwise_keys(
            self._pmk,
            self.authenticator_address,
            self.supplicant_address,
            frame.nonce,
            self.snonce,
        )
        m2_info = int(KeyDescriptorVersion.HMAC_SHA1_AES) | int(
            KeyInformation.KEY_TYPE_PAIRWISE | KeyInformation.MIC
        )
        m2 = build_eapol_key(
            protocol_version=frame.protocol_version,
            descriptor_type=frame.descriptor_type,
            key_information=m2_info,
            key_length=0,
            replay_counter=frame.replay_counter,
            nonce=self.snonce,
            key_data=self.association_rsn_element,
        )
        signed_m2 = sign_eapol_key(keys.kck, m2).encode()

        self._candidate_keys = keys
        self.anonce = frame.nonce
        self._m1_replay = frame.replay_counter
        self._m1_fingerprint = encoded
        self._m2 = signed_m2
        self.state = HandshakeState.AWAITING_M3
        return signed_m2

    def process_m3(self, packet: Union[bytes, EAPOLKeyFrame]) -> bytes:
        frame = _coerce_eapol_key(packet)
        if classify_four_way_message(frame) is not FourWayMessage.M3:
            raise HandshakeError("expected four-way handshake M3")
        if self.state is HandshakeState.COMPLETE:
            encoded = frame.encode()
            if hmac.compare_digest(encoded, self._m3_fingerprint or b""):
                if self._m4 is None:
                    raise HandshakeError("handshake has no cached M4")
                return self._m4
            raise ReplayError("changed M3 received after key installation")
        if self.state is not HandshakeState.AWAITING_M3:
            raise HandshakeError("M3 received before M1")
        if self._candidate_keys is None or self.anonce is None or self._m1_replay is None:
            raise HandshakeError("handshake state is incomplete")
        if frame.descriptor_version != KeyDescriptorVersion.HMAC_SHA1_AES:
            raise HandshakeError("M3 changed the negotiated descriptor version")
        if frame.nonce != self.anonce:
            raise HandshakeError("M3 ANonce does not match M1")
        if frame.replay_counter <= self._m1_replay:
            raise ReplayError("M3 replay counter did not advance beyond M1")
        require_valid_eapol_mic(self._candidate_keys.kck, frame)
        pending_group_key = None
        if frame.has(KeyInformation.ENCRYPTED_KEY_DATA):
            pending_group_key = extract_group_key(
                self._candidate_keys.kck,
                self._candidate_keys.kek,
                frame,
            )

        m4_info = int(KeyDescriptorVersion.HMAC_SHA1_AES) | int(
            KeyInformation.KEY_TYPE_PAIRWISE
            | KeyInformation.MIC
            | KeyInformation.SECURE
        )
        m4 = build_eapol_key(
            protocol_version=frame.protocol_version,
            descriptor_type=frame.descriptor_type,
            key_information=m4_info,
            key_length=0,
            replay_counter=frame.replay_counter,
            nonce=_ZERO_NONCE,
        )
        signed_m4 = sign_eapol_key(self._candidate_keys.kck, m4).encode()
        self._m3_replay = frame.replay_counter
        self._m3_fingerprint = frame.encode()
        self._m4 = signed_m4
        self.pairwise_keys = self._candidate_keys
        self.group_key = pending_group_key
        self.state = HandshakeState.COMPLETE
        return signed_m4

    def process(self, packet: Union[bytes, EAPOLKeyFrame]) -> bytes:
        frame = _coerce_eapol_key(packet)
        message = classify_four_way_message(frame)
        if message is FourWayMessage.M1:
            return self.process_m1(frame)
        if message is FourWayMessage.M3:
            return self.process_m3(frame)
        raise HandshakeError("supplicant accepts only AP-originated M1 or M3")
