# SPDX-License-Identifier: GPL-2.0-only
"""Strict parsing for RSN (WPA2/WPA3) and legacy WPA information elements.

Suite-selector values follow the IEEE 802.11 RSN selector registry and the
Wi-Fi Alliance WPA vendor IE.  Unknown selectors are retained verbatim so a
caller can make an explicit policy decision instead of accidentally treating
an unfamiliar network as open.
"""

from dataclasses import dataclass
from enum import Enum
import struct
from typing import Iterable, Optional, Sequence, Tuple, Union

from .errors import FrameFormatError
from .ie import ElementID, InformationElement


RSN_OUI = b"\x00\x0f\xac"
WPA_OUI = b"\x00\x50\xf2"
WPA_VENDOR_PREFIX = WPA_OUI + b"\x01"


RSN_CIPHER_NAMES = {
    0: "Use group cipher suite",
    1: "WEP-40",
    2: "TKIP",
    4: "CCMP-128",
    5: "WEP-104",
    6: "BIP-CMAC-128",
    8: "GCMP-128",
    9: "GCMP-256",
    10: "CCMP-256",
    11: "BIP-GMAC-128",
    12: "BIP-GMAC-256",
    13: "BIP-CMAC-256",
}

RSN_AKM_NAMES = {
    1: "802.1X",
    2: "PSK",
    3: "FT/802.1X",
    4: "FT/PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    8: "SAE",
    9: "FT/SAE",
    11: "802.1X Suite B",
    12: "802.1X Suite B-192",
    13: "FT/802.1X-SHA384",
    18: "OWE",
}

WPA_CIPHER_NAMES = {
    1: "WEP-40",
    2: "TKIP",
    4: "CCMP-128",
    5: "WEP-104",
}

WPA_AKM_NAMES = {1: "802.1X", 2: "PSK"}


@dataclass(frozen=True)
class SuiteSelector:
    oui: bytes
    suite_type: int

    def __post_init__(self) -> None:
        oui = bytes(self.oui)
        if len(oui) != 3:
            raise ValueError("suite-selector OUI must contain exactly 3 bytes")
        if not 0 <= self.suite_type <= 0xFF:
            raise ValueError("suite-selector type must fit in one byte")
        object.__setattr__(self, "oui", oui)

    def encode(self) -> bytes:
        return self.oui + bytes((self.suite_type,))

    @property
    def name(self) -> str:
        if self.oui == RSN_OUI:
            # A selector can be used in either cipher or AKM position; callers
            # that need an unambiguous label should use cipher_name/akm_name.
            return "RSN selector %d" % self.suite_type
        if self.oui == WPA_OUI:
            return "WPA selector %d" % self.suite_type
        return "%s:%d" % (self.oui.hex(":"), self.suite_type)

    @property
    def cipher_name(self) -> str:
        names = RSN_CIPHER_NAMES if self.oui == RSN_OUI else WPA_CIPHER_NAMES
        return names.get(self.suite_type, self.name)

    @property
    def akm_name(self) -> str:
        names = RSN_AKM_NAMES if self.oui == RSN_OUI else WPA_AKM_NAMES
        return names.get(self.suite_type, self.name)


RSN_CCMP_128 = SuiteSelector(RSN_OUI, 4)
RSN_PSK = SuiteSelector(RSN_OUI, 2)
RSN_SAE = SuiteSelector(RSN_OUI, 8)


@dataclass(frozen=True)
class RSNCapabilities:
    value: int

    def __post_init__(self) -> None:
        if not 0 <= self.value <= 0xFFFF:
            raise ValueError("RSN capabilities must fit in 16 bits")

    @property
    def preauthentication(self) -> bool:
        return bool(self.value & (1 << 0))

    @property
    def no_pairwise(self) -> bool:
        return bool(self.value & (1 << 1))

    @property
    def ptk_replay_counter_code(self) -> int:
        return (self.value >> 2) & 0x3

    @property
    def gtk_replay_counter_code(self) -> int:
        return (self.value >> 4) & 0x3

    @property
    def management_frame_protection_required(self) -> bool:
        return bool(self.value & (1 << 6))

    @property
    def management_frame_protection_capable(self) -> bool:
        return bool(self.value & (1 << 7))


@dataclass(frozen=True)
class RSNInformation:
    version: int
    group_cipher: SuiteSelector
    pairwise_ciphers: tuple
    akm_suites: tuple
    capabilities: Optional[RSNCapabilities]
    pmkids: tuple
    group_management_cipher: Optional[SuiteSelector]


@dataclass(frozen=True)
class WPAInformation:
    version: int
    group_cipher: SuiteSelector
    pairwise_ciphers: tuple
    akm_suites: tuple
    capabilities: Optional[int]


class SecurityMode(Enum):
    OPEN = "open"
    WEP_OR_UNKNOWN_PRIVACY = "wep-or-unknown-privacy"
    WPA_PERSONAL = "wpa-personal"
    WPA_ENTERPRISE = "wpa-enterprise"
    WPA2_PERSONAL = "wpa2-personal"
    WPA2_ENTERPRISE = "wpa2-enterprise"
    WPA3_PERSONAL = "wpa3-personal"
    WPA2_WPA3_PERSONAL = "wpa2-wpa3-personal"
    WPA3_ENTERPRISE = "wpa3-enterprise"
    ENHANCED_OPEN = "enhanced-open"
    RSN_UNKNOWN = "rsn-unknown"


@dataclass(frozen=True)
class SecurityInformation:
    privacy_capability: bool
    rsn: Optional[RSNInformation]
    wpa: Optional[WPAInformation]
    rsnx: Optional[bytes]
    mode: SecurityMode


class _Cursor:
    def __init__(self, data: bytes, context: str):
        self.data = bytes(data)
        self.offset = 0
        self.context = context

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def take(self, length: int, label: str) -> bytes:
        end = self.offset + length
        if end > len(self.data):
            raise FrameFormatError(
                "%s is truncated while reading %s (need %d bytes, have %d)"
                % (self.context, label, length, self.remaining)
            )
        result = self.data[self.offset : end]
        self.offset = end
        return result

    def little_u16(self, label: str) -> int:
        return struct.unpack("<H", self.take(2, label))[0]

    def suite(self, label: str) -> SuiteSelector:
        value = self.take(4, label)
        return SuiteSelector(value[:3], value[3])


def _body(
    element_or_body: Union[InformationElement, bytes], expected_id: int, name: str
) -> bytes:
    if isinstance(element_or_body, InformationElement):
        if element_or_body.element_id != expected_id:
            raise FrameFormatError(
                "%s parser received element ID %d" % (name, element_or_body.element_id)
            )
        return element_or_body.data
    return bytes(element_or_body)


def _suite_list(cursor: _Cursor, count: int, label: str) -> tuple:
    if count == 0:
        raise FrameFormatError("%s contains an empty %s list" % (cursor.context, label))
    # Checking before iteration also bounds attacker-controlled count values.
    if count > cursor.remaining // 4:
        raise FrameFormatError(
            "%s %s count %d exceeds remaining data" % (cursor.context, label, count)
        )
    return tuple(cursor.suite("%s suite" % label) for _ in range(count))


def parse_rsn(element_or_body: Union[InformationElement, bytes]) -> RSNInformation:
    """Parse the body of an RSN element (element ID 48)."""

    cursor = _Cursor(_body(element_or_body, int(ElementID.RSN), "RSN"), "RSN element")
    version = cursor.little_u16("version")
    if version != 1:
        raise FrameFormatError("unsupported RSN version %d" % version)
    group_cipher = cursor.suite("group cipher")
    pairwise_count = cursor.little_u16("pairwise cipher count")
    pairwise_ciphers = _suite_list(cursor, pairwise_count, "pairwise cipher")
    akm_count = cursor.little_u16("AKM count")
    akm_suites = _suite_list(cursor, akm_count, "AKM")

    capabilities = None
    pmkids: Tuple[bytes, ...] = ()
    group_management_cipher = None
    if cursor.remaining:
        capabilities = RSNCapabilities(cursor.little_u16("capabilities"))
    if cursor.remaining:
        pmkid_count = cursor.little_u16("PMKID count")
        if pmkid_count > cursor.remaining // 16:
            raise FrameFormatError("RSN PMKID count exceeds remaining data")
        pmkids = tuple(cursor.take(16, "PMKID") for _ in range(pmkid_count))
    if cursor.remaining:
        if cursor.remaining != 4:
            raise FrameFormatError(
                "RSN element has %d unsupported trailing bytes" % cursor.remaining
            )
        group_management_cipher = cursor.suite("group management cipher")

    return RSNInformation(
        version=version,
        group_cipher=group_cipher,
        pairwise_ciphers=pairwise_ciphers,
        akm_suites=akm_suites,
        capabilities=capabilities,
        pmkids=pmkids,
        group_management_cipher=group_management_cipher,
    )


def parse_wpa(element_or_body: Union[InformationElement, bytes]) -> WPAInformation:
    """Parse the Wi-Fi Alliance legacy WPA vendor-specific element."""

    body = _body(element_or_body, int(ElementID.VENDOR_SPECIFIC), "WPA")
    cursor = _Cursor(body, "WPA element")
    if cursor.take(4, "OUI and vendor type") != WPA_VENDOR_PREFIX:
        raise FrameFormatError("vendor-specific element is not a WPA element")
    version = cursor.little_u16("version")
    if version != 1:
        raise FrameFormatError("unsupported WPA version %d" % version)
    group_cipher = cursor.suite("group cipher")
    pairwise_ciphers = _suite_list(
        cursor, cursor.little_u16("pairwise cipher count"), "pairwise cipher"
    )
    akm_suites = _suite_list(cursor, cursor.little_u16("AKM count"), "AKM")
    capabilities = None
    if cursor.remaining:
        if cursor.remaining != 2:
            raise FrameFormatError(
                "WPA element has %d unsupported trailing bytes" % cursor.remaining
            )
        capabilities = cursor.little_u16("capabilities")
    return WPAInformation(
        version, group_cipher, pairwise_ciphers, akm_suites, capabilities
    )


def build_rsn_element(
    *,
    group_cipher: SuiteSelector = RSN_CCMP_128,
    pairwise_ciphers: Sequence[SuiteSelector] = (RSN_CCMP_128,),
    akm_suites: Sequence[SuiteSelector] = (RSN_PSK,),
    capabilities: Optional[Union[int, RSNCapabilities]] = 0,
    pmkids: Sequence[bytes] = (),
    group_management_cipher: Optional[SuiteSelector] = None,
) -> InformationElement:
    """Build an RSN IE suitable for an association request."""

    if not pairwise_ciphers:
        raise ValueError("at least one pairwise cipher is required")
    if not akm_suites:
        raise ValueError("at least one AKM suite is required")
    if (
        len(pairwise_ciphers) > 0xFFFF
        or len(akm_suites) > 0xFFFF
        or len(pmkids) > 0xFFFF
    ):
        raise ValueError("RSN list count cannot exceed 65535")

    body = bytearray(struct.pack("<H", 1))
    body.extend(group_cipher.encode())
    body.extend(struct.pack("<H", len(pairwise_ciphers)))
    for selector in pairwise_ciphers:
        body.extend(selector.encode())
    body.extend(struct.pack("<H", len(akm_suites)))
    for selector in akm_suites:
        body.extend(selector.encode())

    if pmkids or group_management_cipher is not None:
        if capabilities is None:
            capabilities = 0
    if capabilities is not None:
        capability_value = (
            capabilities.value
            if isinstance(capabilities, RSNCapabilities)
            else int(capabilities)
        )
        if not 0 <= capability_value <= 0xFFFF:
            raise ValueError("RSN capabilities must fit in 16 bits")
        body.extend(struct.pack("<H", capability_value))
    if pmkids or group_management_cipher is not None:
        body.extend(struct.pack("<H", len(pmkids)))
        for pmkid in pmkids:
            pmkid_bytes = bytes(pmkid)
            if len(pmkid_bytes) != 16:
                raise ValueError("each PMKID must contain exactly 16 bytes")
            body.extend(pmkid_bytes)
    if group_management_cipher is not None:
        body.extend(group_management_cipher.encode())

    return InformationElement(ElementID.RSN, bytes(body))


def _has_rsn_akm(rsn: RSNInformation, suite_types: Iterable[int]) -> bool:
    wanted = set(suite_types)
    return any(
        suite.oui == RSN_OUI and suite.suite_type in wanted for suite in rsn.akm_suites
    )


def _classify(
    rsn: Optional[RSNInformation], wpa: Optional[WPAInformation], privacy: bool
) -> SecurityMode:
    if rsn is not None:
        has_sae = _has_rsn_akm(rsn, (8, 9))
        has_psk = _has_rsn_akm(rsn, (2, 4, 6))
        if has_sae and has_psk:
            return SecurityMode.WPA2_WPA3_PERSONAL
        if has_sae:
            return SecurityMode.WPA3_PERSONAL
        if _has_rsn_akm(rsn, (18,)):
            return SecurityMode.ENHANCED_OPEN
        if _has_rsn_akm(rsn, (11, 12, 13)):
            return SecurityMode.WPA3_ENTERPRISE
        if _has_rsn_akm(rsn, (1, 3, 5)):
            return SecurityMode.WPA2_ENTERPRISE
        if has_psk:
            return SecurityMode.WPA2_PERSONAL
        return SecurityMode.RSN_UNKNOWN
    if wpa is not None:
        if any(
            suite.oui == WPA_OUI and suite.suite_type == 2 for suite in wpa.akm_suites
        ):
            return SecurityMode.WPA_PERSONAL
        return SecurityMode.WPA_ENTERPRISE
    return SecurityMode.WEP_OR_UNKNOWN_PRIVACY if privacy else SecurityMode.OPEN


def parse_security_information(
    elements: Sequence[InformationElement], *, privacy_capability: bool = False
) -> SecurityInformation:
    """Parse security-related IEs and derive a conservative network mode."""

    rsn_elements = [
        element for element in elements if element.element_id == int(ElementID.RSN)
    ]
    wpa_elements = [
        element
        for element in elements
        if element.element_id == int(ElementID.VENDOR_SPECIFIC)
        and element.data.startswith(WPA_VENDOR_PREFIX)
    ]
    rsnx_elements = [
        element for element in elements if element.element_id == int(ElementID.RSNX)
    ]
    if len(rsn_elements) > 1 or len(wpa_elements) > 1 or len(rsnx_elements) > 1:
        raise FrameFormatError("duplicate security information element")
    rsn = parse_rsn(rsn_elements[0]) if rsn_elements else None
    wpa = parse_wpa(wpa_elements[0]) if wpa_elements else None
    rsnx = rsnx_elements[0].data if rsnx_elements else None
    privacy = bool(privacy_capability)
    mode = _classify(rsn, wpa, privacy)
    # RSNXE without the RSN element it extends is malformed or incomplete;
    # never downgrade that observation to "open".
    if rsnx is not None and rsn is None:
        mode = SecurityMode.RSN_UNKNOWN
    return SecurityInformation(
        privacy_capability=privacy,
        rsn=rsn,
        wpa=wpa,
        rsnx=rsnx,
        mode=mode,
    )
