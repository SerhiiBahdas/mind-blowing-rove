# SPDX-License-Identifier: GPL-2.0-only
"""Pure beacon filtering and reporting helpers.

This module deliberately has no USB or wifit3 imports, which keeps its privacy
boundary and frame parsing testable without an adapter attached.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable, Optional


_BSSID_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")

# Channels exposed by wifit3 v0.1.5's Rtl8821cuDkmsDriver. DFS channels are
# intentionally absent from that upstream API.
RTL8821CU_CHANNELS = frozenset(
    (*range(1, 15), 36, 40, 44, 48, 149, 153, 157, 161, 165)
)
DEFAULT_CHANNELS = tuple(range(1, 12))


class InputError(ValueError):
    """A rejected target selector or channel list."""


def normalize_bssid(value: Optional[str]) -> Optional[str]:
    """Validate and normalize an optional colon-delimited BSSID."""
    if value is None:
        return None
    if not _BSSID_RE.fullmatch(value):
        raise InputError("BSSID must contain six colon-delimited hexadecimal octets")
    return value.lower()


def parse_channels(spec: str) -> tuple[int, ...]:
    """Parse ``1-11,36,40`` into unique supported channels in input order."""
    channels: list[int] = []
    try:
        for raw_part in spec.split(","):
            part = raw_part.strip()
            if not part:
                raise InputError("channel list contains an empty item")
            if "-" in part:
                bounds = part.split("-")
                if len(bounds) != 2:
                    raise InputError(f"invalid channel range: {part!r}")
                first, last = (int(value.strip(), 10) for value in bounds)
                if first > last:
                    raise InputError(f"descending channel range: {part!r}")
                requested: Iterable[int] = range(first, last + 1)
            else:
                requested = (int(part, 10),)
            for channel in requested:
                if channel not in RTL8821CU_CHANNELS:
                    raise InputError(
                        f"channel {channel} is not supported by the pinned RTL8821CU driver"
                    )
                if channel not in channels:
                    channels.append(channel)
    except ValueError as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError(f"invalid channel list: {spec!r}") from exc

    if not channels:
        raise InputError("at least one channel is required")
    return tuple(channels)


def _information_elements(frame: bytes) -> tuple[bytes, ...]:
    """Return complete beacon IEs, stopping before a malformed/truncated tail."""
    if len(frame) < 36:
        return ()
    elements: list[bytes] = []
    offset = 36  # 24-byte management header + 12-byte beacon fixed fields
    while offset + 2 <= len(frame):
        length = frame[offset + 1]
        end = offset + 2 + length
        if end > len(frame):
            break
        elements.append(bytes(frame[offset:end]))
        offset = end
    return tuple(elements)


def _security_elements(frame: bytes) -> list[dict[str, Any]]:
    """Keep only standard RSN/RSNXE and Microsoft WPA/WPS vendor IEs."""
    security: list[dict[str, Any]] = []
    for element in _information_elements(frame):
        element_id = element[0]
        data = element[2:]
        name: Optional[str] = None
        if element_id == 48:
            name = "RSN"
        elif element_id == 244:
            name = "RSNXE"
        elif element_id == 221 and data.startswith(b"\x00\x50\xf2\x01"):
            name = "WPA"
        elif element_id == 221 and data.startswith(b"\x00\x50\xf2\x04"):
            name = "WPS"
        if name is not None:
            security.append(
                {
                    "name": name,
                    "element_id": element_id,
                    # Preserve the element ID and length as well as its body.
                    "hex": element.hex(),
                }
            )
    return security


def _privacy_capability(frame: bytes) -> bool:
    """Read the beacon capability-information Privacy bit when present."""
    return len(frame) >= 36 and bool(int.from_bytes(frame[34:36], "little") & 0x0010)


@dataclass(frozen=True)
class Target:
    """Exact target selectors; unrelated beacon identities never leave the filter."""

    ssid: str
    bssid: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.ssid:
            raise InputError("SSID must not be empty")
        if len(self.ssid.encode("utf-8")) > 32:
            raise InputError("SSID must be at most 32 UTF-8 bytes")
        object.__setattr__(self, "bssid", normalize_bssid(self.bssid))

    def matches(self, packet: Any) -> bool:
        """Accept only a beacon for the exact requested SSID and optional BSSID."""
        if getattr(packet, "type", None) != "beacon":
            return False
        if getattr(packet, "ssid", None) != self.ssid:
            return False
        packet_bssid = str(getattr(packet, "bssid", "")).lower()
        return self.bssid is None or packet_bssid == self.bssid


def beacon_report(packet: Any, observed_channel: int) -> dict[str, Any]:
    """Build the intentionally narrow, JSON-safe report for a matched beacon."""
    frame = bytes(getattr(packet, "raw", b""))
    advertised_channel = getattr(packet, "channel", None)
    channel = advertised_channel if isinstance(advertised_channel, int) else observed_channel

    return {
        "ssid": str(packet.ssid),
        "bssid": str(packet.bssid).lower(),
        "channel": channel,
        "security": {
            "label": str(getattr(packet, "encryption", "UNKNOWN")),
            "privacy": _privacy_capability(frame),
            "pairwise_cipher": getattr(packet, "pairwise_cipher", None),
            "akms": list(getattr(packet, "akms", ()) or ()),
            "akm_suites": list(getattr(packet, "akm_suites", ()) or ()),
            "wpa3": bool(getattr(packet, "wpa3", False)),
            "transition_mode": bool(getattr(packet, "transition_mode", False)),
            "pmf_capable": bool(getattr(packet, "pmf_capable", False)),
            "pmf_required": bool(getattr(packet, "pmf_required", False)),
            "beacon_protection": bool(getattr(packet, "beacon_protection", False)),
        },
        "security_ies": _security_elements(frame),
    }

