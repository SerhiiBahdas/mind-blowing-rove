# SPDX-License-Identifier: GPL-2.0-only
"""Validated bridge configuration and deliberately non-printable credentials."""

from __future__ import annotations

from dataclasses import dataclass
import getpass
import ipaddress
import os
from typing import Callable, Mapping, Optional

from mindrove_station.common import format_mac, mac_bytes


DEFAULT_PSK_ENV = "MINDROVE_PSK"


class SecretValue:
    """A small best-effort mutable credential container.

    Python and the process environment can retain copies that cannot be erased,
    so this is not a secure enclave.  It does prevent accidental ``repr``/log
    disclosure and lets the owned copy be overwritten promptly.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        encoded = value.encode("utf-8")
        if not (8 <= len(encoded) <= 63):
            raise ValueError("WPA2 passphrase must contain 8 through 63 UTF-8 octets")
        self._value = bytearray(encoded)

    def reveal(self) -> bytes:
        """Return a short-lived copy for a cryptographic implementation."""
        return bytes(self._value)

    def clear(self) -> None:
        for index in range(len(self._value)):
            self._value[index] = 0

    def __repr__(self) -> str:
        return "SecretValue(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True)
class BridgeConfig:
    """Non-secret settings for one exact MindRove BSS and local UDP sink."""

    ssid: str
    bssid: bytes
    channel: int
    loopback_host: str = "127.0.0.1"
    loopback_port: int = 4210
    auth_timeout: float = 1.0
    association_timeout: float = 1.5
    attempts: int = 4

    def __post_init__(self) -> None:
        encoded_ssid = self.ssid.encode("utf-8")
        if not encoded_ssid or len(encoded_ssid) > 32:
            raise ValueError("SSID must contain 1 through 32 UTF-8 octets")
        if not self.ssid.lower().startswith("mindrove"):
            raise ValueError("active station mode is restricted to a MindRove SSID")
        normalized_bssid = mac_bytes(self.bssid)
        if normalized_bssid[0] & 1:
            raise ValueError("BSSID must be an individual (unicast) address")
        object.__setattr__(self, "bssid", normalized_bssid)
        if not 1 <= self.channel <= 11:
            raise ValueError(
                "active station mode is restricted to US 2.4-GHz channels 1 through 11"
            )
        host = ipaddress.ip_address(self.loopback_host)
        if not host.is_loopback:
            raise ValueError("UDP sink must be a loopback address")
        if not 1 <= self.loopback_port <= 65535:
            raise ValueError("UDP port must be between 1 and 65535")
        if self.auth_timeout <= 0 or self.association_timeout <= 0:
            raise ValueError("authentication timeouts must be positive")
        if self.attempts <= 0:
            raise ValueError("attempt count must be positive")

    @classmethod
    def from_strings(
        cls,
        *,
        ssid: str,
        bssid: str,
        channel: int,
        loopback_host: str = "127.0.0.1",
        loopback_port: int = 4210,
    ) -> "BridgeConfig":
        return cls(
            ssid=ssid,
            bssid=mac_bytes(bssid),
            channel=channel,
            loopback_host=loopback_host,
            loopback_port=loopback_port,
        )

    @property
    def bssid_text(self) -> str:
        return format_mac(self.bssid)


def load_passphrase(
    *,
    environment: Optional[Mapping[str, str]] = None,
    env_name: str = DEFAULT_PSK_ENV,
    prompt: Callable[[str], str] = getpass.getpass,
) -> SecretValue:
    """Read a passphrase from one named environment entry or a hidden prompt.

    There is intentionally no command-line passphrase input: argv is commonly
    visible to process inspection and shell history.
    """

    source = os.environ if environment is None else environment
    value = source.get(env_name)
    if value is None:
        value = prompt("MindRove WPA2 passphrase: ")
    if not value:
        raise ValueError("MindRove WPA2 passphrase is empty")
    return SecretValue(value)
