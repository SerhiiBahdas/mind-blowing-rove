# SPDX-License-Identifier: GPL-2.0-only
"""Live, user-space MindRove station orchestration.

Importing this package never imports wifit3, opens USB, or transmits.  Hardware
access is isolated behind :class:`Wifit3StationRadio.open_exact`.
"""

from .config import BridgeConfig, SecretValue, load_passphrase
from .dhcp import DHCPError, DHCPLease, DHCPOffer, MindRoveDHCPClient
from .radio import (
    AdapterNotFoundError,
    RadioError,
    TargetFrameQueue,
    TuneError,
    TuneRetry,
    Wifit3StationRadio,
)
from .payload import MindRoveSample, parse_datagram, parse_record
from .session import (
    AccessPointProfile,
    AssociationError,
    LoopbackUdpSink,
    StationExchange,
    StationOrchestrator,
)
from .wpa2_provider import (
    DHCPTimeout,
    DefaultWPA2Handshake,
    SecureMindRoveDataPlane,
    WPA2Timeout,
)

__all__ = [
    "AccessPointProfile",
    "AdapterNotFoundError",
    "AssociationError",
    "BridgeConfig",
    "DHCPError",
    "DHCPLease",
    "DHCPOffer",
    "DHCPTimeout",
    "DefaultWPA2Handshake",
    "LoopbackUdpSink",
    "MindRoveSample",
    "MindRoveDHCPClient",
    "RadioError",
    "SecretValue",
    "SecureMindRoveDataPlane",
    "StationExchange",
    "StationOrchestrator",
    "TargetFrameQueue",
    "TuneError",
    "TuneRetry",
    "Wifit3StationRadio",
    "WPA2Timeout",
    "load_passphrase",
    "parse_datagram",
    "parse_record",
]
