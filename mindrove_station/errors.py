# SPDX-License-Identifier: GPL-2.0-only
"""Exceptions raised while handling IEEE 802.11 protocol data."""


class FrameFormatError(ValueError):
    """Raised when a frame is truncated, inconsistent, or unsupported."""


class IntegrityError(ValueError):
    """Raised when an authenticated frame fails its integrity check."""


class ReplayError(ValueError):
    """Raised when a protected frame or handshake counter is replayed."""


class HandshakeError(ValueError):
    """Raised when a WPA handshake message violates the expected state."""


class CryptoDependencyError(RuntimeError):
    """Raised when optional packet crypto support has not been installed."""
