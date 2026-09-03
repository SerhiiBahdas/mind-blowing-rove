# SPDX-License-Identifier: GPL-2.0-only
"""Passive beacon scanner for the exact MindRove RTL8821CU USB adapter."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any, Callable, Optional, Sequence

from .report import DEFAULT_CHANNELS, InputError, Target, beacon_report, parse_channels
from .wifit3_compat import apply_c811_no_bt_coexist_fix


USB_VENDOR_ID = 0x0BDA
USB_PRODUCT_ID = 0xC811
WIFIT3_VERSION = "0.1.5"
WIFIT3_COMMIT = "e1f449c0248a8ad1d4080975ca0368d3f44d75d6"


class PassiveOnlyViolation(RuntimeError):
    """An attempted use of a transmit-capable driver entry point."""


async def _transmit_forbidden(*_args: Any, **_kwargs: Any) -> bool:
    raise PassiveOnlyViolation("frame transmission is disabled by the passive scanner")


def disable_transmit_apis(driver: Any) -> None:
    """Fail closed if this tool accidentally reaches a wifit3 transmit API.

    Firmware upload still uses USB bulk-OUT during ``connect``; this guard blocks
    802.11 injection methods, not the USB operations needed to initialize silicon.
    """
    driver.inject_frame = _transmit_forbidden
    driver.inject_frame_slow_retry = _transmit_forbidden
    driver._inject_frame = _transmit_forbidden
    driver.enter_active_monitor = _transmit_forbidden


class ReceiveOnlyDriver:
    """Least-authority view of the four wifit3 operations used by this scanner."""

    def __init__(self, driver: Any):
        disable_transmit_apis(driver)
        self._driver = driver

    def register_rx_callback(self, callback: Callable[[Any], None]) -> None:
        self._driver.register_rx_callback(callback)

    def register_disconnect_callback(self, callback: Callable[[Exception], None]) -> None:
        self._driver.register_disconnect_callback(callback)

    async def connect(self) -> bool:
        return await self._driver.connect()

    async def set_channel(self, channel: int) -> bool:
        return await self._driver.set_channel(channel, scan=True)

    async def close(self) -> None:
        await self._driver.close()


def _open_exact_adapter() -> ReceiveOnlyDriver:
    """Open only 0bda:c811 and construct its pinned RTL8821CU driver."""
    try:
        import libusb_package
        import usb.core
        import wifit3
        from wifit3.chips.rtl8821cu_dkms import SUPPORTED_IDS, import_driver
    except ImportError as exc:
        raise RuntimeError(
            "pinned dependencies are missing; install requirements.txt in a Python 3.11+ venv"
        ) from exc

    if getattr(wifit3, "__version__", None) != WIFIT3_VERSION:
        raise RuntimeError(
            f"refusing unreviewed wifit3 version {getattr(wifit3, '__version__', None)!r}; "
            f"expected {WIFIT3_VERSION} ({WIFIT3_COMMIT})"
        )

    id_entry = next(
        (
            entry
            for entry in SUPPORTED_IDS
            if (entry.vid, entry.pid) == (USB_VENDOR_ID, USB_PRODUCT_ID)
        ),
        None,
    )
    if id_entry is None:
        raise RuntimeError("pinned wifit3 no longer claims the exact 0bda:c811 adapter")

    # v0.1.5 assumes every 8821CU board initialized Bluetooth coexistence.
    # The MindRove c811 EFUSE says otherwise; apply the provenance-recorded,
    # regression-tested two-condition compatibility fix before connect().
    apply_c811_no_bt_coexist_fix()

    backend = libusb_package.get_libusb1_backend()
    devices = list(
        usb.core.find(
            find_all=True,
            idVendor=USB_VENDOR_ID,
            idProduct=USB_PRODUCT_ID,
            backend=backend,
        )
        or ()
    )
    if not devices:
        raise RuntimeError("MindRove adapter 0bda:c811 was not found")
    if len(devices) != 1:
        raise RuntimeError(
            f"found {len(devices)} identical 0bda:c811 adapters; leave exactly one attached"
        )

    driver_class = import_driver()
    return ReceiveOnlyDriver(driver_class.from_usb_device(devices[0], id_entry))


async def scan(
    target: Target,
    channels: Sequence[int],
    dwell_seconds: float,
    passes: int,
) -> Optional[dict[str, Any]]:
    """Bring up one exact adapter and passively wait for a matching beacon."""
    driver = _open_exact_adapter()
    found = asyncio.Event()
    disconnected: list[Exception] = []
    result: list[dict[str, Any]] = []
    observed_channel = channels[0]

    def on_packet(packet: Any) -> None:
        if result or not target.matches(packet):
            return
        result.append(beacon_report(packet, observed_channel))
        found.set()

    def on_disconnect(error: Exception) -> None:
        disconnected.append(error)
        found.set()

    driver.register_rx_callback(on_packet)
    driver.register_disconnect_callback(on_disconnect)

    try:
        await driver.connect()
        for _ in range(passes):
            for channel in channels:
                if result:
                    return result[0]
                if disconnected:
                    raise RuntimeError(f"adapter disconnected: {disconnected[0]}")
                observed_channel = channel
                await driver.set_channel(channel)
                try:
                    await asyncio.wait_for(found.wait(), timeout=dwell_seconds)
                except TimeoutError:
                    continue
                if result:
                    return result[0]
                if disconnected:
                    raise RuntimeError(f"adapter disconnected: {disconnected[0]}")
        return None
    finally:
        await driver.close()


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value, 10)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _channel_argument(value: str) -> tuple[int, ...]:
    try:
        return parse_channels(value)
    except InputError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Passively scan beacons with exactly one Realtek 0bda:c811 adapter and emit "
            "only the requested MindRove network's identity/channel/security metadata."
        )
    )
    parser.add_argument(
        "--ssid",
        required=True,
        help="exact target MindRove SSID (case-sensitive; no wildcard scanning)",
    )
    parser.add_argument(
        "--bssid",
        help="optional exact target BSSID, e.g. 02:11:22:33:44:55",
    )
    parser.add_argument(
        "--channels",
        type=_channel_argument,
        default=DEFAULT_CHANNELS,
        metavar="LIST",
        help="comma/range list supported by wifit3 (default: 1-11)",
    )
    parser.add_argument(
        "--dwell",
        type=_positive_float,
        default=1.0,
        metavar="SECONDS",
        help="passive receive time per channel (default: 1.0)",
    )
    parser.add_argument(
        "--passes",
        type=_positive_int,
        default=2,
        metavar="COUNT",
        help="maximum passes across the channel list (default: 2)",
    )
    return parser


async def _run(args: argparse.Namespace) -> int:
    try:
        target = Target(args.ssid, args.bssid)
        report = await scan(target, args.channels, args.dwell, args.passes)
    except (InputError, PassiveOnlyViolation, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130

    if report is None:
        print("target beacon not observed; no network data emitted", file=sys.stderr)
        return 3
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        status = asyncio.run(_run(args))
    except KeyboardInterrupt:
        status = 130
    raise SystemExit(status)
