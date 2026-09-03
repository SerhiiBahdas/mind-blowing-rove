# SPDX-License-Identifier: GPL-2.0-only
"""CLI wiring for the built-in WPA2/CCMP MindRove station provider."""

from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import sys
from typing import Optional, Sequence

from mindrove_station.common import mac_bytes

from .config import BridgeConfig, DEFAULT_PSK_ENV, load_passphrase
from .radio import Wifit3StationRadio
from .session import LoopbackUdpSink, StationOrchestrator
from .wpa2_provider import DefaultWPA2Handshake


def _channel(value: str) -> int:
    parsed = int(value, 10)
    if not 1 <= parsed <= 11:
        raise argparse.ArgumentTypeError(
            "must be a US 2.4-GHz channel from 1 through 11"
        )
    return parsed


def _port(value: str) -> int:
    parsed = int(value, 10)
    if not 1 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return parsed


def _station_mac(value: str) -> bytes:
    try:
        parsed = mac_bytes(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("must be a six-octet MAC address") from exc
    if parsed[0] & 1:
        raise argparse.ArgumentTypeError("must be an individual (unicast) address")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Connect exact USB 0bda:c811 to one MindRove WPA2 BSS while macOS's "
            "built-in Wi-Fi remains untouched."
        )
    )
    parser.add_argument("--ssid", required=True, help="exact MindRove SSID")
    parser.add_argument("--bssid", required=True, help="exact MindRove BSSID")
    parser.add_argument("--channel", required=True, type=_channel)
    parser.add_argument(
        "--station-mac",
        type=_station_mac,
        help=(
            "station MAC to reuse (for a board whose DHCP/stream target is tied "
            "to a previous client); default is a fresh local address"
        ),
    )
    parser.add_argument(
        "--loopback-host", default="127.0.0.1", help="local-only UDP destination"
    )
    parser.add_argument("--loopback-port", default=4210, type=_port)
    parser.add_argument(
        "--psk-env",
        default=DEFAULT_PSK_ENV,
        metavar="NAME",
        help="environment variable containing the passphrase; hidden prompt if absent",
    )
    parser.add_argument(
        "--handshake-timeout",
        default=8.0,
        type=float,
        metavar="SECONDS",
        help="four-way-handshake timeout (default: 8)",
    )
    return parser


def _local_station_mac() -> bytes:
    # Locally administered, unicast address; never reuse the built-in Wi-Fi MAC.
    return bytes((0x02,)) + secrets.token_bytes(5)


async def _run(args: argparse.Namespace) -> None:
    config = BridgeConfig.from_strings(
        ssid=args.ssid,
        bssid=args.bssid,
        channel=args.channel,
        loopback_host=args.loopback_host,
        loopback_port=args.loopback_port,
    )
    passphrase = load_passphrase(environment=os.environ, env_name=args.psk_env)
    # Minimize the lifetime of a credential supplied through the environment.
    # The default hidden prompt avoids placing it there at all.
    os.environ.pop(args.psk_env, None)
    sink = None
    orchestrator = None
    try:
        sink = LoopbackUdpSink(config.loopback_host, config.loopback_port)
        radio = Wifit3StationRadio.open_exact(
            bssid=config.bssid,
            station_mac=args.station_mac or _local_station_mac(),
        )
        orchestrator = StationOrchestrator(
            radio,
            config,
            status=lambda message: print("status: " + message, file=sys.stderr),
        )
        handshake = DefaultWPA2Handshake(timeout=args.handshake_timeout)
        await orchestrator.run(
            passphrase=passphrase,
            handshake=handshake,
            packet_callback=sink,
        )
    finally:
        passphrase.clear()
        if sink is not None:
            sink.close()
        if orchestrator is not None:
            await orchestrator.close()


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(None if argv is None else list(argv))
    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        # Credential-handling code can fail with an exception that embeds its
        # input. Never echo exception text on this secret-bearing path.
        print("error: bridge stopped (%s)" % type(exc).__name__, file=sys.stderr)
        return 1
    return 0
