# SPDX-License-Identifier: GPL-2.0-only
"""Decode the fixed MindRove ARB/ARC EXG UDP payload.

The Wi-Fi firmware sends two 108-byte samples in every 216-byte UDP datagram.
All multi-byte fields are little-endian.  The conversion factors here match
MindRove SDK 5.x and the decoder bundled with MindRove Connect 2.10.0.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct


MINDROVE_RECORD_SIZE = 108
MINDROVE_DATAGRAM_SIZE = 216
SAMPLES_PER_DATAGRAM = 2

EXG_UV_PER_LSB = 0.045
ACCEL_G_PER_LSB = 0.000061035
GYRO_DPS_PER_LSB = 0.01526

_RECORD = struct.Struct("<8i10iII3i3iI")
assert _RECORD.size == MINDROVE_RECORD_SIZE


@dataclass(frozen=True)
class MindRoveSample:
    """One decoded EXG/IMU sample from a MindRove Wi-Fi datagram."""

    exg_uv: tuple[float, ...]
    resistance_raw: tuple[int, ...]
    battery_millivolts: int
    battery_percent: float
    trigger: int
    accel_g: tuple[float, float, float]
    gyro_dps: tuple[float, float, float]
    measurement_number: int


def parse_record(record: bytes) -> MindRoveSample:
    """Decode exactly one 108-byte MindRove EXG/IMU record."""

    value = bytes(record)
    if len(value) != MINDROVE_RECORD_SIZE:
        raise ValueError("MindRove sample record must be exactly 108 bytes")

    fields = _RECORD.unpack(value)
    exg_raw = fields[0:8]
    resistance_raw = fields[8:18]
    battery_mv = fields[18]
    trigger = fields[19]
    accel_raw = fields[20:23]
    gyro_raw = fields[23:26]
    measurement_number = fields[26]

    return MindRoveSample(
        exg_uv=tuple(sample * EXG_UV_PER_LSB for sample in exg_raw),
        resistance_raw=tuple(resistance_raw),
        battery_millivolts=battery_mv,
        battery_percent=((battery_mv / 1000.0) - 2.8) * 100.0 / 1.45,
        trigger=trigger,
        accel_g=tuple(sample * ACCEL_G_PER_LSB for sample in accel_raw),  # type: ignore[arg-type]
        gyro_dps=tuple(sample * GYRO_DPS_PER_LSB for sample in gyro_raw),  # type: ignore[arg-type]
        measurement_number=measurement_number,
    )


def parse_datagram(payload: bytes) -> tuple[MindRoveSample, MindRoveSample]:
    """Decode one complete 216-byte MindRove UDP datagram."""

    value = bytes(payload)
    if len(value) != MINDROVE_DATAGRAM_SIZE:
        raise ValueError("MindRove EXG datagram must be exactly 216 bytes")
    first = parse_record(value[:MINDROVE_RECORD_SIZE])
    second = parse_record(value[MINDROVE_RECORD_SIZE:])
    return first, second
