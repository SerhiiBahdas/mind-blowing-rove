# SPDX-License-Identifier: GPL-2.0-only

from __future__ import annotations

import struct

import pytest

from tools.mindrove_bridge.payload import (
    ACCEL_G_PER_LSB,
    EXG_UV_PER_LSB,
    GYRO_DPS_PER_LSB,
    MINDROVE_DATAGRAM_SIZE,
    MINDROVE_RECORD_SIZE,
    parse_datagram,
    parse_record,
)


def record(*, offset: int, measurement_number: int) -> bytes:
    fields = (
        *range(offset, offset + 8),
        *range(1000 + offset, 1010 + offset),
        3500 + offset,
        7 + offset,
        16384 + offset,
        -8192 + offset,
        1000 + offset,
        100 + offset,
        -200 + offset,
        300 + offset,
        measurement_number,
    )
    return struct.pack("<8i10iII3i3iI", *fields)


def test_record_layout_and_sdk_scaling() -> None:
    raw = record(offset=0, measurement_number=123456)
    assert len(raw) == MINDROVE_RECORD_SIZE

    sample = parse_record(raw)
    assert sample.exg_uv == pytest.approx(tuple(i * EXG_UV_PER_LSB for i in range(8)))
    assert sample.resistance_raw == tuple(range(1000, 1010))
    assert sample.battery_millivolts == 3500
    assert sample.battery_percent == pytest.approx((3.5 - 2.8) * 100 / 1.45)
    assert sample.trigger == 7
    assert sample.accel_g == pytest.approx(
        tuple(i * ACCEL_G_PER_LSB for i in (16384, -8192, 1000))
    )
    assert sample.gyro_dps == pytest.approx(
        tuple(i * GYRO_DPS_PER_LSB for i in (100, -200, 300))
    )
    assert sample.measurement_number == 123456


def test_datagram_contains_two_consecutive_records() -> None:
    payload = record(offset=0, measurement_number=100) + record(
        offset=10, measurement_number=101
    )
    assert len(payload) == MINDROVE_DATAGRAM_SIZE

    first, second = parse_datagram(payload)
    assert first.measurement_number == 100
    assert second.measurement_number == 101
    assert first.exg_uv[0] == 0.0
    assert second.exg_uv[0] == pytest.approx(10 * EXG_UV_PER_LSB)
    assert first.accel_g != second.accel_g
    assert first.gyro_dps != second.gyro_dps


@pytest.mark.parametrize("length", [0, 107, 109])
def test_record_rejects_wrong_length(length: int) -> None:
    with pytest.raises(ValueError, match="108 bytes"):
        parse_record(bytes(length))


@pytest.mark.parametrize("length", [0, 108, 215, 217])
def test_datagram_rejects_wrong_length(length: int) -> None:
    with pytest.raises(ValueError, match="216 bytes"):
        parse_datagram(bytes(length))
