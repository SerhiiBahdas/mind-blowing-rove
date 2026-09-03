# SPDX-License-Identifier: GPL-2.0-only

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from tools.mindrove_bridge.validate_log import (
    ACCEL_COLUMNS,
    EMG_COLUMNS,
    GYRO_COLUMNS,
    REQUIRED_COLUMNS,
    format_validation,
    validate_saved_stream,
)


def write_log(path: Path, *, sample_count: int, active: bool = True) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=REQUIRED_COLUMNS, delimiter="\t")
        writer.writeheader()
        for index in range(sample_count):
            phase = index % 5 if active else 0
            row = {
                name: str(100000 + channel * 100 + phase * 0.045)
                for channel, name in enumerate(EMG_COLUMNS)
            }
            row.update(
                {
                    name: str(0.5 + axis * 0.1 + phase * 0.000061035)
                    for axis, name in enumerate(ACCEL_COLUMNS)
                }
            )
            row.update(
                {
                    name: str(-1.0 + axis + phase * 0.01526)
                    for axis, name in enumerate(GYRO_COLUMNS)
                }
            )
            row["NumMeasurements"] = str(1000 + index)
            row["Timestamp"] = str(1_700_000_000 + index / 500)
            writer.writerow(row)


def test_active_500_hz_log_passes(tmp_path: Path) -> None:
    path = tmp_path / "stream.csv"
    write_log(path, sample_count=1000)

    summary = validate_saved_stream(path)

    assert summary.passed
    assert summary.sample_count == 1000
    assert summary.missing_samples == 0
    assert summary.delivery_ratio == 1.0
    assert summary.observed_rate_hz == pytest.approx(500.0, rel=1e-4)
    assert format_validation(summary).startswith("PASS\n")


def test_constant_signals_fail_activity_check(tmp_path: Path) -> None:
    path = tmp_path / "constant.csv"
    write_log(path, sample_count=500, active=False)

    summary = validate_saved_stream(path)

    assert not summary.passed
    assert any("EMG" in error for error in summary.errors)
    assert any("accelerometer" in error for error in summary.errors)
    assert any("gyroscope" in error for error in summary.errors)


def test_missing_columns_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.csv"
    path.write_text("Channel1\tTimestamp\n0\t1\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing required columns"):
        validate_saved_stream(path)
