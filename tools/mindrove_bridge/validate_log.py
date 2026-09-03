# SPDX-License-Identifier: GPL-2.0-only
"""Non-invasive validation of a TSV log saved by MindRove Connect 2.10.

The validator reads an already-written file.  It does not bind UDP/4210,
claim the USB adapter, or send anything to the device, so it can be run while
the bridge and vendor application continue streaming.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import math
from pathlib import Path
from typing import Iterable, Sequence

from .payload import ACCEL_G_PER_LSB, EXG_UV_PER_LSB, GYRO_DPS_PER_LSB


EMG_COLUMNS = tuple(f"Channel{index}" for index in range(1, 9))
ACCEL_COLUMNS = ("AccX", "AccY", "AccZ")
GYRO_COLUMNS = ("GyroX", "GyroY", "GyroZ")
SIGNAL_COLUMNS = EMG_COLUMNS + ACCEL_COLUMNS + GYRO_COLUMNS
METADATA_COLUMNS = ("NumMeasurements", "Timestamp")
REQUIRED_COLUMNS = SIGNAL_COLUMNS + METADATA_COLUMNS


@dataclass(frozen=True)
class SavedStreamValidation:
    """Evidence extracted from one MindRove Connect saved stream."""

    sample_count: int
    first_measurement: int
    last_measurement: int
    missing_samples: int
    delivery_ratio: float
    elapsed_seconds: float
    observed_rate_hz: float
    signal_spans: dict[str, float]
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors


def _integer_measurement(value: str, row_number: int) -> int:
    parsed = float(value)
    if not math.isfinite(parsed) or not parsed.is_integer():
        raise ValueError(f"row {row_number}: NumMeasurements is not an integer")
    return int(parsed)


def validate_saved_stream(
    path: Path | str,
    *,
    minimum_samples: int = 500,
) -> SavedStreamValidation:
    """Validate continuity, rate, and activity in a vendor-app TSV log."""

    if minimum_samples < 2:
        raise ValueError("minimum_samples must be at least two")
    source = Path(path)
    measurements: list[int] = []
    timestamps: list[float] = []
    minima = {name: math.inf for name in SIGNAL_COLUMNS}
    maxima = {name: -math.inf for name in SIGNAL_COLUMNS}

    with source.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        present = set(reader.fieldnames or ())
        missing_columns = [name for name in REQUIRED_COLUMNS if name not in present]
        if missing_columns:
            raise ValueError(
                "MindRove log is missing required columns: " + ", ".join(missing_columns)
            )
        for row_number, row in enumerate(reader, start=2):
            measurements.append(_integer_measurement(row["NumMeasurements"], row_number))
            timestamp = float(row["Timestamp"])
            if not math.isfinite(timestamp):
                raise ValueError(f"row {row_number}: Timestamp is not finite")
            timestamps.append(timestamp)
            for name in SIGNAL_COLUMNS:
                sample = float(row[name])
                if not math.isfinite(sample):
                    raise ValueError(f"row {row_number}: {name} is not finite")
                minima[name] = min(minima[name], sample)
                maxima[name] = max(maxima[name], sample)

    errors: list[str] = []
    count = len(measurements)
    if count < minimum_samples:
        errors.append(f"only {count} samples; need at least {minimum_samples}")
    if count < 2:
        first = last = measurements[0] if measurements else 0
        return SavedStreamValidation(
            sample_count=count,
            first_measurement=first,
            last_measurement=last,
            missing_samples=0,
            delivery_ratio=0.0,
            elapsed_seconds=0.0,
            observed_rate_hz=0.0,
            signal_spans={name: 0.0 for name in SIGNAL_COLUMNS},
            errors=tuple(errors),
        )

    deltas = [later - earlier for earlier, later in zip(measurements, measurements[1:])]
    if any(delta <= 0 for delta in deltas):
        errors.append("measurement counter is duplicated or moves backwards")
    missing_samples = sum(max(0, delta - 1) for delta in deltas)
    expected_samples = measurements[-1] - measurements[0] + 1
    delivery_ratio = count / expected_samples if expected_samples > 0 else 0.0
    if delivery_ratio < 0.95:
        errors.append(f"sample delivery ratio is only {delivery_ratio:.1%}")

    elapsed = timestamps[-1] - timestamps[0]
    observed_rate = (measurements[-1] - measurements[0]) / elapsed if elapsed > 0 else 0.0
    if not 450.0 <= observed_rate <= 550.0:
        errors.append(f"counter-derived sample rate is {observed_rate:.1f} Hz, not near 500 Hz")

    spans = {name: maxima[name] - minima[name] for name in SIGNAL_COLUMNS}
    groups: Iterable[tuple[str, Sequence[str], float]] = (
        ("EMG", EMG_COLUMNS, EXG_UV_PER_LSB),
        ("accelerometer", ACCEL_COLUMNS, ACCEL_G_PER_LSB),
        ("gyroscope", GYRO_COLUMNS, GYRO_DPS_PER_LSB),
    )
    for group_name, names, quantum in groups:
        inactive = [name for name in names if spans[name] < quantum * 0.9]
        if inactive:
            errors.append(f"{group_name} fields show no sample-level activity: {', '.join(inactive)}")

    return SavedStreamValidation(
        sample_count=count,
        first_measurement=measurements[0],
        last_measurement=measurements[-1],
        missing_samples=missing_samples,
        delivery_ratio=delivery_ratio,
        elapsed_seconds=elapsed,
        observed_rate_hz=observed_rate,
        signal_spans=spans,
        errors=tuple(errors),
    )


def _group_span(summary: SavedStreamValidation, names: Sequence[str]) -> str:
    spans = [summary.signal_spans[name] for name in names]
    return f"{min(spans):.6f}..{max(spans):.6f}"


def format_validation(summary: SavedStreamValidation) -> str:
    """Format a compact, non-sensitive validation report."""

    lines = [
        "PASS" if summary.passed else "FAIL",
        (
            f"samples={summary.sample_count} rate={summary.observed_rate_hz:.2f} Hz "
            f"delivery={summary.delivery_ratio:.3%} missing={summary.missing_samples}"
        ),
        f"EMG channel spans (uV): {_group_span(summary, EMG_COLUMNS)}",
        f"accelerometer axis spans (g): {_group_span(summary, ACCEL_COLUMNS)}",
        f"gyroscope axis spans (dps): {_group_span(summary, GYRO_COLUMNS)}",
    ]
    lines.extend(f"error: {error}" for error in summary.errors)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="MindRove Connect .csv/TSV log")
    parser.add_argument("--minimum-samples", type=int, default=500)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary = validate_saved_stream(args.log, minimum_samples=args.minimum_samples)
    print(format_validation(summary))
    return 0 if summary.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
