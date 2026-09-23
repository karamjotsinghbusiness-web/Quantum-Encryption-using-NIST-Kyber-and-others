"""Helpers for exporting self-describing CipherShield benchmark records."""

from __future__ import annotations

import platform
from datetime import datetime, timezone
from importlib import metadata


DEPENDENCIES = ("cryptography", "matplotlib", "pqcrypto")


def runtime_environment() -> dict:
    """Return the runtime details needed to interpret a benchmark result."""
    versions = {}
    for package in DEPENDENCIES:
        try:
            versions[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            versions[package] = None
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "dependencies": versions,
    }


def build_benchmark_record(
    results: list[dict],
    iterations: int,
    *,
    generated_at: str | None = None,
    environment: dict | None = None,
) -> dict:
    """Build the versioned JSON record written by the desktop application."""
    if iterations < 1:
        raise ValueError("iterations must be at least 1")
    return {
        "schema_version": 1,
        "generated_at": generated_at
        or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "experiment": {
            "iterations_per_algorithm": iterations,
            "timing_clock": "time.perf_counter",
            "aggregation": "arithmetic mean",
        },
        "environment": environment or runtime_environment(),
        "results": results,
    }
