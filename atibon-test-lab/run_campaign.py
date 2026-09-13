#!/usr/bin/env python3
"""Safe, deterministic ATIBON defensive benchmark.

The runner emits synthetic security events; it never performs real attacks.
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path

VECTORS = [
    "reconnaissance", "scans", "brute-force", "credential-attacks", "web-attacks",
    "malware-simulation", "lateral-movement", "exfiltration-simulation",
    "abnormal-egress", "dns-abuse", "tls-anomalies", "api-abuse", "resource-exhaustion",
]

@dataclass(frozen=True)
class Scenario:
    vector: str
    event_type: str
    severity: float
    expected_detection: bool = True
    expected_blocking: bool = True

@dataclass
class Sample:
    vector: str
    repetition: int
    true_positive: int
    false_positive: int
    false_negative: int
    detection_time_ms: float | None
    blocking_time_ms: float | None
    cpu_overhead_pct: float | None
    memory_overhead_mb: float | None
    network_latency_ms: float | None
    recovery_time_ms: float | None


def scenarios() -> list[Scenario]:
    return [Scenario(v, f"synthetic.{v}", 0.90) for v in VECTORS]


def summarize(values: list[float | None]) -> dict[str, float | None]:
    clean = [v for v in values if v is not None]
    if not clean:
        return {"mean": None, "median": None, "p95": None}
    ordered = sorted(clean)
    idx = min(len(ordered) - 1, int((len(ordered) - 1) * 0.95))
    return {"mean": statistics.fmean(clean), "median": statistics.median(clean), "p95": ordered[idx]}


def run(repetitions: int, mode: str) -> dict:
    # Deterministic harness timings are intentionally synthetic. Integrators can
    # replace measure() with their authorized local ATIBON adapter.
    samples: list[Sample] = []
    baseline_cpu = 0.0
    baseline_mem = 0.0
    baseline_latency = 1.0
    for scenario in scenarios():
        for repetition in range(1, repetitions + 1):
            start = time.monotonic_ns()
            # Synthetic decision: high-confidence test vectors are expected to be detected.
            detected = scenario.severity >= 0.80
            blocked = detected and mode == "enforce"
            detect_ms = (time.monotonic_ns() - start) / 1_000_000
            block_ms = detect_ms if blocked else None
            # These are placeholders until a live authorized adapter supplies host counters.
            samples.append(Sample(
                scenario.vector, repetition,
                int(detected and scenario.expected_detection),
                int(not scenario.expected_detection and detected),
                int(scenario.expected_detection and not detected),
                detect_ms, block_ms, None, None, baseline_latency, None,
            ))

    def avg(name: str) -> dict:
        return summarize([getattr(s, name) for s in samples])

    return {
        "schema_version": "1.0",
        "mode": mode,
        "generated_at_epoch_s": time.time(),
        "environment": {"python": platform.python_version(), "os": platform.platform()},
        "repetitions": repetitions,
        "vectors": VECTORS,
        "counts": {
            "TP": sum(s.true_positive for s in samples),
            "FP": sum(s.false_positive for s in samples),
            "FN": sum(s.false_negative for s in samples),
        },
        "metrics": {k: avg(k) for k in (
            "detection_time_ms", "blocking_time_ms", "cpu_overhead_pct",
            "memory_overhead_mb", "network_latency_ms", "recovery_time_ms")},
        "samples": [asdict(s) for s in samples],
        "note": "Host CPU/memory/recovery metrics remain null until an authorized ATIBON adapter supplies real counters; null is not zero.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=["all", *VECTORS], default="all")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--mode", choices=["shadow", "enforce"], default="shadow")
    parser.add_argument("--output", default="results.json")
    args = parser.parse_args()
    if args.repetitions < 1 or args.repetitions > 1000:
        raise SystemExit("--repetitions must be between 1 and 1000")
    result = run(args.repetitions, args.mode)
    if args.scenario != "all":
        result["vectors"] = [args.scenario]
        result["samples"] = [s for s in result["samples"] if s["vector"] == args.scenario]
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"], indent=2))

if __name__ == "__main__":
    main()
