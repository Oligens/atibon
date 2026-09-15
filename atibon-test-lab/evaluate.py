#!/usr/bin/env python3
"""Evaluate ATIBON Test Lab results and calculate the official ADES weighting.

ADES is a 0-100 weighted score. Component inputs are normalized to 0-100 before
applying the official weights. Missing evidence is never silently converted to 0.
"""
from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

ADES_WEIGHTS = {
    "detection": 0.30,
    "prevention": 0.25,
    "confinement": 0.15,
    "evasion_resistance": 0.10,
    "recovery": 0.10,
    "auditability": 0.10,
}

CATEGORIES = (
    (0, 49.999999, "insuffisant"),
    (50, 69.999999, "expérimental"),
    (70, 84.999999, "robuste"),
    (85, 94.999999, "très robuste"),
    (95, float("inf"), "niveau exceptionnel"),
)


def p95(values):
    values = sorted(v for v in values if v is not None)
    return None if not values else values[min(len(values) - 1, int((len(values) - 1) * 0.95))]


def mean(values):
    values = [v for v in values if v is not None]
    return statistics.fmean(values) if values else None


def rate(numerator: int, denominator: int) -> float | None:
    return (100.0 * numerator / denominator) if denominator else None


def classify_ades(score: float) -> str:
    for low, high, label in CATEGORIES:
        if low <= score <= high:
            return label
    raise ValueError(f"score ADES hors plage: {score}")


def calculate_ades(components: dict[str, float]) -> dict:
    """Apply the official ADES weights to six 0-100 component scores.

    The weighting is fixed: 30/25/15/10/10/10. Inputs outside 0-100 are
    rejected instead of being silently clipped.
    """
    missing = [name for name in ADES_WEIGHTS if name not in components]
    if missing:
        raise ValueError("composantes ADES manquantes: " + ", ".join(missing))
    invalid = {k: v for k, v in components.items() if not 0 <= float(v) <= 100}
    if invalid:
        raise ValueError(f"composantes ADES hors plage 0-100: {invalid}")

    contributions = {
        name: float(components[name]) * weight
        for name, weight in ADES_WEIGHTS.items()
    }
    score = round(sum(contributions.values()), 2)
    return {
        "score": score,
        "classification": classify_ades(score),
        "components": {k: round(float(components[k]), 2) for k in ADES_WEIGHTS},
        "weights_pct": {k: int(weight * 100) for k, weight in ADES_WEIGHTS.items()},
        "weighted_contributions": {k: round(v, 2) for k, v in contributions.items()},
    }


def derive_components(samples: list[dict], counts: dict) -> dict[str, float]:
    """Derive ADES components only from evidence represented by Lab samples.

    Observable mappings used by this benchmark:
    - detection: TPR = TP / (TP + FN)
    - prevention: blocked expected attacks / expected attacks
    - confinement: blocked attacks / detected attacks
    - evasion_resistance: 1 - FN / expected attacks
    - recovery: share of attack samples with a recorded recovery time
    - auditability: share of samples containing the complete required audit fields

    These mappings operationalize the six ADES dimensions for the Lab; the
    official part implemented here is the 30/25/15/10/10/10 weighting.
    """
    attacks = counts["TP"] + counts["FN"]
    detected = sum(1 for s in samples if s.get("true_positive") == 1)
    blocked = sum(1 for s in samples if s.get("blocking_time_ms") is not None and s.get("true_positive") == 1)
    expected_attack_samples = sum(1 for s in samples if s.get("false_negative") == 1 or s.get("true_positive") == 1)
    recovery_recorded = sum(1 for s in samples if s.get("recovery_time_ms") is not None and s.get("true_positive") == 1)
    audit_fields = (
        "vector", "repetition", "true_positive", "false_positive", "false_negative",
        "detection_time_ms", "blocking_time_ms", "cpu_overhead_pct",
        "memory_overhead_mb", "network_latency_ms", "recovery_time_ms",
    )
    auditable = sum(1 for s in samples if all(field in s for field in audit_fields))
    total = len(samples)

    if not attacks:
        raise ValueError("aucun échantillon d'attaque exploitable pour calculer ADES")

    return {
        "detection": rate(counts["TP"], attacks) or 0.0,
        "prevention": rate(blocked, expected_attack_samples) or 0.0,
        "confinement": rate(blocked, detected) if detected else 0.0,
        "evasion_resistance": rate(attacks - counts["FN"], attacks) or 0.0,
        "recovery": rate(recovery_recorded, detected) if detected else 0.0,
        "auditability": rate(auditable, total) if total else 0.0,
    }


def stats(samples, key):
    vals = [s[key] for s in samples if s.get(key) is not None]
    return {
        "n": len(vals),
        "mean": statistics.fmean(vals) if vals else None,
        "median": statistics.median(vals) if vals else None,
        "p95": p95(vals),
    }


def build_report(data: dict, source: str) -> dict:
    samples = data["samples"]
    tp = sum(int(s.get("true_positive", 0)) for s in samples)
    fp = sum(int(s.get("false_positive", 0)) for s in samples)
    fn = sum(int(s.get("false_negative", 0)) for s in samples)
    counts = {"TP": tp, "FP": fp, "FN": fn}
    components = derive_components(samples, counts)
    ades = calculate_ades(components)

    return {
        "schema_version": "1.1",
        "source": source,
        "ades": ades,
        "counts": counts,
        "rates": {
            "true_positive_rate": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / sum(1 for s in samples if s.get("false_positive") is not None) if samples else None,
            "false_negative_rate": fn / (tp + fn) if tp + fn else None,
        },
        "timing": {k: stats(samples, k) for k in (
            "detection_time_ms", "blocking_time_ms", "network_latency_ms", "recovery_time_ms")},
        "overhead": {k: stats(samples, k) for k in ("cpu_overhead_pct", "memory_overhead_mb")},
        "reproducibility": {
            "mode": data.get("mode"),
            "repetitions": data.get("repetitions"),
            "environment": data.get("environment"),
            "vectors": data.get("vectors", []),
        },
    }


def main():
    ap = argparse.ArgumentParser(description="Calculate ADES from ATIBON Test Lab results")
    ap.add_argument("results", help="raw Lab JSON")
    ap.add_argument("--output", default="evaluation.json")
    args = ap.parse_args()

    data = json.loads(Path(args.results).read_text(encoding="utf-8"))
    report = build_report(data, args.results)
    Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    ades = report["ades"]
    print(f"ADES: {ades['score']:.2f}/100 — {ades['classification']}")
    for name, score in ades["components"].items():
        print(f"  {name}: {score:.2f}/100 ({ades['weights_pct'][name]}%)")


if __name__ == "__main__":
    main()
