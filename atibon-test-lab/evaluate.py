#!/usr/bin/env python3
"""Evaluate raw ATIBON Test Lab JSON without changing the raw samples."""
from __future__ import annotations
import argparse, json, statistics


def p95(values):
    values = sorted(v for v in values if v is not None)
    return None if not values else values[min(len(values)-1, int((len(values)-1)*0.95))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--output", default="evaluation.json")
    args = ap.parse_args()
    data = json.load(open(args.results, encoding="utf-8"))
    samples = data["samples"]
    tp = sum(s["true_positive"] for s in samples)
    fp = sum(s["false_positive"] for s in samples)
    fn = sum(s["false_negative"] for s in samples)
    attack = tp + fn
    benign = fp

    def stats(key):
        vals = [s[key] for s in samples if s.get(key) is not None]
        return {
            "n": len(vals),
            "mean": statistics.fmean(vals) if vals else None,
            "median": statistics.median(vals) if vals else None,
            "p95": p95(vals),
        }

    report = {
        "schema_version": "1.0",
        "source": args.results,
        "counts": {"TP": tp, "FP": fp, "FN": fn},
        "rates": {
            "true_positive_rate": tp / attack if attack else None,
            "false_positive_rate": fp / benign if benign else None,
            "false_negative_rate": fn / attack if attack else None,
        },
        "timing": {k: stats(k) for k in ("detection_time_ms", "blocking_time_ms", "network_latency_ms", "recovery_time_ms")},
        "overhead": {k: stats(k) for k in ("cpu_overhead_pct", "memory_overhead_mb")},
        "reproducibility": {
            "mode": data.get("mode"),
            "repetitions": data.get("repetitions"),
            "environment": data.get("environment"),
            "vectors": data.get("vectors", []),
        },
    }
    json.dump(report, open(args.output, "w", encoding="utf-8"), indent=2)
    print(json.dumps(report["rates"], indent=2))

if __name__ == "__main__":
    main()
