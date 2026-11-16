"""Run the comparative detection evaluation and save the results.

    python scripts/evaluate_detection.py [--variants 5]

Prints the metrics table and writes reports/evaluation-<timestamp>.json and
.csv. Uses only synthetic generated data; no database is read or changed.
"""
import argparse
import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.analysis_service import asset_contexts  # noqa: E402
from app.evaluation import run_evaluation  # noqa: E402


def fmt(value):
    return "-" if value is None else (f"{value:.3f}" if isinstance(value, float) else str(value))


def main() -> int:
    parser = argparse.ArgumentParser(description="AegisGate comparative detection evaluation.")
    parser.add_argument("--variants", type=int, default=5, help="variants per case family (1-10)")
    args = parser.parse_args()

    result = run_evaluation(asset_contexts(), args.variants)
    print(f"{result['case_count']} cases ({result['malicious_cases']} malicious, "
          f"{result['benign_cases']} benign) - {result['data_provenance']}\n")
    columns = ("approach", "true_positives", "false_positives", "true_negatives", "false_negatives",
               "precision", "recall", "false_positive_rate", "f1", "median_latency_seconds")
    print(" | ".join(columns))
    for row in result["metrics"]:
        print(" | ".join(fmt(row[c]) for c in columns))
    comparison = result["allowlist_comparison"]
    print("\nWith the approved-activity allowlist:")
    print(" | ".join(columns))
    for row in comparison["metrics"]:
        print(" | ".join(fmt(row[c]) for c in columns))
    after = {row["family"]: row for row in comparison["by_family"]}
    print("\nFlagged cases per family (rule / anomaly / combined), without -> with allowlist:")
    for row in result["by_family"]:
        a = after[row["family"]]
        print(f"  {row['family']:26s} {row['label']:9s} {row['rule_based']}/{row['anomaly_based']}/"
              f"{row['combined']} -> {a['rule_based']}/{a['anomaly_based']}/{a['combined']} of {row['cases']}")

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "reports"
    out.mkdir(exist_ok=True)
    (out / f"evaluation-{stamp}.json").write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    with (out / f"evaluation-{stamp}.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["allowlist", *columns])
        writer.writerows([["without", *[row[c] for c in columns]] for row in result["metrics"]])
        writer.writerows([["with", *[row[c] for c in columns]] for row in comparison["metrics"]])
    print(f"\nSaved reports/evaluation-{stamp}.json and .csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
