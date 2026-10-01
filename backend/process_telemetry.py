import argparse
import json
from pathlib import Path

from telemetry_pipeline import process_network_event


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Normalize, correlate, score, and recommend an access "
            "decision for Suricata or Zeek JSON telemetry."
        )
    )

    parser.add_argument(
        "inputs",
        nargs="+",
        help="One or more Suricata or Zeek JSON event files.",
    )

    parser.add_argument(
        "--output",
        default=None,
        help="Optional path for the JSON results file.",
    )

    args = parser.parse_args()
    results = []

    for input_name in args.inputs:
        input_path = Path(input_name)

        raw_event = json.loads(
            input_path.read_text(encoding="utf-8")
        )

        results.append(
            {
                "input_file": str(input_path),
                **process_network_event(raw_event),
            }
        )

    output = json.dumps(
        results,
        indent=2,
        ensure_ascii=False,
        default=str,
    )

    if args.output:
        output_path = Path(args.output)

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path.write_text(
            output + "\n",
            encoding="utf-8",
        )

        print(
            f"Processed {len(results)} event(s). "
            f"Results written to {output_path}."
        )
    else:
        print(output)


if __name__ == "__main__":
    main()