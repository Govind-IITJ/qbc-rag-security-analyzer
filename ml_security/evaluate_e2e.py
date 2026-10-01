from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from qbc_rag_security.analyzer import analyze_query

DATA = ROOT / "ml_security/data/dataset/QBC-RAG-1200-Query-Dataset/QBC-RAG_1200_test.csv"
OUT = ROOT / "ml_security/results/e2e_test_v5.json"
OUT.parent.mkdir(parents=True, exist_ok=True)


def main() -> None:
    df = pd.read_csv(DATA)
    results = []
    started = time.time()

    print(f"Running E2E evaluation: {len(df)} queries")

    for i, row in df.iterrows():
        result = analyze_query(str(row["query"]))

        results.append({
            "query": str(row["query"]),
            "expected": str(row["label"]),
            "result": result,
        })

        if (i + 1) % 10 == 0:
            OUT.write_text(
                json.dumps(results, indent=2),
                encoding="utf-8",
            )
            print(f"{i + 1}/{len(df)} saved")

    OUT.write_text(
        json.dumps(results, indent=2),
        encoding="utf-8",
    )

    actual = [x["result"]["decision"] for x in results]
    expected = [x["expected"] for x in results]

    print("Expected:", Counter(expected))
    print("Actual:", Counter(actual))
    print("Elapsed:", round(time.time() - started, 1), "seconds")
    print("Saved:", OUT)


if __name__ == "__main__":
    main()