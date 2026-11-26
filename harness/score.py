"""Scores every run under runs/ and prints one Markdown table.

One row per analyser, per condition and model, and per harness stage.
Recall carries a 95% Wilson interval. For each model, McNemar's exact test
compares "llm" with the harness on the vulnerable programs both runs cover.

  python -m harness.score
"""

from __future__ import annotations

import json
import math
import sys

from harness import castle
from harness.analyze import RUNS
from harness.normalize import PARSERS


def wilson(k: int, n: int, z: float = 1.96) -> str:
    if not n:
        return "n/a"
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return f"{100 * max(0.0, centre - half):.0f}-{100 * min(1.0, centre + half):.0f}%"


def mcnemar(b: int, c: int) -> float:
    """Exact two-sided p-value on the b and c discordant pairs."""
    n = b + c
    if not n:
        return 1.0
    tail = 0
    for k in range(min(b, c) + 1):
        tail += math.comb(n, k)
    return min(1.0, 2 * tail / 2 ** n)


def row(name: str, tests: list[dict], findings: list[list[dict]], groups: dict, records: list[dict]) -> tuple:
    results = []
    for test, found in zip(tests, findings, strict=True):
        results.append(castle.judge(test, found, groups))
    s = castle.score(tests, results)
    precision = s["tp"] / (s["tp"] + s["fp"]) if s["tp"] + s["fp"] else 0.0
    recall = s["tp"] / (s["tp"] + s["fn"]) if s["tp"] + s["fn"] else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    tokens = 0
    seconds = 0.0
    for record in records:
        seconds += record.get("seconds", 0)
        for call in record.get("trace", []):
            tokens += call["prompt_tokens"] + call["completion_tokens"]
    line = (f"| {name} | {len(tests)} | {s['score']} | {s['tp']} | {s['fn']} | {s['fp']} | {s['tn']} | "
            f"{precision:.2f} | {recall:.2f} ({wilson(s['tp'], s['tp'] + s['fn'])}) | {f1:.2f} | "
            f"{tokens} | {seconds:.0f} |")
    return line, results


def main() -> int:
    dataset = castle.load()
    groups = castle.accepted_cwes(dataset)
    by_id = {}
    for t in dataset["tests"]:
        by_id[t["id"]] = t
    print("| run | programs | CASTLE score | TP | FN | FP | TN | precision | recall (95% CI) | F1 | tokens | s |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    detected: dict[tuple[str, str], dict[str, int]] = {}
    for condition in ("analyzers", "llm", "harness"):
        cond_dir = RUNS / condition
        if not cond_dir.is_dir():
            continue
        for label_dir in sorted(cond_dir.iterdir()):
            records = []
            for path in sorted(label_dir.glob("*.json")):
                records.append(json.loads(path.read_text(encoding="utf-8")))
            if not records:
                continue
            tests = []
            for r in records:
                tests.append(by_id[r["id"]])
            views = {"": []}
            if cond_dir.name == "harness":
                views = {" triage": [], " verifier": [], " checker": []}
            for r in records:
                for view in views:
                    stage = view.strip()
                    views[view].append(r["stages"].get(stage, []) if stage else r["findings"])
            for view, findings in views.items():
                for found in findings:
                    for f in found:
                        f.setdefault("severity", "")
                line, results = row(f"{cond_dir.name}/{label_dir.name}{view}", tests, findings, groups,
                                    records if view in ("", " checker") else [])
                print(line)
                hits = {}
                for test, res in zip(tests, results, strict=True):
                    if test["vulnerable"]:
                        hits[test["id"]] = res["tp"]
                detected[(cond_dir.name, label_dir.name)] = hits
            if cond_dir.name == "analyzers":
                for tool in PARSERS:
                    findings = []
                    for r in records:
                        mine = []
                        for f in r["per_tool"]:
                            if f["tool"] == tool:
                                mine.append(f)
                        findings.append(mine)
                    print(row(f"analyser/{tool}", tests, findings, groups, [])[0])
    print()
    for (cond, label), harness_hits in detected.items():
        if cond != "harness" or ("llm", label) not in detected:
            continue
        llm_hits = detected[("llm", label)]
        b = c = 0
        for pid, hit in harness_hits.items():
            if pid in llm_hits:
                b += 1 if hit and not llm_hits[pid] else 0
                c += 1 if llm_hits[pid] and not hit else 0
        print(f"McNemar {label}: harness only {b}, llm only {c}, p = {mcnemar(b, c):.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
