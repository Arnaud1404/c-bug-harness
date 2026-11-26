"""CASTLE-C250: loading, the LLM answer parser and the CASTLE score.

Ported from CASTLE-Source at 765376e (wrappers/llm/run.py and charts.ipynb)
so our numbers stay comparable with the paper. Departures are marked.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

CASTLE_DIR = Path(os.environ.get("CASTLE_DIR", Path(__file__).resolve().parent.parent / "data" / "castle"))

SCORING = {"tp": 5, "tn": 2, "fp": -1, "fn": 0}
TOPLIST_BONUS = 5
# MITRE 2024 Top 25, the list charts.ipynb ranks against.
TOP_25 = [79, 787, 89, 352, 22, 125, 78, 416, 862, 434, 94, 20, 77, 287, 269,
          502, 200, 863, 918, 119, 476, 798, 190, 400, 306]
# charts.ipynb keeps only these severities; tools without one report "".
RELEVANT = {"", "none", "warning", "error", "medium", "high", "critical", "portability"}
JSON_BLOCK = re.compile(r"```json(?P<json>[\s\S]*)```")


def load() -> dict:
    with open(CASTLE_DIR / "datasets" / "CASTLE-C250.json", encoding="utf-8") as f:
        return json.load(f)


def accepted_cwes(dataset: dict) -> dict[int, set[int]]:
    """CWE -> itself, its children and its parents, as charts.ipynb matches them."""
    groups = {0: set()}
    for cwe, entry in dataset["cwes"].items():
        group = {int(cwe)}
        for relative in entry["children"] + entry["parents"]:
            for key in relative:
                group.add(int(key))
        groups[int(cwe)] = group
    return groups


def parse_llm_report(code: str, report: str) -> list[dict]:
    """CASTLE's parse_report. Departure: it returns the input list, so findings
    with missing keys stayed in; this returns only the validated ones."""
    match = JSON_BLOCK.search(report)
    if not match:
        return []
    try:
        findings = json.loads(match.group("json"))
    except json.JSONDecodeError:
        return []
    if not isinstance(findings, list):
        return []
    lines = code.split("\n")
    cleaned = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        types = {"severity": str, "line": int, "cwe": int, "message": str, "line_content": str}
        valid = True
        for key, kind in types.items():
            if not isinstance(f.get(key), kind) or isinstance(f.get(key), bool):
                valid = False
        if not valid:
            continue
        line = min(max(f["line"], 1), len(lines))
        wanted = f["line_content"].strip()
        if lines[line - 1].strip() != wanted:
            # CASTLE moves the finding to the first line holding that content.
            for i, text in enumerate(lines):
                if text.strip() == wanted:
                    line = i + 1
                    break
        cleaned.append({"line": line, "cwe": f["cwe"], "severity": f["severity"], "message": f["message"]})
    return cleaned


def judge(test: dict, findings: list[dict], groups: dict[int, set[int]]) -> dict:
    """charts.ipynb validate_findings: one tp at most per program, every other
    finding is a fp. A finding matches on the line or on a related CWE."""
    kept = []
    for f in findings:
        if f.get("severity", "").lower() in RELEVANT:
            kept.append(f)
    if not kept and not test["vulnerable"]:
        return {"tp": 0, "fp": 0, "tn": 1, "fn": 0}
    matches = 0
    for f in kept:
        line_hit = f["line"] != 0 and f["line"] in test["lines"]
        if line_hit or f["cwe"] in groups[test["cwe"]]:
            matches += 1
    fp = len(kept) - matches
    if matches == 0 and test["vulnerable"]:
        return {"tp": 0, "fp": fp, "tn": 0, "fn": 1}
    if matches > 0:
        return {"tp": 1, "fp": fp, "tn": 0, "fn": 0}
    return {"tp": 0, "fp": fp, "tn": 0, "fn": 0}


def score(tests: list[dict], results: list[dict]) -> dict:
    """charts.ipynb castle(). Kept as written: the bonus test reads the running
    tp total, so after the first tp every Top 25 program earns its bonus,
    found or not. Fixing it would break comparison with the paper."""
    total = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    bonus = 0
    for test, result in zip(tests, results, strict=True):
        for key in total:
            total[key] += result[key]
        if test["cwe"] in TOP_25 and total["tp"] > 0:
            bonus += TOPLIST_BONUS - TOP_25.index(test["cwe"]) // TOPLIST_BONUS
    points = bonus
    for key, weight in SCORING.items():
        points += total[key] * weight
    return {"score": points, "bonus": bonus, **total}
