"""Runs one condition on CASTLE programs and writes runs/<condition>/<label>/<id>.json.

  python -m harness.run analyzers
  python -m harness.run llm     --label qwen3.5-9b [--per-cwe 1] [--ids 125-1 ...]
  python -m harness.run harness --label qwen3.5-9b [--per-cwe 1] [--no-report]

A program already written is skipped, so a stopped run resumes.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request

from harness import castle
from harness.analyze import RUNS
from harness.loop import URL, chat
from harness.pipeline import run_program


def select(tests: list[dict], per_cwe: int, ids: list[str]) -> list[dict]:
    if ids:
        chosen = []
        for t in tests:
            if t["id"] in ids:
                chosen.append(t)
        return chosen
    if not per_cwe:
        return tests
    seen: dict[int, int] = {}
    chosen = []
    for t in tests:
        if seen.get(t["cwe"], 0) < per_cwe:
            chosen.append(t)
            seen[t["cwe"]] = seen.get(t["cwe"], 0) + 1
    return chosen


def served_model() -> str:
    """The GGUF the server actually loaded, whatever label the run was given."""
    with urllib.request.urlopen(URL.replace("/chat/completions", "/models"), timeout=30) as response:
        return json.load(response)["data"][0]["id"]


def union(findings: list[dict]) -> list[dict]:
    """One finding per line across all analysers, so eight tools agreeing on a
    line count once, as CASTLE's tool combinations do."""
    by_line = {}
    for f in findings:
        if f["severity"].lower() in castle.RELEVANT and f["line"] not in by_line:
            by_line[f["line"]] = f
    return list(by_line.values())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("condition", choices=["analyzers", "llm", "harness"])
    parser.add_argument("--label", default="")
    parser.add_argument("--per-cwe", type=int, default=0)
    parser.add_argument("--ids", nargs="*", default=[])
    parser.add_argument("--no-report", action="store_true")
    args = parser.parse_args()
    dataset = castle.load()
    tests = select(dataset["tests"], args.per_cwe, args.ids)
    out_dir = RUNS / args.condition / (args.label or "tools")
    out_dir.mkdir(parents=True, exist_ok=True)
    model = served_model() if args.condition != "analyzers" else None

    for test in tests:
        out = out_dir / f"{test['id']}.json"
        if out.exists():
            continue
        found = json.loads((RUNS / "raw" / test["id"] / "findings.json").read_text(encoding="utf-8"))
        record = {"id": test["id"], "model": model, "trace": []}
        start = time.monotonic()
        if args.condition == "analyzers":
            record["findings"] = union(found)
            record["per_tool"] = found
        elif args.condition == "llm":
            # CASTLE's own LLM run: its prompt as system message, the code fenced.
            reply = chat([{"role": "system", "content": dataset["prompt"]},
                          {"role": "user", "content": f"```{test['code']}\n```"}])
            text = reply["choices"][0]["message"].get("content") or ""
            record["trace"].append({"agent": "llm", "turn": 1, "seconds": reply["seconds"],
                                    "model": reply.get("model"),
                                    "prompt_tokens": reply["usage"]["prompt_tokens"],
                                    "completion_tokens": reply["usage"]["completion_tokens"], "calls": []})
            record["answer"] = text
            record["findings"] = castle.parse_llm_report(test["code"], text)
        else:
            stages = run_program(test, found, RUNS / "work" / args.label / test["id"],
                                 record["trace"], write_report=not args.no_report)
            record["stages"] = stages
            record["findings"] = []
            for bug in stages["checker"]:
                record["findings"].append({"line": bug["line"], "cwe": bug["cwe"], "severity": "",
                                           "message": bug.get("reason", "")})
        record["seconds"] = round(time.monotonic() - start, 2)
        out.write_text(json.dumps(record, indent=1), encoding="utf-8")
        tokens = 0
        for r in record["trace"]:
            tokens += r["prompt_tokens"] + r["completion_tokens"]
        print(f"{test['id']}: {len(record['findings'])} findings, {tokens} tokens, {record['seconds']} s",
              flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
