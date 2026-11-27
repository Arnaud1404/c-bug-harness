"""Runs one condition on CASTLE programs and writes runs/<condition>/<label>/<id>.json.

  python -m harness.run analyzers
  python -m harness.run llm     --label qwen3.5-9b [--temperature 0] [--per-cwe 1] [--ids 125-1 ...]
  python -m harness.run harness --label qwen3.5-9b [--temperature 0] [--per-cwe 1] [--no-report]

A program already written is skipped, so a stopped run resumes.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

from harness import castle
from harness.analyze import RUNS
from harness.loop import URL, chat
from harness.pipeline import run_program


def select(tests: list[dict], per_cwe: int, ids: list[str]) -> list[dict]:
    """Selects tests by explicit IDs or stratified per CWE (preserving the
    60/40 vulnerable/clean split so pilots include clean programs)."""
    if ids:
        chosen = []
        for t in tests:
            if t["id"] in ids:
                chosen.append(t)
        return chosen
    if not per_cwe:
        return tests
    by_cwe: dict[int, list[dict]] = {}
    for t in tests:
        by_cwe.setdefault(t["cwe"], []).append(t)
    chosen = []
    for idx, cwe_tests in enumerate(by_cwe.values()):
        vuln = []
        clean = []
        for t in cwe_tests:
            if t["vulnerable"]:
                vuln.append(t)
            else:
                clean.append(t)
        if per_cwe == 1:
            want_vuln = idx % 5 < 3
            pool = vuln if want_vuln else clean
            fallback = clean if want_vuln else vuln
            if pool:
                chosen.append(pool[0])
            elif fallback:
                chosen.append(fallback[0])
        else:
            want_v = min(len(vuln), max(1, round(per_cwe * 0.6)))
            want_c = min(len(clean), per_cwe - want_v)
            picked = vuln[:want_v] + clean[:want_c]
            remaining = vuln[want_v:] + clean[want_c:]
            while len(picked) < per_cwe and remaining:
                picked.append(remaining.pop(0))
            chosen.extend(picked)
    return chosen


def served_model() -> str:
    """The GGUF the server actually loaded, whatever label the run was given."""
    with urllib.request.urlopen(URL.replace("/chat/completions", "/models"), timeout=30) as response:
        return json.load(response)["data"][0]["id"]


def union(findings: list[dict]) -> list[dict]:
    """One finding per line across all analysers, so eight runs agreeing on a
    line count once, as CASTLE's tool combinations do. Prefers a finding with
    a non-zero CWE when tools collide on the same line."""
    by_line: dict[int, dict] = {}
    for f in findings:
        if f["severity"].lower() not in castle.RELEVANT:
            continue
        existing = by_line.get(f["line"])
        if existing is None or (existing["cwe"] == 0 and f["cwe"] != 0):
            by_line[f["line"]] = f
    return list(by_line.values())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("condition", choices=["analyzers", "llm", "harness"])
    parser.add_argument("--label", default="")
    parser.add_argument("--per-cwe", type=int, default=0)
    parser.add_argument("--ids", nargs="*", default=[])
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--temperature", type=float, default=None)
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
        record: dict = {"id": test["id"], "model": model, "temperature": args.temperature, "trace": []}
        start = time.monotonic()
        if args.condition == "analyzers":
            record["findings"] = union(found)
            record["per_tool"] = found
        elif args.condition == "llm":
            # CASTLE's own LLM run: its prompt as system message, the code fenced.
            try:
                reply = chat([{"role": "system", "content": dataset["prompt"]},
                              {"role": "user", "content": f"```{test['code']}\n```"}],
                             temperature=args.temperature)
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")[:300]
                record["trace"].append({"agent": "llm", "turn": 1, "seconds": 0.0, "model": None,
                                        "temperature": args.temperature, "prompt_tokens": 0,
                                        "completion_tokens": 0, "error": f"HTTP {exc.code}: {detail}", "calls": []})
                record["answer"] = ""
                record["findings"] = []
            else:
                choice = reply["choices"][0]
                text = choice["message"].get("content") or ""
                usage = reply.get("usage") or {}
                call_rec = {"agent": "llm", "turn": 1, "seconds": reply["seconds"], "model": reply.get("model"),
                            "temperature": args.temperature, "finish_reason": choice.get("finish_reason"),
                            "prompt_tokens": usage.get("prompt_tokens", 0),
                            "completion_tokens": usage.get("completion_tokens", 0), "calls": []}
                reasoning = choice["message"].get("reasoning_content")
                if reasoning:
                    call_rec["reasoning"] = reasoning
                record["trace"].append(call_rec)
                record["answer"] = text
                record["findings"] = castle.parse_llm_report(test["code"], text)
        else:
            stages = run_program(test, found, RUNS / "work" / args.label / test["id"],
                                 record["trace"], write_report=not args.no_report, temperature=args.temperature)
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
