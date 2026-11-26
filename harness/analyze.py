"""Runs analyzers/run.sh on every CASTLE program, one container each, and
writes runs/raw/<id>/findings.json. A program already done is skipped,
so an interrupted run resumes.

  python -m harness.analyze [--only ID ...]
"""

from __future__ import annotations

import argparse
import json
import sys

from harness import castle, docker
from harness.normalize import normalize

RUNS = castle.CASTLE_DIR.parent.parent / "runs"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", nargs="*", default=[])
    args = parser.parse_args()
    dataset = castle.load()
    source = castle.CASTLE_DIR / "datasets" / "CASTLE-C250"
    failed = 0
    for test in dataset["tests"]:
        if args.only and test["id"] not in args.only:
            continue
        out = RUNS / "raw" / test["id"]
        if (out / "findings.json").exists():
            continue
        out.mkdir(parents=True, exist_ok=True)
        (out / test["name"]).write_bytes((source / test["name"]).read_bytes())
        code = docker.run(out, ["./analyzers/run.sh", "/work/" + test["name"], "/work/out", test["compile"]])
        # run.sh exits 2 when a tool timed out or crashed; the others still count.
        if code not in (0, 2):
            print(f"{test['id']}: run.sh exited {code}", file=sys.stderr)
            failed += 1
            continue
        findings = normalize(out / "out")
        (out / "findings.json").write_text(json.dumps(findings, indent=1), encoding="utf-8")
        print(f"{test['id']}: {len(findings)} findings, status {code}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
