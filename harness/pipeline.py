"""The harness on one program: analysers -> triage -> verifier <-> checker -> writer.

Each stage's output is kept, so one run scores the gain of every stage.
Findings rejected by triage, the verifier or the checker go to "rejected"
with the stage and the reason.
"""

from __future__ import annotations

import json
from pathlib import Path

from harness.castle import RELEVANT
from harness.loop import parse_json, run_agent
from harness.tools import make_tools

MAX_ROUNDS = 2  # verifier -> checker passes per bug (at most 1 retry)
MAX_BUGS = 10   # cap triage candidates on one single-file program
VERDICTS = ("confirmed", "not_triggered", "refuted")
DECISIONS = ("accept", "reject", "retry")


def numbered(code: str) -> str:
    out = []
    for i, line in enumerate(code.split("\n"), start=1):
        out.append(f"{i:4} | {line}")
    return "\n".join(out)


def is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def valid_triage(answer) -> bool:
    if not isinstance(answer, dict):
        return False
    for key in ("bugs", "rejected"):
        if not isinstance(answer.get(key), list):
            return False
        for item in answer[key]:
            if not isinstance(item, dict) or not is_int(item.get("line")):
                return False
    for bug in answer["bugs"]:
        if not is_int(bug.get("cwe")):
            return False
    return True


def tool_findings(findings: list[dict]) -> str:
    """The analyser findings as the triage prompt shows them, after the
    severity filter CASTLE scores with."""
    lines = []
    for f in findings:
        if f["severity"].lower() in RELEVANT:
            lines.append(f"- {f['tool']}, line {f['line']}, CWE {f['cwe']}: {f['message'][:200]}")
    return "\n".join(lines) or "(no findings)"


def format_runs(trace: list[dict], start: int) -> tuple[str, list[dict]]:
    """Recorded build_san and run_input calls since trace[start], with inputs
    and raw outputs, so the checker and writer see what actually ran."""
    parts = []
    runs = []
    for record in trace[start:]:
        for call in record["calls"]:
            tool = call["tool"]
            if tool == "build_san":
                parts.append(f"build_san:\n{call['output']}")
            elif tool == "run_input":
                args = call["arguments"] if isinstance(call["arguments"], dict) else {}
                entry = {"args": args.get("args", []), "stdin": args.get("stdin", ""), "output": call["output"]}
                runs.append(entry)
                parts.append(f"run_input(args={json.dumps(entry['args'])}, stdin={json.dumps(entry['stdin'])}):\n"
                             f"{entry['output']}")
    if not parts:
        return "(the verifier did not call build_san or run_input)", runs
    return "\n\n".join(parts), runs


def run_program(test: dict, findings: list[dict], workdir: Path, trace: list[dict],
                write_report: bool = True, temperature: float | None = None) -> dict:
    workdir.mkdir(parents=True, exist_ok=True)
    code = numbered(test["code"])
    stages: dict = {"triage": [], "verifier": [], "checker": [], "rejected": [], "invalid_calls": 0}

    answer = parse_json(run_agent("triage", f"Program {test['name']}:\n\n{code}\n\nFindings:\n"
                                  f"{tool_findings(findings)}", {}, trace, temperature=temperature))
    if not valid_triage(answer):
        stages["invalid"] = "triage"
        stages["invalid_calls"] += 1
        return stages
    for item in answer["rejected"]:
        stages["rejected"].append({"stage": "triage", **item})
    bugs = answer["bugs"]
    if len(bugs) > MAX_BUGS:
        stages["truncated_triage"] = len(bugs)
        bugs = bugs[:MAX_BUGS]
    stages["triage"] = bugs

    for idx, bug in enumerate(bugs, start=1):
        # Each bug runs in its own workspace so files written by one run cannot affect another.
        bug_dir = workdir / f"bug-{idx}"
        bug_dir.mkdir(parents=True, exist_ok=True)
        (bug_dir / test["name"]).write_text(test["code"], encoding="utf-8")
        tools = make_tools(bug_dir, test)
        objection = ""
        last_verdict: str | None = None
        for round_no in range(1, MAX_ROUNDS + 1):
            start = len(trace)
            task = (f"Program {test['name']}:\n\n{code}\n\nSuspected bug: line {bug['line']}, "
                    f"CWE {bug['cwe']}. Triage: {bug.get('reason', '')}")
            if objection:
                task += f"\n\nThe checker rejected your previous attempt: {objection}"
            verdict = parse_json(run_agent("verifier", task, tools, trace, temperature=temperature))
            if not isinstance(verdict, dict) or verdict.get("verdict") not in VERDICTS:
                stages["invalid_calls"] += 1
                verdict = {"verdict": "invalid", "reason": "no valid answer"}
            evidence, runs = format_runs(trace, start)
            if verdict["verdict"] in ("refuted", "invalid"):
                last_verdict = None
                stages["rejected"].append({"stage": "verifier", "round": round_no, **bug,
                                           "reason": verdict.get("reason", "")})
                break
            last_verdict = verdict["verdict"]
            check = parse_json(run_agent("checker", (
                f"Program {test['name']}:\n\n{code}\n\nReported bug: line {bug['line']}, CWE {bug['cwe']}.\n"
                f"Verifier verdict: {verdict['verdict']}.\nVerifier tool calls, as recorded:\n{evidence}"),
                {}, trace, temperature=temperature))
            decision = check.get("decision") if isinstance(check, dict) else None
            if decision not in DECISIONS:
                stages["invalid_calls"] += 1
            if decision == "accept":
                stages["checker"].append({**bug, "verdict": verdict["verdict"], "evidence": evidence, "runs": runs})
                break
            reason = check.get("reason", "") if isinstance(check, dict) else "no valid answer"
            if decision != "retry" or round_no == MAX_ROUNDS:
                # A bug still sent back after the last round is dropped.
                stages["rejected"].append({"stage": "checker", "round": round_no, **bug, "reason": reason})
                break
            objection = reason
        if last_verdict is not None:
            stages["verifier"].append({**bug, "verdict": last_verdict})

    if write_report:
        stages["report"] = run_agent("writer", json.dumps({
            "program": test["name"], "accepted": stages["checker"], "rejected": stages["rejected"],
            "counts": {"findings": len(findings), "triage": len(stages["triage"]),
                       "verifier": len(stages["verifier"]), "accepted": len(stages["checker"])},
        }, indent=1), {}, trace, temperature=temperature)
    return stages
