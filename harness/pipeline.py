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

MAX_ROUNDS = 2  # verifier -> checker rounds per bug
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


def last_run(trace: list[dict], start: int) -> str:
    """Raw output of the verifier's last run_input since trace[start]."""
    output = "(the verifier did not run the program)"
    for record in trace[start:]:
        for call in record["calls"]:
            if call["tool"] == "run_input":
                output = call["output"]
    return output


def run_program(test: dict, findings: list[dict], workdir: Path, trace: list[dict],
                write_report: bool = True) -> dict:
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / test["name"]).write_text(test["code"], encoding="utf-8")
    code = numbered(test["code"])
    stages = {"triage": [], "verifier": [], "checker": [], "rejected": []}

    answer = parse_json(run_agent("triage", f"Program {test['name']}:\n\n{code}\n\nFindings:\n"
                                  f"{tool_findings(findings)}", {}, trace))
    if not valid_triage(answer):
        stages["invalid"] = "triage"
        return stages
    for item in answer["rejected"]:
        stages["rejected"].append({"stage": "triage", **item})
    stages["triage"] = answer["bugs"]

    tools = make_tools(workdir, test)
    for bug in answer["bugs"]:
        objection = ""
        for round_no in range(1, MAX_ROUNDS + 1):
            start = len(trace)
            task = (f"Program {test['name']}:\n\n{code}\n\nSuspected bug: line {bug['line']}, "
                    f"CWE {bug['cwe']}. Triage: {bug.get('reason', '')}")
            if objection:
                task += f"\n\nThe checker rejected your previous attempt: {objection}"
            verdict = parse_json(run_agent("verifier", task, tools, trace))
            if not isinstance(verdict, dict) or verdict.get("verdict") not in VERDICTS:
                verdict = {"verdict": "invalid", "reason": "no valid answer"}
            evidence = last_run(trace, start)
            if verdict["verdict"] in ("refuted", "invalid"):
                stages["rejected"].append({"stage": "verifier", "round": round_no, **bug,
                                           "reason": verdict.get("reason", "")})
                break
            if round_no == 1:
                stages["verifier"].append(bug)
            check = parse_json(run_agent("checker", (
                f"Program {test['name']}:\n\n{code}\n\nReported bug: line {bug['line']}, CWE {bug['cwe']}.\n"
                f"Verifier verdict: {verdict['verdict']}.\nVerifier's last run, as recorded:\n{evidence}"),
                {}, trace))
            decision = check.get("decision") if isinstance(check, dict) else None
            if decision == "accept":
                stages["checker"].append({**bug, "verdict": verdict["verdict"], "evidence": evidence})
                break
            reason = check.get("reason", "") if isinstance(check, dict) else "no valid answer"
            if decision != "retry" or round_no == MAX_ROUNDS:
                # A bug still sent back after the last round is dropped.
                stages["rejected"].append({"stage": "checker", "round": round_no, **bug, "reason": reason})
                break
            objection = reason

    if write_report:
        stages["report"] = run_agent("writer", json.dumps({
            "program": test["name"], "accepted": stages["checker"], "rejected": stages["rejected"],
            "counts": {"findings": len(findings), "triage": len(stages["triage"]),
                       "verifier": len(stages["verifier"]), "accepted": len(stages["checker"])},
        }, indent=1), {}, trace)
    return stages
