"""Turns the raw reports of analyzers/run.sh into one list of findings.

Each finding is {"tool", "line", "cwe", "severity", "message"}. cwe is 0 when
the tool gives none. severity is kept where a tool has one that CASTLE or the
harness filters on (cppcheck, infer-liveness); the others get "".
"""

from __future__ import annotations

import json
import re
from pathlib import Path

CWE = re.compile(r"CWE-(\d+)")
# file.c:LINE:COL: warning: MESSAGE, as printed by GCC and by scan-build.
DIAG = re.compile(r"^[^:\s]+\.c:(\d+):\d+: warning: (.*)$")
EVA_ALARM = re.compile(r"^\[eva:alarm\] [^:]+\.c:(\d+): Warning:")
ESBMC_FILE = re.compile(r"file \S+ line (\d+)")
STARVATION_TYPES = {
    "DEADLOCK",
    "STARVATION",
    "LOCK_CONSISTENCY_VIOLATION",
    "STRICT_MODE_VIOLATION",
    "ARBITRARY_CODE_EXECUTION_UNDER_LOCK",
    "IPC_ON_UI_THREAD",
    "REGEX_OP_ON_UI_THREAD",
}


def first_cwe(text: str) -> int:
    match = CWE.search(text)
    if match:
        return int(match.group(1))
    return 0


def finding(tool: str, line: int, message: str, cwe: int = -1, severity: str = "") -> dict:
    if cwe < 0:
        cwe = first_cwe(message)
    return {"tool": tool, "line": line, "cwe": cwe, "severity": severity, "message": message.strip()}


def flawfinder(path: Path) -> list[dict]:
    found = []
    for result in json.loads(path.read_text(encoding="utf-8"))["runs"][0]["results"]:
        region = result["locations"][0]["physicalLocation"]["region"]
        found.append(finding("flawfinder", region["startLine"], result["message"]["text"]))
    return found


def cppcheck(path: Path) -> list[dict]:
    found = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        # --template={severity},{line},{cwe},{message}; the message may hold commas.
        parts = raw.split(",", 3)
        if len(parts) != 4 or not parts[1].isdigit() or parts[1] == "0":
            continue
        found.append(finding("cppcheck", int(parts[1]), parts[3], int(parts[2] or 0), parts[0]))
    return found


def diagnostics(tool: str, path: Path) -> list[dict]:
    found = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = DIAG.match(raw)
        if match:
            found.append(finding(tool, int(match.group(1)), match.group(2)))
    return found


def infer(path: Path) -> list[dict]:
    """Splits Infer findings by checker: pulse, starvation, and liveness.
    DEAD_STORE gets severity 'dead_code' so bug scoring counts it separately."""
    found = []
    for bug in json.loads(path.read_text(encoding="utf-8")):
        bug_type = bug["bug_type"]
        if bug_type == "DEAD_STORE":
            tool = "infer-liveness"
            severity = "dead_code"
        elif bug_type in STARVATION_TYPES:
            tool = "infer-starvation"
            severity = ""
        else:
            tool = "infer-pulse"
            severity = ""
        found.append(finding(tool, bug["line"], bug_type + ": " + bug["qualifier"], 0, severity))
    return found


def esbmc(path: Path) -> list[dict]:
    """One finding per "Violated property" block: its file line, then the
    property text and the CWE line ESBMC prints under the stack trace."""
    found = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for i, raw in enumerate(lines):
        if raw.strip() != "Violated property:" or i + 1 >= len(lines):
            continue
        where = ESBMC_FILE.search(lines[i + 1])
        if not where:
            continue
        block = []
        for nxt in lines[i + 2:]:
            if not nxt.strip():
                break
            if not nxt.startswith("  ") or nxt.strip().startswith(("main at", "Stack trace")):
                continue
            block.append(nxt.strip())
        text = "; ".join(block)
        found.append(finding("esbmc", int(where.group(1)), text))
    return found


def eva(path: Path) -> list[dict]:
    found = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for i, raw in enumerate(lines):
        match = EVA_ALARM.match(raw)
        if match:
            text = lines[i + 1].strip() if i + 1 < len(lines) else ""
            found.append(finding("frama-c-eva", int(match.group(1)), text, 0))
    return found


# tool name in OUT/status -> (report file, parser)
PARSERS = {
    "flawfinder": ("flawfinder.sarif", flawfinder),
    "cppcheck": ("cppcheck.txt", cppcheck),
    "clang-sa": ("clang-sa.log", lambda p: diagnostics("clang-sa", p)),
    "gcc-fanalyzer": ("gcc-fanalyzer.txt", lambda p: diagnostics("gcc-fanalyzer", p)),
    "gcc-fanalyzer-taint": ("gcc-fanalyzer-taint.txt", lambda p: diagnostics("gcc-fanalyzer-taint", p)),
    "infer": ("infer.json", infer),
    "esbmc": ("esbmc.log", esbmc),
    "frama-c-eva": ("frama-c-eva.log", eva),
}

# Individual analyser rows printed by harness.score (infer-liveness is reported separately).
SCORED_TOOLS = [
    "flawfinder",
    "cppcheck",
    "clang-sa",
    "gcc-fanalyzer",
    "gcc-fanalyzer-taint",
    "infer-pulse",
    "infer-starvation",
    "esbmc",
    "frama-c-eva",
]


def normalize(outdir: Path) -> list[dict]:
    """All findings of one run.sh output directory. A tool whose report is
    missing (it crashed or timed out) contributes nothing."""
    found = []
    for filename, parse in PARSERS.values():
        path = outdir / filename
        if path.is_file() and path.stat().st_size > 0:
            found.extend(parse(path))
    return found
