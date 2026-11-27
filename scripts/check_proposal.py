"""Checks that proposal/proposition.tex matches the repository: every file it
cites is tracked by git, and every number it gives about the harness is the
one in the code. Exits 1 and lists the mismatches otherwise.

  python scripts/check_proposal.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEX = ROOT / "proposal" / "proposition.tex"

# (text the proposal must contain, file that must back it, text that file must contain)
FACTS = [
    ("6 tours max.", "agents/verifier.md", "max_turns: 6"),
    ("Au plus 2 passages", "harness/pipeline.py", "MAX_ROUNDS = 2"),
    ("10 secondes", "harness/tools.py", "RUN_TIMEOUT = 10"),
    ("build b12767", "scripts/serve.sh", "server-cuda13-b12767"),
    ("Q4\\_K\\_M", "models.lock", "Qwen3.5-9B-Q4_K_M.gguf"),
    ("Q4\\_0", "models.lock", "gemma-4-E4B-it-Q4_0.gguf"),
    ("\\texttt{c7391c9}", "scripts/fetch.sh", "c7391c9"),
    ("-fanalyzer-checker=taint", "analyzers/run.sh", "-fanalyzer-checker=taint"),
    ("\\texttt{-{}-pulse}", "analyzers/run.sh", "--pulse --liveness --starvation"),
    ("\\texttt{\\$CC}", "analyzers/run.sh", "--use-cc=gcc"),
]
VERSIONS = ["2.0.20", "2.22.0", "16.2.0", "23.1.6", "1.3.0", "8.8", "33.0"]
BANNED = ["Semgrep CE &", "exerce", "\u2014", "\u2013"]


def main() -> int:
    tex = TEX.read_text(encoding="utf-8")
    tracked = set(subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True,
                                 check=True).stdout.splitlines())
    errors = []
    for cited in re.findall(r"\\fichier\{([^}]+)\}", tex):
        if cited.endswith("/"):
            found = False
            for path in tracked:
                if path.startswith(cited):
                    found = True
            if not found:
                errors.append(f"cited directory {cited} holds no tracked file")
        elif cited not in tracked:
            errors.append(f"cited file {cited} is not tracked")
    for claim, path, backing in FACTS:
        if claim not in tex:
            errors.append(f"proposal no longer says {claim!r}: update FACTS")
        if backing not in (ROOT / path).read_text(encoding="utf-8"):
            errors.append(f"{path} does not contain {backing!r}, which backs {claim!r}")
    readme = (ROOT / "analyzers" / "README.md").read_text(encoding="utf-8")
    for version in VERSIONS:
        if version not in tex or version not in readme:
            errors.append(f"version {version} is not in both the proposal and analyzers/README.md")
    for word in BANNED:
        if word in tex:
            errors.append(f"banned text in the proposal: {word!r}")
    for error in errors:
        print("FAIL", error)
    if not errors:
        print("proposal matches the repository")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
