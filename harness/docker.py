"""One way to run a command in the analyser image: repository read-only at
/src, the program's workspace at /work, no network."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

IMAGE = os.environ.get("ANALYZERS_IMAGE", "c-bug-harness-analyzers")
REPO = Path(__file__).resolve().parent.parent


def command(workdir: Path, argv: list[str]) -> list[str]:
    cmd = ["docker", "run", "--rm", "--network", "none",
           "-v", f"{REPO}:/src:ro", "-v", f"{workdir.resolve()}:/work"]
    # Docker Desktop maps file ownership itself; on Linux the files must stay ours.
    if hasattr(os, "getuid"):
        cmd += ["--user", f"{os.getuid()}:{os.getgid()}"]
    return cmd + [IMAGE] + argv


def run(workdir: Path, argv: list[str]) -> int:
    return subprocess.run(command(workdir, argv), check=False).returncode


def capture(workdir: Path, argv: list[str], timeout: int) -> tuple[int, str]:
    """Exit code and merged output, cut to 4000 characters for the model."""
    try:
        done = subprocess.run(command(workdir, argv), capture_output=True, text=True,
                              errors="replace", timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout} s"
    out = done.stdout + done.stderr
    if len(out) > 4000:
        out = out[:2000] + "\n[... cut ...]\n" + out[-2000:]
    return done.returncode, out
