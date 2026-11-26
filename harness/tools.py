"""The verifier's two tools. Each runs in the analyser image, without network,
on the program's workspace; the model only sees what they return."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from harness import docker

SANITIZE = "-g -fno-omit-frame-pointer -fsanitize=address,undefined"
RUN_TIMEOUT = 10

BUILD_SPEC = {
    "name": "build_san",
    "description": "Compile the program with AddressSanitizer and UndefinedBehaviorSanitizer. "
                   "Returns the exit code and the compiler output.",
    "parameters": {"type": "object", "properties": {}},
}
RUN_SPEC = {
    "name": "run_input",
    "description": "Run the sanitizer build once with these command-line arguments and this "
                   f"standard input, for at most {RUN_TIMEOUT} seconds. Returns the exit code and the "
                   "output, including any sanitizer report. Call build_san first.",
    "parameters": {
        "type": "object",
        "properties": {
            "args": {"type": "array", "items": {"type": "string"}},
            "stdin": {"type": "string"},
        },
        "required": ["args", "stdin"],
    },
}


def make_tools(workdir: Path, test: dict) -> dict[str, tuple[dict, Callable[..., str]]]:
    binary = test["name"].removesuffix(".c")

    def build_san() -> str:
        argv = ["sh", "-c", f'cd /work && {test["compile"]} {SANITIZE}']
        code, out = docker.capture(workdir, argv, timeout=120)
        return f"exit {code}\n{out}"

    def run_input(args: list, stdin: str) -> str:
        if not (workdir / binary).exists():
            return "error: no build, call build_san first"
        (workdir / "stdin.txt").write_text(str(stdin), encoding="utf-8")
        # The arguments reach "$@" as separate argv entries, never through a shell parse.
        script = f'cd /work && timeout {RUN_TIMEOUT} ./{binary} "$@" < stdin.txt'
        argv = ["sh", "-c", script, "_"]
        for arg in args:
            argv.append(str(arg))
        code, out = docker.capture(workdir, argv, timeout=RUN_TIMEOUT + 30)
        return f"exit {code}\n{out}"

    return {"build_san": (BUILD_SPEC, build_san), "run_input": (RUN_SPEC, run_input)}
