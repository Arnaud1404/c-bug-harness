# AGENTS.md

Instructions for coding agents working in this repository. Humans: see `README.md`.

## What the repo is

- A measurement of a C bug-finding agent harness against a fixed model, on CASTLE-C250. The work proposal is `proposal/proposition.tex`, in French, for the Numerics course tutor.
- `agents/*.md` are the agent prompts. A header of `key: value` lines (`name`, `tools`, `max_turns`) sits between `---` fences, and `harness/loop.py` reads it.
- `harness/castle.py` ports CASTLE-Source (commit 765376e). Keep its scoring as written, quirks included, so the numbers stay comparable with the paper.

## Commands

```bash
make test lint                        # pytest + ruff + shellcheck
make docker-analyzers                 # analyser image and its smoke test
python scripts/check_proposal.py      # proposal cites only tracked files and the numbers in the code
cd proposal && latexmk -pdf proposition.tex
```

A change is done when `make test lint` and `scripts/check_proposal.py` pass. A change to the proposal must also build with no undefined references and no overfull box.

## Rules

- Python 3.12, explicit `for` loops: no comprehensions, no generator expressions, no `any()`/`all()` over generators.
- No new dependency for the harness: it uses the standard library only. Dev tools are pinned in `requirements-dev.txt`.
- Pin every download: image digests, apt versions and SHA-256 checksums in `analyzers/Dockerfile`, model checksums in `models.lock`, actions by commit SHA.
- The model never runs code directly. Every tool runs in the analyser image with `--network none`, through `harness/docker.py`.
- When a number in the proposal changes (turn limits, rounds, timeouts, versions), update `FACTS` in `scripts/check_proposal.py`.
- Every quote in `docs/related-work.md` is verbatim from the linked version. Do not add a quote that was not read in the source.

## Workflow

1. One task per branch, one logical change per commit, conventional subject, no body.
2. A bug fix comes with a test in `tests/` that fails before the fix.
3. Update `README.md` when a command or the pipeline changes.
