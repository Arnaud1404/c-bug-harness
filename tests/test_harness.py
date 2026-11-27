"""Checks that need no GPU, no Docker and no dataset: agent files, report
parsing, CASTLE scoring, the agent loop against a scripted server, and the
verifier/checker rounds of the pipeline."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from harness import castle, loop, pipeline, run, score
from harness.normalize import infer as parse_infer
from harness.normalize import normalize
from harness.tools import make_tools

FIXTURES = Path(__file__).parent / "fixtures"
HEADER_KEYS = {"name", "tools", "max_turns", "prompt"}


def agent_names() -> list[str]:
    names = []
    for path in sorted(loop.AGENTS.glob("*.md")):
        names.append(path.stem)
    return names


def test_the_four_board_agents_exist():
    assert agent_names() == ["checker", "triage", "verifier", "writer"]


@pytest.mark.parametrize("name", agent_names())
def test_agent_header(name):
    agent = loop.load_agent(name)
    assert set(agent) <= HEADER_KEYS
    assert agent["name"] == name
    assert agent["max_turns"] >= 1
    available = make_tools(Path("."), {"name": "x.c", "compile": "gcc x.c -o x"})
    for tool in agent["tools"]:
        assert tool in available
    if agent["tools"]:
        assert agent["max_turns"] >= 2, "an agent with tools needs a turn to answer after them"


def test_normalize_finds_the_use_after_free_on_line_20():
    found = normalize(FIXTURES / "416-1")
    tools_on_20 = set()
    for f in found:
        if f["line"] == 20:
            tools_on_20.add(f["tool"])
    assert {"gcc-fanalyzer", "infer-pulse", "esbmc", "frama-c-eva"} <= tools_on_20
    for f in found:
        if f["tool"] == "esbmc":
            assert f["cwe"] == 416


def test_infer_splits_checkers_and_excludes_dead_store(tmp_path):
    report = [
        {"bug_type": "USE_AFTER_FREE", "qualifier": "uaf", "line": 10},
        {"bug_type": "DEAD_STORE", "qualifier": "unused", "line": 12},
        {"bug_type": "DEADLOCK", "qualifier": "lock cycle", "line": 15},
    ]
    path = tmp_path / "infer.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    found = parse_infer(path)
    tools = []
    for f in found:
        tools.append((f["tool"], f["severity"]))
    assert tools == [("infer-pulse", ""), ("infer-liveness", "dead_code"), ("infer-starvation", "")]
    # DEAD_STORE must not enter the bug union or triage prompt.
    merged = run.union(found)
    merged_tools = []
    for f in merged:
        merged_tools.append(f["tool"])
    assert merged_tools == ["infer-pulse", "infer-starvation"]
    assert "DEAD_STORE" not in pipeline.tool_findings(found)


def test_cppcheck_keeps_its_severity_for_the_castle_filter():
    found = normalize(FIXTURES / "416-1")
    severities = set()
    for f in found:
        if f["tool"] == "cppcheck":
            severities.add(f["severity"])
    assert severities == {"information", "style"}


def test_llm_report_line_is_moved_to_the_quoted_content():
    code = "int main(void) {\n    int a[2];\n    return a[2];\n}"
    report = ('```json\n[{"severity": "high", "line": 1, "cwe": 125, "message": "oob",'
              ' "line_content": "return a[2];"}, {"line": 2}]\n```')
    assert castle.parse_llm_report(code, report) == [
        {"line": 3, "cwe": 125, "severity": "high", "message": "oob"}]


def test_castle_judge_and_score():
    groups = {125: {125, 119}, 0: set()}
    vulnerable = {"vulnerable": True, "lines": [7], "cwe": 125}
    clean = {"vulnerable": False, "lines": [], "cwe": 125}
    hit = castle.judge(vulnerable, [{"line": 7, "cwe": 0, "severity": ""},
                                    {"line": 9, "cwe": 0, "severity": ""}], groups)
    assert hit == {"tp": 1, "fp": 1, "tn": 0, "fn": 0}
    by_cwe = castle.judge(vulnerable, [{"line": 3, "cwe": 119, "severity": ""}], groups)
    assert by_cwe["tp"] == 1
    style_only = castle.judge(clean, [{"line": 3, "cwe": 0, "severity": "style"}], groups)
    assert style_only == {"tp": 0, "fp": 0, "tn": 1, "fn": 0}
    # 5 per tp, -1 per fp, 2 per tn; CWE-125 is 6th in the Top 25: bonus 5 - 5 // 5 = 4.
    # The clean program earns the bonus too, as in charts.ipynb (see castle.score).
    assert castle.score([vulnerable, clean], [hit, style_only])["score"] == 5 - 1 + 2 + 4 + 4


def test_parse_json_handles_multiple_fences_and_trailing_bare_json():
    fenced = '```\nint a[2];\n```\n```json\n{"verdict": "confirmed"}\n```'
    assert loop.parse_json(fenced) == {"verdict": "confirmed"}
    trailing = 'Line 12 overflows the heap.\n{"verdict": "confirmed", "args": ["AAAA"]}'
    assert loop.parse_json(trailing) == {"verdict": "confirmed", "args": ["AAAA"]}
    assert loop.parse_json("no json here") is None


def test_run_input_rejects_non_list_args(tmp_path):
    (tmp_path / "prog").write_text("", encoding="utf-8")
    tools = make_tools(tmp_path, {"name": "prog.c", "compile": "gcc prog.c -o prog"})
    assert tools["run_input"][1]("AAAA", "") == "error: args must be a list of strings"


def test_select_per_cwe_stratifies_clean_programs():
    tests = []
    for cwe in (125, 190, 416, 476, 787):
        tests.append({"id": f"{cwe}-1", "cwe": cwe, "vulnerable": True})
        tests.append({"id": f"{cwe}-2", "cwe": cwe, "vulnerable": False})
    one = run.select(tests, per_cwe=1, ids=[])
    assert len(one) == 5
    vuln_count = 0
    clean_count = 0
    for t in one:
        if t["vulnerable"]:
            vuln_count += 1
        else:
            clean_count += 1
    assert vuln_count == 3 and clean_count == 2
    two = run.select(tests, per_cwe=2, ids=[])
    assert len(two) == 10


def test_union_prefers_non_zero_cwe_on_same_line():
    merged = run.union([
        {"tool": "flawfinder", "line": 10, "cwe": 0, "severity": "", "message": "a"},
        {"tool": "esbmc", "line": 10, "cwe": 416, "severity": "", "message": "b"},
    ])
    assert len(merged) == 1 and merged[0]["cwe"] == 416


class Scripted(BaseHTTPRequestHandler):
    replies: list[dict] = []
    seen: list[dict] = []

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Scripted.seen.append(body)
        entry = Scripted.replies.pop(0)
        status = entry.get("_status", 200)
        payload = json.dumps(entry).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def reply(content: str = "", calls: list | None = None, finish_reason: str = "stop",
          reasoning: str | None = None) -> dict:
    message: dict = {"role": "assistant", "content": content}
    if calls:
        message["tool_calls"] = calls
    if reasoning is not None:
        message["reasoning_content"] = reasoning
    return {"model": "scripted", "choices": [{"message": message, "finish_reason": finish_reason}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5}}


@pytest.fixture
def server(monkeypatch):
    httpd = HTTPServer(("127.0.0.1", 0), Scripted)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(loop, "URL", f"http://127.0.0.1:{httpd.server_port}/v1/chat/completions")
    Scripted.seen = []
    yield Scripted
    httpd.shutdown()


def test_loop_runs_the_requested_tool_and_returns_the_answer(server):
    call = {"id": "c1", "type": "function", "function": {"name": "run_input",
                                                         "arguments": '{"args": ["AAAA"], "stdin": ""}'}}
    server.replies = [reply(calls=[call]), reply('```json\n{"verdict": "confirmed"}\n```', reasoning="checked")]
    ran = []

    def run_input(args, stdin):
        ran.append(args)
        return "exit 1\nERROR: AddressSanitizer: heap-buffer-overflow"

    trace = []
    tools = {"build_san": ({"name": "build_san"}, lambda: "exit 0"), "run_input": ({"name": "run_input"}, run_input)}
    text = loop.run_agent("verifier", "task", tools, trace, temperature=0.0)
    assert loop.parse_json(text) == {"verdict": "confirmed"}
    assert ran == [["AAAA"]]
    assert server.seen[0]["temperature"] == 0.0
    assert server.seen[1]["messages"][-1] == {"role": "tool", "tool_call_id": "c1",
                                              "content": "exit 1\nERROR: AddressSanitizer: heap-buffer-overflow"}
    assert len(trace) == 2 and trace[0]["calls"][0]["tool"] == "run_input"
    assert trace[1]["finish_reason"] == "stop" and trace[1]["reasoning"] == "checked"


def test_loop_handles_http_error_without_crashing(server):
    server.replies = [{"_status": 400, "error": "context length exceeded"}]
    trace = []
    text = loop.run_agent("triage", "task", {}, trace)
    assert text == "" and "HTTP 400" in trace[0]["error"]


def test_loop_refuses_a_tool_the_agent_does_not_have(server):
    call = {"id": "c1", "type": "function", "function": {"name": "build_san", "arguments": "{}"}}
    server.replies = [reply(calls=[call]), reply("{}")]
    trace = []
    # triage has max_turns 1, so the call is ignored and no tool is offered.
    loop.run_agent("triage", "task", {"build_san": ({"name": "build_san"}, lambda: "ran")}, trace)
    assert "tools" not in server.seen[0]


def test_last_turn_offers_no_tools_and_keeps_tool_role_order(server):
    call = {"id": "c", "type": "function", "function": {"name": "build_san", "arguments": "{}"}}
    max_turns = loop.load_agent("verifier")["max_turns"]
    server.replies = [reply(calls=[call])] * (max_turns - 1) + [reply('{"verdict": "refuted"}')]
    tools = {"build_san": ({"name": "build_san"}, lambda: "exit 0"), "run_input": ({"name": "run_input"}, None)}
    loop.run_agent("verifier", "task", tools, [])
    assert "tools" in server.seen[0] and "tools" not in server.seen[-1]
    assert server.seen[-1]["messages"][-1]["role"] == "tool"
    assert "No more tool calls" in server.seen[-1]["messages"][-1]["content"]


def test_pipeline_passes_all_runs_and_inputs_to_checker_and_writer(monkeypatch, tmp_path):
    answers = {
        "triage": ['{"bugs": [{"line": 7, "cwe": 125, "tools": ["cppcheck"], "reason": "i <= 5"}],'
                   ' "rejected": [{"line": 6, "tools": ["flawfinder"], "reason": "literal format"}]}'],
        "verifier": ['{"verdict": "not_triggered", "reason": "no crash"}',
                     '{"verdict": "confirmed", "reason": "global-buffer-overflow"}'],
        "checker": ['{"decision": "retry", "reason": "read past the end needs an argument"}',
                    '{"decision": "accept", "reason": "ASan names line 7"}'],
    }
    tasks = []
    verifier_round = 0

    def fake_agent(name, task, tools, trace, temperature=None):
        nonlocal verifier_round
        tasks.append((name, task))
        calls = []
        if name == "verifier":
            verifier_round += 1
            if verifier_round == 1:
                calls = [{"tool": "build_san", "arguments": {}, "output": "exit 0\n"},
                         {"tool": "run_input", "arguments": {"args": [], "stdin": ""}, "output": "exit 0\nok"}]
            else:
                # Earlier crashing run followed by a clean boundary run: both must reach checker.
                calls = [{"tool": "run_input", "arguments": {"args": ["LONGARG"], "stdin": ""},
                          "output": "exit 1\nERROR: AddressSanitizer: global-buffer-overflow"},
                         {"tool": "run_input", "arguments": {"args": ["a"], "stdin": ""}, "output": "exit 0\nok"}]
        trace.append({"agent": name, "calls": calls, "prompt_tokens": 10, "completion_tokens": 5})
        return answers[name].pop(0)

    monkeypatch.setattr(pipeline, "run_agent", fake_agent)
    test = {"name": "CASTLE-125-1.c", "code": "int main(void) {}", "compile": "gcc CASTLE-125-1.c -o CASTLE-125-1"}
    stages = pipeline.run_program(test, [], tmp_path, [], write_report=False)
    checker_lines = []
    for s in stages["checker"]:
        checker_lines.append(s["line"])
    assert checker_lines == [7]
    assert stages["checker"][0]["runs"][0]["args"] == ["LONGARG"]
    assert "args=[]" in tasks[2][1] and "build_san:" in tasks[2][1]
    assert "LONGARG" in tasks[4][1] and "AddressSanitizer" in tasks[4][1]
    assert stages["rejected"] == [{"stage": "triage", "line": 6, "tools": ["flawfinder"], "reason": "literal format"}]
    order = []
    for name, _ in tasks:
        order.append(name)
    assert order == ["triage", "verifier", "checker", "verifier", "checker"]


def test_pipeline_drops_round_2_refuted_from_verifier_stage(monkeypatch, tmp_path):
    answers = {
        "triage": ['{"bugs": [{"line": 3, "cwe": 125}], "rejected": []}'],
        "verifier": ['{"verdict": "not_triggered", "reason": "unsure"}',
                     '{"verdict": "refuted", "reason": "bounds check prevents it"}'],
        "checker": ['{"decision": "retry", "reason": "check line 2"}'],
    }

    def fake_agent(name, task, tools, trace, temperature=None):
        trace.append({"agent": name, "calls": []})
        return answers[name].pop(0)

    monkeypatch.setattr(pipeline, "run_agent", fake_agent)
    stages = pipeline.run_program({"name": "t.c", "code": "", "compile": "gcc t.c -o t"}, [], tmp_path, [],
                                  write_report=False)
    assert stages["verifier"] == [] and stages["checker"] == []
    assert stages["rejected"][0]["stage"] == "verifier" and stages["rejected"][0]["round"] == 2


def test_pipeline_drops_a_bug_still_sent_back_after_the_last_round(monkeypatch, tmp_path):
    def fake_agent(name, task, tools, trace, temperature=None):
        if name == "triage":
            return '{"bugs": [{"line": 3, "cwe": 0}], "rejected": []}'
        if name == "verifier":
            return '{"verdict": "not_triggered"}'
        return '{"decision": "retry", "reason": "still unclear"}'

    monkeypatch.setattr(pipeline, "run_agent", fake_agent)
    test = {"name": "t.c", "code": "", "compile": "gcc t.c -o t"}
    stages = pipeline.run_program(test, [], tmp_path, [], write_report=False)
    assert stages["checker"] == []
    assert stages["rejected"][0]["stage"] == "checker"
    assert stages["rejected"][0]["round"] == pipeline.MAX_ROUNDS


def test_invalid_triage_answer_counts_as_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "run_agent", lambda *a, **kw: "I think line 4 is bad")
    stages = pipeline.run_program({"name": "t.c", "code": "", "compile": "gcc t.c -o t"}, [], tmp_path, [],
                                  write_report=False)
    assert stages["invalid"] == "triage" and stages["invalid_calls"] == 1 and stages["checker"] == []


def test_score_row_includes_precision_ci_invalid_and_split_tokens():
    groups = {125: {125}, 0: set()}
    tests = [{"vulnerable": True, "lines": [7], "cwe": 125}]
    findings = [[{"line": 7, "cwe": 125, "severity": ""}]]
    records = [{"seconds": 3.0, "stages": {"invalid_calls": 2},
                "trace": [{"prompt_tokens": 120, "completion_tokens": 45}]}]
    line, _ = score.row("harness/demo", tests, findings, groups, records)
    assert "1.00 (21-100%)" in line and "| 2 | 120 | 45 | 3 |" in line
