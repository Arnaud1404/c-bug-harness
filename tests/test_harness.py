"""Checks that need no GPU, no Docker and no dataset: agent files, report
parsing, CASTLE scoring, the agent loop against a scripted server, and the
verifier/checker rounds of the pipeline."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from harness import castle, loop, pipeline
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
    assert {"gcc-fanalyzer", "infer", "esbmc", "frama-c-eva"} <= tools_on_20
    for f in found:
        if f["tool"] == "esbmc":
            assert f["cwe"] == 416


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


class Scripted(BaseHTTPRequestHandler):
    replies: list[dict] = []
    seen: list[dict] = []

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Scripted.seen.append(body)
        payload = json.dumps(Scripted.replies.pop(0)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def reply(content: str = "", calls: list | None = None) -> dict:
    message = {"role": "assistant", "content": content}
    if calls:
        message["tool_calls"] = calls
    return {"model": "scripted", "choices": [{"message": message}],
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
    server.replies = [reply(calls=[call]), reply('```json\n{"verdict": "confirmed"}\n```')]
    ran = []

    def run_input(args, stdin):
        ran.append(args)
        return "exit 1\nERROR: AddressSanitizer: heap-buffer-overflow"

    trace = []
    tools = {"build_san": ({"name": "build_san"}, lambda: "exit 0"), "run_input": ({"name": "run_input"}, run_input)}
    text = loop.run_agent("verifier", "task", tools, trace)
    assert loop.parse_json(text) == {"verdict": "confirmed"}
    assert ran == [["AAAA"]]
    assert server.seen[1]["messages"][-1] == {"role": "tool", "tool_call_id": "c1",
                                              "content": "exit 1\nERROR: AddressSanitizer: heap-buffer-overflow"}
    assert len(trace) == 2 and trace[0]["calls"][0]["tool"] == "run_input"


def test_loop_refuses_a_tool_the_agent_does_not_have(server):
    call = {"id": "c1", "type": "function", "function": {"name": "build_san", "arguments": "{}"}}
    server.replies = [reply(calls=[call]), reply("{}")]
    trace = []
    # triage has max_turns 1, so the call is ignored and no tool is offered.
    loop.run_agent("triage", "task", {"build_san": ({"name": "build_san"}, lambda: "ran")}, trace)
    assert "tools" not in server.seen[0]


def test_last_turn_offers_no_tools(server):
    call = {"id": "c", "type": "function", "function": {"name": "build_san", "arguments": "{}"}}
    max_turns = loop.load_agent("verifier")["max_turns"]
    server.replies = [reply(calls=[call])] * (max_turns - 1) + [reply('{"verdict": "refuted"}')]
    tools = {"build_san": ({"name": "build_san"}, lambda: "exit 0"), "run_input": ({"name": "run_input"}, None)}
    loop.run_agent("verifier", "task", tools, [])
    assert "tools" in server.seen[0] and "tools" not in server.seen[-1]


def test_pipeline_sends_a_bug_back_once_then_accepts(monkeypatch, tmp_path):
    answers = {
        "triage": ['{"bugs": [{"line": 7, "cwe": 125, "tools": ["cppcheck"], "reason": "i <= 5"}],'
                   ' "rejected": [{"line": 6, "tools": ["flawfinder"], "reason": "literal format"}]}'],
        "verifier": ['{"verdict": "not_triggered", "reason": "no crash"}',
                     '{"verdict": "confirmed", "reason": "global-buffer-overflow"}'],
        "checker": ['{"decision": "retry", "reason": "read past the end needs no input"}',
                    '{"decision": "accept", "reason": "ASan names line 7"}'],
    }
    tasks = []

    def fake_agent(name, task, tools, trace):
        tasks.append((name, task))
        trace.append({"agent": name, "calls": []})
        return answers[name].pop(0)

    monkeypatch.setattr(pipeline, "run_agent", fake_agent)
    test = {"name": "CASTLE-125-1.c", "code": "int main(void) {}", "compile": "gcc CASTLE-125-1.c -o CASTLE-125-1"}
    stages = pipeline.run_program(test, [], tmp_path, [], write_report=False)
    assert [s["line"] for s in stages["checker"]] == [7]
    assert stages["rejected"] == [{"stage": "triage", "line": 6, "tools": ["flawfinder"], "reason": "literal format"}]
    order = []
    for name, _ in tasks:
        order.append(name)
    assert order == ["triage", "verifier", "checker", "verifier", "checker"]
    assert "read past the end needs no input" in tasks[3][1]


def test_pipeline_drops_a_bug_still_sent_back_after_the_last_round(monkeypatch, tmp_path):
    def fake_agent(name, task, tools, trace):
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
    monkeypatch.setattr(pipeline, "run_agent", lambda *a: "I think line 4 is bad")
    stages = pipeline.run_program({"name": "t.c", "code": "", "compile": "gcc t.c -o t"}, [], tmp_path, [],
                                  write_report=False)
    assert stages["invalid"] == "triage" and stages["checker"] == []
