"""The agent loop: one agent, one task, until it answers or runs out of turns.

1. The harness sends the agent's prompt (agents/<name>.md) and the task.
2. The model answers with text, or asks for one of its tools.
3. The harness runs the tool itself, in the analyser image, and sends back
   the real output. The model never runs anything directly.
4. Repeat until the model answers without a tool call. The last allowed turn
   offers no tools, so the model has to answer.

The model server is any OpenAI-compatible endpoint (llama-server here).
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path

URL = os.environ.get("HARNESS_URL", "http://127.0.0.1:8080") + "/v1/chat/completions"
AGENTS = Path(__file__).resolve().parent.parent / "agents"
MAX_TOKENS = 8192
JSON_BLOCK = re.compile(r"```(?:json)?\s*(?P<json>[\[{][\s\S]*[\]}])\s*```")


def chat(messages: list[dict], tools: list[dict] | None = None) -> dict:
    body = {"messages": messages, "max_tokens": MAX_TOKENS}
    if tools:
        body["tools"] = tools
    request = urllib.request.Request(URL, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
    start = time.monotonic()
    # The first request of a run waits for the model to load into VRAM.
    with urllib.request.urlopen(request, timeout=1800) as response:
        reply = json.load(response)
    reply["seconds"] = round(time.monotonic() - start, 2)
    return reply


def load_agent(name: str) -> dict:
    """agents/<name>.md: a header of `key: value` lines between --- fences,
    then the prompt."""
    text = (AGENTS / f"{name}.md").read_text(encoding="utf-8")
    _, header, prompt = text.split("---\n", 2)
    agent = {"prompt": prompt.strip(), "tools": [], "max_turns": 1}
    for raw in header.strip().splitlines():
        key, value = raw.split(":", 1)
        agent[key.strip()] = value.strip()
    if isinstance(agent["tools"], str):
        agent["tools"] = [t.strip() for t in agent["tools"].split(",") if t.strip()]
    agent["max_turns"] = int(agent["max_turns"])
    return agent


def parse_json(text: str):
    """The JSON answer, fenced or bare; None when there is none."""
    match = JSON_BLOCK.search(text)
    candidate = match.group("json") if match else text.strip()
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None


def run_agent(name: str, task: str, tools: dict[str, tuple[dict, Callable[..., str]]],
              trace: list[dict]) -> str:
    """Runs agent `name` on `task` and returns its final text. tools maps a
    tool name to (OpenAI function spec, Python function); the agent only
    gets the ones its header lists. Every model call is appended to trace."""
    agent = load_agent(name)
    specs = []
    for tool in agent["tools"]:
        specs.append({"type": "function", "function": tools[tool][0]})
    messages = [{"role": "system", "content": agent["prompt"]}, {"role": "user", "content": task}]
    for turn in range(1, agent["max_turns"] + 1):
        last = turn == agent["max_turns"]
        if last and specs:
            messages.append({"role": "user", "content": "No more tool calls. Give your final answer now."})
        reply = chat(messages, None if last else specs)
        message = reply["choices"][0]["message"]
        calls = message.get("tool_calls") or []
        record = {"agent": name, "turn": turn, "seconds": reply["seconds"], "model": reply.get("model"),
                  "prompt_tokens": reply["usage"]["prompt_tokens"],
                  "completion_tokens": reply["usage"]["completion_tokens"], "calls": []}
        trace.append(record)
        if not calls:
            return message.get("content") or ""
        messages.append({"role": "assistant", "content": message.get("content") or "", "tool_calls": calls})
        for call in calls:
            fn = call["function"]
            try:
                arguments = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                arguments = None
            if fn["name"] not in agent["tools"] or not isinstance(arguments, dict):
                output = f"error: no tool {fn['name']} with those arguments"
            else:
                try:
                    output = tools[fn["name"]][1](**arguments)
                except TypeError as exc:
                    output = f"error: {exc}"
            record["calls"].append({"tool": fn["name"], "arguments": arguments, "output": output})
            messages.append({"role": "tool", "tool_call_id": call.get("id", ""), "content": output})
    return ""
