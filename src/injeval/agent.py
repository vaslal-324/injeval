"""Minimal tool-calling agent loop."""
from __future__ import annotations

import json
from dataclasses import dataclass

from .defences import Defence
from .models import Model
from .tools import TOOL_SPECS, execute
from .world import Environment, ToolCall


@dataclass
class AgentResult:
    final_text: str
    steps: int
    error: str | None
    messages: list[dict]


def run_agent(model: Model, env: Environment, user_prompt: str, defence: Defence,
              max_steps: int = 10) -> AgentResult:
    messages: list[dict] = [
        {"role": "system", "content": defence.system_prompt()},
        {"role": "user", "content": user_prompt},
    ]
    last_text = ""
    for step in range(1, max_steps + 1):
        try:
            turn = model.complete(messages, TOOL_SPECS)
        except Exception as exc:  # report, don't crash the whole run
            return AgentResult(last_text, step, f"model_error: {exc}", messages)
        last_text = turn.get("content") or last_text
        tool_calls = turn.get("tool_calls") or []
        messages.append({
            "role": "assistant", "content": turn.get("content"),
            **({"tool_calls": [{"id": c["id"], "type": "function", "function": {
                "name": c["name"], "arguments": json.dumps(c["args"])}} for c in tool_calls]}
               if tool_calls else {}),
        })
        if not tool_calls:
            return AgentResult(last_text, step, None, messages)
        for c in tool_calls:
            args = c["args"] if isinstance(c["args"], dict) else {}
            record = ToolCall(name=c["name"], args=args)
            reason = defence.check(c["name"], args, user_prompt, env)
            if reason:
                record.blocked, record.block_reason = True, reason
                record.output = f"Error: blocked by security policy ({reason})."
            else:
                record.output = execute(env, c["name"], args)
            env.calls.append(record)
            messages.append({"role": "tool", "tool_call_id": c["id"],
                             "content": defence.wrap_tool_output(record.output, user_prompt)})
    return AgentResult(last_text, max_steps, "max_steps", messages)
