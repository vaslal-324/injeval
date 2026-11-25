"""Model clients. All return {"content": str | None, "tool_calls": [{"id", "name", "args"}]}."""
from __future__ import annotations

import json
import time
from typing import Callable, Protocol


class Model(Protocol):
    name: str

    def complete(self, messages: list[dict], tools: list[dict]) -> dict: ...


class OpenAIChatModel:
    """Any OpenAI-compatible chat endpoint (OpenAI, vLLM, Ollama, Together, ...)."""

    def __init__(self, model: str, base_url: str | None = None, api_key: str | None = None,
                 temperature: float = 0.0, seed: int = 0, retries: int = 4):
        from openai import OpenAI  # imported lazily so tests need no API package
        kwargs = {k: v for k, v in {"base_url": base_url, "api_key": api_key}.items() if v}
        self.client = OpenAI(**kwargs)
        self.name, self.temperature, self.seed, self.retries = model, temperature, seed, retries

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        for attempt in range(self.retries):
            try:
                resp = self.client.chat.completions.create(
                    model=self.name, messages=messages, tools=tools,
                    temperature=self.temperature, seed=self.seed)
                break
            except Exception:  # network / rate limit: back off and retry
                if attempt == self.retries - 1:
                    raise
                time.sleep(2 ** attempt)
        msg = resp.choices[0].message
        calls = []
        for tc in msg.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {"_unparsed": tc.function.arguments}
            calls.append({"id": tc.id, "name": tc.function.name, "args": args})
        return {"content": msg.content, "tool_calls": calls}


Step = Callable[[list[dict]], dict]


class ScriptedModel:
    """Deterministic stand-in used by tests and dry runs.

    Each step receives the message history and returns a model turn, so a
    scripted step can copy data out of an earlier tool result (as a real
    compromised agent would).
    """

    def __init__(self, name: str, steps: list[Step]):
        self.name, self._steps, self._i = name, steps, 0

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        if self._i >= len(self._steps):
            return {"content": "Done.", "tool_calls": []}
        step = self._steps[self._i]
        self._i += 1
        return step(messages)


def calls(*specs: tuple[str, dict]) -> Step:
    def step(_msgs: list[dict]) -> dict:
        return {"content": None, "tool_calls": [
            {"id": f"call_{i}", "name": n, "args": a} for i, (n, a) in enumerate(specs)]}
    return step


def answer(text: str) -> Step:
    return lambda _msgs: {"content": text, "tool_calls": []}


def last_tool_output(messages: list[dict]) -> str:
    return next(m["content"] for m in reversed(messages) if m["role"] == "tool")
