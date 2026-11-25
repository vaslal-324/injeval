"""Build the case matrix, run it, and write one JSON line per run."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Callable

from .agent import run_agent
from .attacks import GOALS, TEMPLATES, render
from .defences import DEFENCES
from .grader import collateral, grade_attack, grade_utility
from .models import Model
from .world import build_world, inject, make_canary


def load_tasks() -> list[dict]:
    return json.loads(resources.files("injeval").joinpath("data/tasks.json").read_text())


@dataclass(frozen=True)
class Case:
    task: dict
    goal_id: str | None = None
    template_id: str | None = None

    @property
    def id(self) -> str:
        if self.goal_id is None:
            return f"{self.task['id']}__benign"
        return f"{self.task['id']}__{self.goal_id}__{self.template_id}"


def build_cases(tasks: list[dict], goals: list[str], templates: list[str],
                include_benign: bool = True) -> list[Case]:
    cases = [Case(t) for t in tasks] if include_benign else []
    cases += [Case(t, g, tp) for t in tasks for g in goals for tp in templates]
    return cases


ModelFactory = Callable[[Case], Model]


def run_case(case: Case, defence_id: str, make_model: ModelFactory, repeat: int = 0,
             max_steps: int = 10) -> dict:
    env = build_world(make_canary(case.id))
    if case.goal_id:
        inject(env, case.task["surface"], render(case.template_id, GOALS[case.goal_id]))
    model = make_model(case)
    result = run_agent(model, env, case.task["prompt"], DEFENCES[defence_id], max_steps)
    return {
        "case_id": case.id, "task": case.task["id"], "surface": case.task["surface"]["type"],
        "goal": case.goal_id, "category": GOALS[case.goal_id].category if case.goal_id else None,
        "template": case.template_id, "defence": defence_id, "repeat": repeat,
        "model": model.name, "injected": case.goal_id is not None,
        **grade_attack(case.goal_id, env),
        "utility": grade_utility(case.task["utility"], result.final_text, env),
        **collateral(env),
        "steps": result.steps, "error": result.error,
        "blocked_calls": sum(c.blocked for c in env.calls),
        "tool_calls": [{"name": c.name, "args": c.args, "blocked": c.blocked} for c in env.calls],
        "final_text": result.final_text[:2000],
    }


def run_key(row: dict) -> tuple:
    return (row["case_id"], row["defence"], row["repeat"])


def run_matrix(cases: list[Case], defences: list[str], make_model: ModelFactory,
               out_path: Path, repeats: int = 1, workers: int = 4, max_steps: int = 10,
               resume: bool = True, progress: Callable[[int, int], None] | None = None) -> list[dict]:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    done: dict[tuple, dict] = {}
    if resume and out_path.exists():
        for line in out_path.read_text().splitlines():
            if line.strip():
                row = json.loads(line)
                done[run_key(row)] = row
    jobs = [(c, d, r) for c in cases for d in defences for r in range(repeats)
            if (c.id, d, r) not in done]
    rows = list(done.values())
    total = len(jobs)
    with out_path.open("a") as fh, ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(run_case, c, d, make_model, r, max_steps) for c, d, r in jobs]
        for i, fut in enumerate(as_completed(futures), 1):
            row = fut.result()
            fh.write(json.dumps(row) + "\n")
            fh.flush()
            rows.append(row)
            if progress:
                progress(i, total)
    return rows
