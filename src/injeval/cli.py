"""Command line: `injeval run ...`, `injeval report ...`, `injeval cases`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .attacks import GOALS, TEMPLATES
from .defences import DEFENCES
from .report import summarise
from .runner import Case, build_cases, load_tasks, run_matrix
from .scripted import scripted_model


def _csv(value: str, allowed: dict | list, what: str) -> list[str]:
    items = list(allowed) if value == "all" else [v.strip() for v in value.split(",") if v.strip()]
    bad = [v for v in items if v not in allowed]
    if bad:
        sys.exit(f"unknown {what}: {', '.join(bad)} (choose from {', '.join(allowed)})")
    return items


def _cases(args) -> list[Case]:
    tasks = load_tasks()
    task_ids = _csv(args.tasks, [t["id"] for t in tasks], "task")
    tasks = [t for t in tasks if t["id"] in task_ids]
    cases = build_cases(tasks, _csv(args.goals, GOALS, "goal"),
                        _csv(args.templates, TEMPLATES, "template"),
                        include_benign=not args.no_benign)
    return cases[: args.limit] if args.limit else cases


def _add_matrix_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--tasks", default="all")
    p.add_argument("--goals", default="all")
    p.add_argument("--templates", default="all")
    p.add_argument("--no-benign", action="store_true", help="skip runs without injection")
    p.add_argument("--limit", type=int, default=0, help="only the first N cases (smoke test)")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="injeval",
                                 description="Prompt-injection safety eval for tool-using agents")
    sub = ap.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run the eval matrix")
    run.add_argument("--model", required=True,
                     help="model name for an OpenAI-compatible API, or scripted:gullible / scripted:safe")
    run.add_argument("--base-url", default=None, help="OpenAI-compatible endpoint (e.g. vLLM)")
    run.add_argument("--defences", default="all")
    run.add_argument("--repeats", type=int, default=1)
    run.add_argument("--workers", type=int, default=4)
    run.add_argument("--max-steps", type=int, default=10)
    run.add_argument("--seed", type=int, default=0)
    run.add_argument("--out", default="results")
    run.add_argument("--fresh", action="store_true", help="ignore existing results instead of resuming")
    _add_matrix_args(run)

    rep = sub.add_parser("report", help="summarise a results.jsonl file")
    rep.add_argument("path")

    cs = sub.add_parser("cases", help="list the cases that would run")
    _add_matrix_args(cs)

    args = ap.parse_args(argv)

    if args.cmd == "cases":
        for c in _cases(args):
            print(c.id)
        return

    if args.cmd == "report":
        rows = [json.loads(l) for l in Path(args.path).read_text().splitlines() if l.strip()]
        print(summarise(rows))
        return

    cases = _cases(args)
    defences = _csv(args.defences, DEFENCES, "defence")
    if args.model.startswith("scripted:"):
        kind = args.model.split(":", 1)[1]
        make_model = lambda case: scripted_model(kind, case.task, case.goal_id)  # noqa: E731
    else:
        from .models import OpenAIChatModel
        try:  # one shared, thread-safe client; fail fast on missing credentials
            shared = OpenAIChatModel(args.model, base_url=args.base_url, seed=args.seed)
        except Exception as exc:
            sys.exit(f"Could not create the model client: {exc}\n"
                     "Set OPENAI_API_KEY (any non-empty value works for a local vLLM server).")
        make_model = lambda case: shared  # noqa: E731

    out_dir = Path(args.out) / args.model.replace("/", "_").replace(":", "_")
    results = out_dir / "results.jsonl"
    if args.fresh and results.exists():
        results.unlink()

    def progress(i: int, n: int) -> None:
        print(f"\r{i}/{n} runs", end="", file=sys.stderr, flush=True)

    rows = run_matrix(cases, defences, make_model, results, repeats=args.repeats,
                      workers=args.workers, max_steps=args.max_steps, progress=progress)
    print(file=sys.stderr)
    summary = summarise(rows)
    (out_dir / "summary.md").write_text(summary)
    print(summary)
    print(f"Wrote {results} and {out_dir / 'summary.md'}", file=sys.stderr)


if __name__ == "__main__":
    main()
