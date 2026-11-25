"""Aggregate results into markdown tables with Wilson 95% intervals."""
from __future__ import annotations

import math
from collections import defaultdict


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _rate(rows: list[dict], key: str) -> str:
    vals = [r[key] for r in rows if r[key] is not None]
    if not vals:
        return "-"
    k, n = sum(map(bool, vals)), len(vals)
    lo, hi = wilson(k, n)
    return f"{k / n:.0%} [{lo:.0%}-{hi:.0%}] (n={n})"


def _table(header: list[str], body: list[list[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(row) + " |" for row in body]
    return "\n".join(lines)


def _pivot(rows: list[dict], row_key: str, defences: list[str]) -> str:
    groups: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for r in rows:
        if r["injected"]:
            groups[r[row_key]][r["defence"]].append(r)
    body = [[k] + [_rate(groups[k][d], "attack_success") if groups[k][d] else "-"
                   for d in defences] for k in sorted(groups)]
    return _table([row_key] + defences, body)


def summarise(rows: list[dict]) -> str:
    if not rows:
        return "No results."
    order = ["none", "spotlight", "sandwich", "guard"]
    present = set(r["defence"] for r in rows)
    defences = [d for d in order if d in present] + sorted(present - set(order))
    models = sorted({r["model"] for r in rows})
    by_def: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_def[r["defence"]].append(r)

    overview = []
    for d in defences:
        rs = by_def[d]
        benign = [r for r in rs if not r["injected"]]
        attacked = [r for r in rs if r["injected"]]
        overview.append([d, _rate(benign, "utility"), _rate(attacked, "utility"),
                         _rate(attacked, "attack_attempted"), _rate(attacked, "attack_success")])

    errors = sum(1 for r in rows if r["error"])
    out = [
        f"# Prompt-injection eval results\n\nModel(s): {', '.join(models)} · runs: {len(rows)}"
        f" · runs with errors: {errors}\n",
        "Rates show the point estimate with a Wilson 95% interval.\n",
        "## By defence\n",
        _table(["defence", "utility (no attack)", "utility (under attack)",
                "attack attempted", "attack success (ASR)"], overview),
        "\n## ASR by attack template\n", _pivot(rows, "template", defences),
        "\n## ASR by attacker goal\n", _pivot(rows, "goal", defences),
        "\n## ASR by injection surface\n", _pivot(rows, "surface", defences),
    ]
    return "\n".join(out) + "\n"
