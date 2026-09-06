"""Benchmark harness: heuristic vs Prompt Guard vs both, no model calls.

Scores already-collected runner rows (needs prompt_text + vulnerable labels)
under each input-stage configuration and reports precision/recall/FPR plus
classifier latency. Used to calibrate the guard threshold before block mode.
"""

from __future__ import annotations

import statistics
from typing import Any

from llm_red_team.defense.prompt_guard import PromptGuardDefense
from llm_red_team.defense.strategies import InputSanitizationDefense


def _heuristic_flags(prompt: str) -> tuple[bool, int]:
    import time

    start = time.time()
    hit = InputSanitizationDefense().apply(prompt, "")
    return bool(hit.get("flagged")), int((time.time() - start) * 1000)


def benchmark_prompt_guard(
    rows: list[dict[str, Any]],
    guard: PromptGuardDefense | None = None,
    threshold: float = 0.5,
) -> dict[str, Any]:
    guard = guard or PromptGuardDefense(config={"threshold": threshold})
    lat_h, lat_g = [], []
    table: dict[str, dict[str, int]] = {
        "heuristic": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
        "guard": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
        "both": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
    }
    guard_methods: set[str] = set()
    for row in rows:
        prompt = row.get("prompt_text") or row.get("prompt") or ""
        vuln = bool(row.get("vulnerable"))
        h_flag, h_ms = _heuristic_flags(prompt)
        lat_h.append(h_ms)
        g = guard.classify(prompt, threshold=threshold)
        lat_g.append(g.get("latency_ms", 0))
        guard_methods.add(g.get("method", "?"))
        g_flag = bool(g["malicious"])
        for key, flag in (("heuristic", h_flag), ("guard", g_flag),
                          ("both", h_flag or g_flag)):
            cell = table[key]
            if flag and vuln:
                cell["tp"] += 1
            elif flag and not vuln:
                cell["fp"] += 1
            elif not flag and vuln:
                cell["fn"] += 1
            else:
                cell["tn"] += 1

    def metrics(cell: dict[str, int]) -> dict[str, float]:
        tp, fp, fn, tn = cell["tp"], cell["fp"], cell["fn"], cell["tn"]
        return {
            **cell,
            "precision": round(tp / (tp + fp), 3) if (tp + fp) else 0.0,
            "recall": round(tp / (tp + fn), 3) if (tp + fn) else 0.0,
            "fpr": round(fp / (fp + tn), 3) if (fp + tn) else 0.0,
        }

    def pct(lat: list[int], q: float) -> float:
        return round(statistics.quantiles(sorted(lat), n=100)[int(q * 100) - 1], 1) if lat else 0.0

    return {
        "n": len(rows),
        "threshold": threshold,
        "guard_methods": sorted(guard_methods),
        "heuristic": {**metrics(table["heuristic"]),
                      "latency_p50_ms": pct(lat_h, 0.5), "latency_p95_ms": pct(lat_h, 0.95)},
        "guard": {**metrics(table["guard"]),
                  "latency_p50_ms": pct(lat_g, 0.5), "latency_p95_ms": pct(lat_g, 0.95)},
        "both": metrics(table["both"]),
    }
