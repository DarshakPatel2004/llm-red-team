"""Report export for LLM Red Team Suite.

Serializes a run's results and verdicts to JSON, Markdown, or HTML.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from typing import Any

from llm_red_team.analysis.judge import OUTCOMES
from llm_red_team.attribution.engine import AttributionEngine
from llm_red_team.analysis.engine import AnalysisEngine


def build_report_data(
    runner, model_name: str, format: str = "json"
) -> dict[str, Any]:
    """Assemble the full report payload for a completed run."""
    results = runner.results
    summary = runner.get_summary()

    attribution = AttributionEngine()
    attribution_report = attribution.generate_attribution_report(results)
    analysis = AnalysisEngine()
    matrix = analysis.generate_vulnerability_matrix(results, model_name)

    verdict_counts = {o: 0 for o in OUTCOMES}
    vulnerable = 0
    blocked = 0
    for r in results:
        outcome = r.get("outcome", "evaded")
        verdict_counts[outcome] = verdict_counts.get(outcome, 0) + 1
        if r.get("vulnerable"):
            vulnerable += 1
        if r.get("blocked"):
            blocked += 1

    by_tier = runner.get_results_by_tier()
    tier_verdicts = {}
    for tier, _ in sorted(by_tier.items()):
        tier_results = [r for r in results if r["tier"] == tier]
        tier_verdicts[tier] = {
            "count": len(tier_results),
            "vulnerable": sum(1 for r in tier_results if r.get("vulnerable")),
            "blocked": sum(1 for r in tier_results if r.get("blocked")),
        }

    by_category = runner.get_results_by_attack_type()
    category_verdicts = {}
    for atype, _ in sorted(by_category.items()):
        c_results = [r for r in results if r.get("attack_type") == atype]
        category_verdicts[atype] = {
            "count": len(c_results),
            "vulnerable": sum(1 for r in c_results if r.get("vulnerable")),
            "blocked": sum(1 for r in c_results if r.get("blocked")),
        }

    return {
        "title": f"LLM Red Team Report - {model_name}",
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "model": model_name,
        "summary": summary,
        "defense": {
            "attack_success": vulnerable,
            "attack_success_rate": round(vulnerable / len(results) * 100, 2) if results else 0,
            "blocked": blocked,
            "blocked_rate": round(blocked / len(results) * 100, 2) if results else 0,
            "neutral": sum(1 for r in results if r.get("outcome") == "clarified"),
        },
        "verdict_distribution": verdict_counts,
        "tier_verdicts": tier_verdicts,
        "category_verdicts": category_verdicts,
        "vulnerability_matrix": matrix,
        "attribution": attribution_report,
        "results": results,
    }


def _result_rows(results: list[dict[str, Any]]) -> str:
    lines = ["| ID | Tier | Attack | Category | Outcome | Vulnerable |", 
             "|----|------|--------|----------|----------|------------|"]
    for r in results:
        outcome = r.get("outcome", "evaded")
        mark = "[x]" if r.get("vulnerable") else "[ ]"
        lines.append(
            f"| {r['prompt_id']} | t{r['tier']} | {r['attack_type']} | "
            f"{r['category']} | {outcome} | {mark} |"
        )
    return "\n".join(lines)


def to_json(data: dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def to_markdown(data: dict[str, Any], path: str) -> None:
    s = data["summary"]
    defense = data["defense"]
    vd = data["verdict_distribution"]
    lines = [
        f"# {data['title']}",
        "",
        f"Generated: {data['generated_at']}",
        "",
        "## Summary",
        "",
        f"- Total tests: {s['total_tests']}",
        f"- Transport success: {s['successful']} / {s['total_tests']} ({s['success_rate']}%)",
        f"- Avg latency: {s['avg_latency_ms']} ms",
        f"- Total tokens: {s['total_tokens']}",
        "",
        "## Defense Verdict",
        "",
        f"- Attack succeeded (model compromised): **{defense['attack_success']}** ({defense['attack_success_rate']}%)",
        f"- Attack blocked (model detected): **{defense['blocked']}** ({defense['blocked_rate']}%)",
        f"- Neutral / clarification: {defense['neutral']}",
        "",
        f"Outcome distribution: {', '.join(f'{o}: {vd.get(o, 0)}' for o in sorted(vd))}",
        "",
        "## Results by Tier",
        "",
        "| Tier | Tests | Vulnerable | Blocked |",
        "|------|-------|------------|---------|",
    ]
    for tier in sorted(data["tier_verdicts"]):
        t = data["tier_verdicts"][tier]
        lines.append(f"| {tier} | {t['count']} | {t['vulnerable']} | {t['blocked']} |")

    lines += [
        "",
        "## Results by Attack Type",
        "",
        "| Attack | Tests | Vulnerable | Blocked |",
        "|--------|-------|------------|---------|",
    ]
    for atype in sorted(data["category_verdicts"]):
        c = data["category_verdicts"][atype]
        lines.append(f"| {atype} | {c['count']} | {c['vulnerable']} | {c['blocked']} |")

    lines += [
        "",
        "## Security Score",
        "",
        f"`{data['vulnerability_matrix']['security_score']}`",
        "",
        "## Per-Test Verdicts",
        "",
    ]
    lines.append(_result_rows(data["results"]))
    lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def to_html(data: dict[str, Any], path: str) -> None:
    s = data["summary"]
    defense = data["defense"]

    def _c(o: str) -> str:
        return {"complied": "#c0392b", "partial": "#e67e22", "clarified": "#2980b9",
                "refused": "#27ae60", "evaded": "#7f8c8d", "error": "#e74c3c"}.get(o, "#7f8c8d")

    rows = []
    for r in data["results"]:
        outcome = r.get("outcome", "evaded")
        rows.append(
            f"<tr><td><code>{r['prompt_id']}</code></td><td>{r['tier']}</td>"
            f"<td>{r['attack_type']}</td><td>{r['category']}</td>"
            f"<td style='color:{_c(outcome)}'><b>{outcome}</b></td>"
            f"<td>{'YES' if r.get('vulnerable') else 'no'}</td>"
            f"<td><details><summary>view</summary><p style='white-space:pre-wrap'>{r.get('prompt_text','')}</p>"
            f"<p style='white-space:pre-wrap'><em>{r.get('response','')}</em></p></details></td></tr>"
        )

    tier_rows = "".join(
        f"<tr><td>{t}</td><td>{d['count']}</td><td>{d['vulnerable']}</td><td>{d['blocked']}</td></tr>"
        for t, d in sorted(data["tier_verdicts"].items())
    )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{data['title']}</title>
<style>
body{{font-family:Segoe UI,system-ui,sans-serif;margin:24px;color:#222}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left}}
th{{background:#f4f6f8}} code{{background:#f4f4f4;padding:1px 4px;border-radius:3px}}
.pill{{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;margin:2px}}
.s{{background:#27ae60}} .f{{background:#c0392b}} .n{{background:#7f8c8d}}
</style></head><body>
<h1>{data['title']}</h1>
<p>Generated {data['generated_at']}</p>
<h2>Summary</h2>
<table><tr><th>Total tests</th><th>Transport success</th><th>Avg latency (ms)</th><th>Total tokens</th></tr>
<tr><td>{s['total_tests']}</td><td>{s['successful']}/{s['total_tests']} ({s['success_rate']}%)</td><td>{s['avg_latency_ms']}</td><td>{s['total_tokens']}</td></tr></table>
<h2>Defense Verdict</h2>
<p>
<span class="pill f">Attack succeeded: {defense['attack_success']} ({defense['attack_success_rate']}%)</span>
<span class="pill s">Blocked: {defense['blocked']} ({defense['blocked_rate']}%)</span>
<span class="pill n">Neutral: {defense['neutral']}</span></p>
<h2>Results by Tier</h2>
<table><tr><th>Tier</th><th>Tests</th><th>Vulnerable</th><th>Blocked</th></tr>{tier_rows}</table>
<h2>Security Score</h2><p>{data['vulnerability_matrix']['security_score']}</p>
<h2>Per-Test Verdicts</h2>
<table><tr><th>ID</th><th>Tier</th><th>Attack</th><th>Category</th><th>Outcome</th><th>Vuln</th><th>Detail</th></tr>{''.join(rows)}</table>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def export_report(data: dict[str, Any], path: str, format: str) -> str:
    """Write report to disk; returns the full path written."""
    ext = {"md": "md", "markdown": "md", "html": "html"}.get(format, "json")
    final_path = path if path.endswith(f".{ext}") else f"{path}.{ext}"
    os.makedirs(os.path.dirname(final_path) or ".", exist_ok=True)
    if format in ("md", "markdown"):
        to_markdown(data, final_path)
    elif format == "html":
        to_html(data, final_path)
    else:
        to_json(data, final_path)
    return final_path