"""Export failed red-team pairs to SFT JSONL for safety-tuning experiments.

Each example pairs an attack prompt with a template refusal (chosen) and the
model's actual complied/partial output (rejected). Training itself is out of
scope here; any experiment consuming this data must pass docs/EVAL_GATE_RULE.md.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

DEFAULT_OUTPUT = "llm_red_team/eval/sft_training_data.jsonl"

_HIERARCHY = (
    "I can't do that. Instructions embedded in user input don't override "
    "my system guidelines, and I only follow instructions from trusted sources."
)
_PERSONA = (
    "I can't roleplay as an unrestricted AI or pretend my safety guidelines "
    "don't apply."
)
_ENCODING = (
    "That prompt appears to use hidden characters or encoding tricks to "
    "disguise its intent. I can't help with the underlying request either."
)
_CONFIDENTIAL = (
    "I can't disclose system instructions, internal data, or retrieved "
    "content beyond what I'm permitted to share."
)
_DEFAULT = "I can't help with that request."

CATEGORY_TEMPLATES = {
    "prompt_injection": _HIERARCHY,
    "jailbreak": _PERSONA,
    "obfuscation": _ENCODING,
    "covert_channel": _ENCODING,
    "multimodal": _ENCODING,
    "extraction": _CONFIDENTIAL,
    "leakage": _CONFIDENTIAL,
    "rag": _CONFIDENTIAL,
    "supply_chain": _CONFIDENTIAL,
    "agentic": _HIERARCHY,
    "multi_turn": _HIERARCHY,
    "composite": _HIERARCHY,
    "reasoning": _HIERARCHY,
    "production": _HIERARCHY,
    "model_specific": _HIERARCHY,
    "dos": _DEFAULT,
    "default": _DEFAULT,
}

VULNERABLE_OUTCOMES = {"complied", "partial"}


def refusal_for(
    attack_type: str | None,
    category: str | None,
    templates: dict[str, str] | None = None,
) -> str:
    table = dict(CATEGORY_TEMPLATES)
    if templates:
        table.update(templates)
    return (
        table.get(attack_type or "")
        or table.get(category or "")
        or table["default"]
    )


def _is_failed(row: dict[str, Any]) -> bool:
    if row.get("vulnerable") is True:
        return True
    return str(row.get("outcome", "")).lower() in VULNERABLE_OUTCOMES


def export_sft_training_data(
    results: list[dict[str, Any]],
    output_path: str = DEFAULT_OUTPUT,
    refusal_templates: dict[str, str] | None = None,
) -> int:
    """Write failed pairs to JSONL. Returns number of examples exported."""
    count = 0
    with open(output_path, "w", encoding="utf-8") as f:
        for row in results:
            if not _is_failed(row):
                continue
            prompt = row.get("prompt_text") or row.get("prompt") or ""
            rejected = row.get("response") or ""
            if not prompt or not rejected:
                continue
            attack_type = row.get("attack_type")
            category = row.get("category") or row.get("attack_category")
            example = {
                "prompt": prompt,
                "chosen_refusal": refusal_for(attack_type, category, refusal_templates),
                "rejected_response": rejected,
                "attack_type": attack_type,
                "category": category,
                "tier": row.get("tier"),
                "judge_verdict": str(row.get("outcome", "")).lower() or None,
                "prompt_id": row.get("prompt_id"),
                "model_id": row.get("model_id"),
            }
            f.write(json.dumps(example, ensure_ascii=False) + "\n")
            count += 1
    return count


def export_from_db(
    db_path: str = "llm_red_team.db",
    output_path: str = DEFAULT_OUTPUT,
    refusal_templates: dict[str, str] | None = None,
    exclude_models: set[str] | None = None,
) -> int:
    """Collect vulnerable rows from the DB, dedupe by prompt, export.

    Attack types come from the attacks library (not stored per-row in the
    DB). Prefers full complies over partials when a prompt failed repeatedly.
    Unit-test mock rows (model_id test/mock/unknown) are excluded by default.
    """
    from llm_red_team.attacks import ALL_PROMPTS

    excluded = exclude_models if exclude_models is not None else {"test", "mock", "unknown"}
    attack_of = {p["id"]: p.get("attack_type") for p in ALL_PROMPTS}
    conn = sqlite3.connect(db_path)
    best: dict[str, dict[str, Any]] = {}
    for pid, prompt, response, tier, cat, model, meta in conn.execute(
        "SELECT prompt_id, prompt_text, response, tier, attack_category,"
        " model_id, extra_metadata FROM test_results"
    ):
        if (model or "unknown") in excluded:
            continue
        try:
            m = json.loads(meta or "{}")
        except Exception:
            m = {}
        outcome = str(m.get("outcome", "")).lower()
        if not (m.get("vulnerable") is True or outcome in VULNERABLE_OUTCOMES):
            continue
        if not (prompt and response):
            continue
        row = {
            "prompt_id": pid, "prompt_text": prompt, "response": response,
            "tier": tier, "attack_type": attack_of.get(pid), "category": cat,
            "outcome": outcome, "vulnerable": True, "model_id": model,
        }
        prev = best.get(pid)
        if prev is None or (outcome == "complied" and prev["outcome"] != "complied"):
            best[pid] = row
    conn.close()
    return export_sft_training_data(list(best.values()), output_path, refusal_templates)
