# AS-BUILT SPEC — LLM Defense Suite (canonical, code-authoritative)

Status: reflects the repo at `9f5f05f`. When this doc and any earlier brief
disagree, **this doc wins** — every claim below was read off the code.
Tests: 108 collected (53 at Phase-A start), all green.

Mission: not unbeatable — transparent about what beats us, making attacks
expensive enough that defenders have options.

## 1. Current state (measured)

- Attack suite: 112 prompts, 5 tiers, `llm_red_team/attacks/__init__.py`.
- Baseline vs qwen2.5:3b: 28/112 vulnerable (25.0%); fresh re-run 30/112 (26.8%).
- Defended (measure, preamble + normalized send active): 12/112 (10.7%).
  Tier-1 A/B: baseline 6/20 → measure 2/20 → block 1/20 (9 pre-blocked).
- Benign corpus: `llm_red_team/eval/benign_100.jsonl`, 100 queries.
  True FPR @0.5: heuristics 0/100, Meta 22M 0/100, ProtectAI 0/100.
- SFT data: `llm_red_team/eval/sft_training_data.jsonl`, **41 unique
  real-model pairs** (6 complied, 35 partial), deduped by prompt_id.

## 2. Phase A — hardened heuristics (no new dependencies)

### 2.1 Normalizer (`llm_red_team/defense/normalizer.py`)

```python
class Normalizer:
    VERSION = "1.0"  # module constant VERSION; recorded per run
    def normalize(self, text: str) -> tuple[str, dict]: ...
    # meta: diverged, nfkc_changed, zero_width_chars_removed,
    #   control_chars_removed, original_length, normalized_length,
    #   homoglyph_flags, normalizer_version
```

Pipeline: NFKC → strip 8 zero-width/format chars → strip controls
(`0x00–0x1F` except `\t\n\r`, `0x7F–0x9F`) → collapse whitespace.
Homoglyph audit is **conservative mixed-script detection only**
(Cyrillic U+0400–U+04FF, Greek U+0370–U+03FF, kana remnants, in otherwise
Latin tokens). There is deliberately NO `0`/`O`/`1`/`l` map — rejected for
false positives. `build_guarded_prompt(preamble, user_text)` wraps untrusted
input in `<<<USER_DATA ... USER_DATA>>>` delimiters; `SYSTEM_PREAMBLE` (Wallace
et al. Table 3 adaptation) lives here as the single source.

### 2.2 Strategy interface (class-based — the only interface that exists)

```python
class DefenseStrategy:
    def __init__(self, name: str, level: str = "prompt",
                 config: dict | None = None) -> None: ...
    def apply(self, prompt: str, response: str, *,
              normalized: str | None = None,
              norm_meta: dict | None = None,
              preamble: str | None = None,
              mode: str | None = None) -> dict: ...
    # result: flagged, action (allow/block/sanitize/blocked_by_validation),
    #   defense, reason, confidence, latency_ms (+ extras per defense)
```

Standalone calls normalize internally; the runner passes pre-computed
`normalized`/`norm_meta`. Registry stays pinned: 18 strategies, 4 levels
(prompt 5 / model 5 / pipeline 4 / architecture 4) — asserted by tests.
Hardened (real logic): contradiction_detection, roleplay_filtering,
system_prompt_reinforcement (override detection + preamble/hash injector),
instruction_tokenization_hardening (divergence gate), input_sanitization
(merged entry over the three detectors), output_validation (echo/leak/exfil),
output_modification (block default / sanitize redaction). The other 11 keep
prior behavior with a tolerant `**_ctx` signature.

Key detector facts:
- Contradiction: 4 override regex families on normalized text (0/100 benign FPR).
- Roleplay: 6 persona-pattern families incl. DAN/GODMODE/alter-ego/developer-mode.
- Tokenization gate blocks on removed-char count or NFKC+mixed-script, not on
  normalization alone (fullwidth neutralized by NFKC is sanitization, not a block).
- Output constant-echo is a **generalized pattern**
  (`\b[A-Z]{3,}(?:-[A-Z0-9]{2,})+\b` mined from the normalized prompt) — NOT a
  hardcoded `ADVANCED-MODE` string.
- Bare-word output indicators are narrowed to
  `ignore instructions / developer mode / godmode` with a refusal-prefix
  bypass (measure mode caught 12/12 FPR on tier-5 refusals before the fix).
- `output_modification` is enforcement-only, never a detection source
  (a post-hook bug once counted its `blocked_by_validation` action as a hit;
  fixed + regression-tested).

### 2.3 Runner (`llm_red_team/engine/runner.py`)

```python
TestRunner(client, max_retries=3, timeout=30, parallel=1, db_url=None,
           judge=None, defenses: list[str] | None = None,
           defense_mode: str = "block")  # "block" | "measure"
```

Pre-hook: normalize once → input-stage defenses in requested order →
block synthesizes a refused row with **no model call** (every-tier-output
guarantee holds); measure records `would_block` and always calls the model.
Guarded send: preamble + normalized text via `build_guarded_prompt` only when
`system_prompt_reinforcement` is in the requested set. Post-hook: output-stage
defenses on the raw response → judge scores raw → block mode redacts top-level
text, raw kept at `extra_metadata.raw_response`. Defense fields persist in
`extra_metadata` (no schema change): defenses, defense_mode, defense_blocked,
blocking_defense, block_reason/pattern, would-block pair, preamble_hash,
normalizer_version. `get_defense_effectiveness()` → by_defense / by_tier /
by_attack_type. `resolve_defenses()` presets: csv names, `all-prompt`
(6 input incl. sanitization entry), `all-output` (3), `all` (18),
`none`; `prompt_guard` is explicit opt-in (see §3).

### 2.4 CLI (`llm_red_team/api/cli.py`)

`run --defenses {csv|all-prompt|all-output|all|none|prompt_guard[,…]}`
`--defense-mode {block|measure}` (default block). Live rows carry
`[DEFENSE:name]` / `[would-block:name]` tags; summary prints defense set,
defense-blocked and would-block counts. Default (no flags) is byte-identical
to pre-defense behavior.

## 3. Phase B — ML sidecar

`llm_red_team/defense/prompt_guard.py`: `PromptGuardDefense(config, pipeline)` —
lazy `transformers` import, loads on first `classify()`; any failure degrades
to the Phase A heuristic with `method` recorded. 512-token window / 256 stride,
max-segment aggregation, default threshold 0.5, `model_id` overrideable
(default Meta 22M). Deliberately outside `get_all_defenses()`; runner adds it
as `"prompt_guard"`. `transformers` is an optional `guard` extra in
`pyproject.toml`.

**Label truth (commit `e38822e`):** the 22M weights emit generic
`LABEL_0`/`LABEL_1` (`1` = malicious). The first mapper assumed
BENIGN/MALICIOUS and inverted every score (canonical injection read 0.002).
`_MALICIOUS_LABELS` / `_BENIGN_LABELS` sets + unknown-label warning +
regression test now pin this. Any doc or comment claiming the reverse is wrong.

`llm_red_team/defense/benchmark_defenses.py`: no-model-call harness
(heuristic vs guard vs both) with precision/recall/FPR + p50/p95.

Measured on all 112 prompts (17 successful attacks): heuristic P=0.20
R=0.18 FPR=0.13; Meta22M P=0.21 R=0.18 FPR=0.12 @~35ms CPU; both R=0.24.
ProtectAI contrast: R=0.77, attempt-flag rate 0.67. Meta misses cluster in
extraction rephrasings, persona jailbreaks (DAN ≈ 0.09), obfuscation —
the classes Phase A covers. Operating points: ProtectAI aggressive/recall,
Meta22M conservative/precision. Setup notes: HF approval is per-account
(granted account's token required); each shell needs `$env:HF_TOKEN` inline.

## 4. Phase C — data + gate

`llm_red_team/defense/export_sft_data.py`: `export_sft_training_data`
(runner rows → JSONL) + `export_from_db` (DB → dedupe by prompt_id, complied
preferred; excludes test/mock/unknown models). Refusal lookup:
attack_type → category → default, over this exact 16-category table —
prompt_injection/agentic/multi_turn/composite/reasoning/production/
model_specific → hierarchy refusal; jailbreak → persona refusal;
obfuscation/covert_channel/multimodal → encoding refusal;
extraction/leakage/rag/supply_chain → confidentiality refusal;
dos → default. `llm_red_team/eval/sft_training_data.jsonl` holds the 41.
Gate: `docs/EVAL_GATE_RULE.md` (112-suite + benign-100; vuln down +
helpfulness stable + FPR < 2% or no ship; experiment card required).
Enforcement in `CONTRIBUTING.md`: measure-mode receipt for block mode,
gate verification for tuned models.

Hygiene incident (why the gate exists in this repo, not just theory): the
suite once persisted ~6.9k mock rows into the working DB and the first export
was 92/101 garbage. Fixed by purge + autouse pytest fixture forcing
`:memory:` DB (verified zero leakage) + export model filter.

## 5. Corrections vs earlier draft briefs

Earlier chat briefs were aspirational; where they differ from §§2–4, they are
wrong. The six material corrections: (1) labels are LABEL_0/LABEL_1, never
assume BENIGN/MALICIOUS; (2) strategies are classes with `apply(prompt,
response, **ctx)`, runner is `(client, …, defenses, defense_mode)`, CLI lives
in `api/cli.py`; (3) 108 tests (53 at baseline), 18 strategies kept, 7
hardened; (4) homoglyph = mixed-script audit, no 0/O map; (5) constant-echo =
generalized regex, no hardcoded mode names; (6) SFT templates = §4 table, 41
rows. File paths, CLI flags, gate rule, 41-row SFT, 0/100 FPR were already
correct and are unchanged.

## 6. Open items

- Guard block mode: measurement-clear, still recommended stacked only.
- Full defended 112 in a single run (evidence is per-tier slices + union).
- Cloud clients (Gemini/OpenAI, `19eb425`) are built and smoke-tested but not
  part of the 112 ground truth; Gemini free quota is 20 req/min with
  RetryInfo backoff.
