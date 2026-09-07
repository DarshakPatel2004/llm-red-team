# CONTRIBUTING.md

## How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `pytest`
5. Run linter: `ruff check llm_red_team/`
6. Run type checker: `mypy llm_red_team/`
7. Commit with conventional format: `feat: add new feature`
8. Push and open a Pull Request

## Adding a New Client

1. Create `llm_red_team/clients/your_client.py` extending `LLMClient`
2. Add import in `llm_red_team/clients/__init__.py`
3. Add entry to `configs/models.yaml`
4. Add tests in `llm_red_team/tests/`
5. Update documentation

## Code Style

- Python 3.10+ syntax
- Type hints required
- Line length: 120
- Use `ruff` for formatting
- Use `mypy` for type checking

## Branch Strategy

- `main` — stable releases
- `develop` — integration
- `feature/phase-{n}` — per-phase development
- `bugfix/{issue}` — bug fixes

## Reporting Issues

Use GitHub Issues with the appropriate template.

## Safety-Tuning Eval Gate (non-negotiable)

Safety-tuned models must pass `docs/EVAL_GATE_RULE.md` before merge:
vulnerability down on the 112-suite, no helpfulness regression on the benign
100, FPR < 2%. Any single failure blocks the merge. No card, no merge.

## Defense & Safety Requirements

**Measure-mode receipt requirement:** No defense ships in block mode without a measure-mode evaluation receipt. This is mandatory before any PR merge.

1. Run `llm-red-team run --defenses {your-defense} --defense-mode measure` on the full 112-prompt suite.
2. Report per-defense blocking statistics and FPR against `llm_red_team/eval/benign_100.jsonl`.
3. Include report in PR description; maintainers verify before merge.

**Fine-tuning experiments:** Must pass `EVAL_GATE_RULE.md` (see docs/) before release. No exceptions.
