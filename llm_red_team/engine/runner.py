from __future__ import annotations

import time
import json
import os
import uuid
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from llm_red_team.clients.base import LLMClient
from llm_red_team.attacks import ALL_PROMPTS, ALL_CONVERSATIONS
from llm_red_team.database.schema import get_session, TestResult
from llm_red_team.analysis.judge import AttackJudge, EVADED
from llm_red_team.defense.normalizer import Normalizer, build_guarded_prompt
from llm_red_team.defense.prompt_guard import PromptGuardDefense
from llm_red_team.defense.strategies import (
    INPUT_STAGE,
    OUTPUT_STAGE,
    get_all_defenses,
)

class TestRunner:
    """Executes adversarial prompts against LLM models.

    Supports sequential and parallel execution with
    full error recovery, timeout handling, and result persistence.
    Every result is scored by an AttackJudge into a security verdict.
    """

    def __init__(
        self,
        client: LLMClient,
        max_retries: int = 3,
        timeout: int = 30,
        parallel: int = 1,
        db_url: str | None = None,
        judge: AttackJudge | None = None,
        defenses: list[str] | None = None,
        defense_mode: str = "block",
    ) -> None:
        self.client = client
        self.max_retries = max_retries
        self.timeout = timeout
        self.parallel = parallel
        self.db_url = db_url or "sqlite:///llm_red_team.db"
        self.judge = judge or AttackJudge()
        self.results: list[dict[str, Any]] = []
        self.run_id = uuid.uuid4().hex
        self._session = None
        if defense_mode not in ("block", "measure"):
            raise ValueError("defense_mode must be 'block' or 'measure'")
        self.defense_mode = defense_mode
        self.defenses = list(defenses or [])
        by_name = {d.name: d for d in get_all_defenses()}
        by_name["prompt_guard"] = PromptGuardDefense()
        unknown = [n for n in self.defenses if n not in by_name]
        if unknown:
            raise ValueError(f"Unknown defenses: {', '.join(unknown)}")
        self._defense_map = {n: by_name[n] for n in self.defenses}
        self._normalizer = Normalizer() if self.defenses else None

    def _get_session(self):
        try:
            session = get_session(self.db_url)
            return session
        except Exception:
            return None

    def _pre_hook(self, prompt_text: str) -> dict[str, Any]:
        """Normalize + run input-stage defenses. No model call here."""
        normalized, meta = self._normalizer.normalize(prompt_text)
        hook: dict[str, Any] = {
            "normalized": normalized,
            "norm_meta": meta,
            "blocked_by": None,
            "would_block_by": None,
            "preamble": None,
            "preamble_hash": None,
        }
        for name, defense in self._defense_map.items():
            if name in OUTPUT_STAGE:
                continue
            hit = defense.apply(prompt_text, "", normalized=normalized, norm_meta=meta)
            if hit.get("flagged"):
                if self.defense_mode == "block":
                    hook["blocked_by"] = name
                    hook["block_reason"] = hit.get("reason")
                    break
                hook["would_block_by"] = hook["would_block_by"] or name
            if name == "system_prompt_reinforcement" and hit.get("preamble"):
                hook["preamble"] = hit["preamble"]
                hook["preamble_hash"] = hit.get("preamble_hash")
        return hook

    def _post_hook(
        self, prompt_text: str, normalized: str, response_text: str, preamble: str | None
    ) -> dict[str, Any]:
        """Run output-stage defenses against the raw model response."""
        hook: dict[str, Any] = {"blocked_by": None, "would_block_by": None, "pattern": None}
        for name, defense in self._defense_map.items():
            if name not in OUTPUT_STAGE:
                continue
            hit = defense.apply(
                prompt_text, response_text,
                normalized=normalized, preamble=preamble, mode=self.defense_mode,
            )
            # NOTE: output_modification is enforcement (redaction), never a
            # detection source — only `flagged` detectors count here.
            if hit.get("flagged"):
                if self.defense_mode == "block":
                    hook["blocked_by"] = name
                    hook["pattern"] = hit.get("pattern")
                    break
                hook["would_block_by"] = hook["would_block_by"] or name
        return hook

    def _defense_extra(self, pre: dict, post: dict) -> dict[str, Any]:
        blocker = pre.get("blocked_by") or post.get("blocked_by")
        would = pre.get("would_block_by") or post.get("would_block_by")
        return {
            "defenses": self.defenses,
            "defense_mode": self.defense_mode,
            "defense_blocked": blocker is not None,
            "blocking_defense": blocker,
            "block_reason": pre.get("block_reason"),
            "block_pattern": post.get("pattern"),
            "defense_would_block": would is not None,
            "would_block_defense": would,
            "preamble_hash": pre.get("preamble_hash"),
            "normalizer_version": Normalizer.VERSION,
            "normalizer_diverged": (pre.get("norm_meta") or {}).get("diverged"),
        }

    def run_prompt(self, prompt: dict[str, Any]) -> dict[str, Any]:
        """Execute a single prompt against the model with retry logic."""
        pre: dict[str, Any] = {}
        if self.defenses:
            pre = self._pre_hook(prompt["prompt"])
            if pre.get("blocked_by") and self.defense_mode == "block":
                result = {
                    "prompt_id": prompt["id"],
                    "tier": prompt["tier"],
                    "category": prompt["category"],
                    "attack_type": prompt["attack_type"],
                    "prompt_text": prompt["prompt"],
                    "response": "",
                    "tokens_used": 0,
                    "latency_ms": 0,
                    "success": True,
                    "vulnerability_type": prompt.get("expected_vulnerability"),
                    "attempt": 0,
                    "error": None,
                    "outcome": "refused",
                    "vulnerable": False,
                    "blocked": True,
                    "attack_detected": True,
                    "signals": ["defense_pre_block"],
                    "confidence": 1.0,
                }
                result.update(self._defense_extra(pre, {}))
                self._persist(result)
                return result

        query_text = prompt["prompt"]
        if pre.get("preamble"):
            query_text = build_guarded_prompt(pre["preamble"], pre["normalized"])

        attempt = 0
        last_error = None

        while attempt < self.max_retries:
            try:
                start = time.time()
                response = self.client.query(
                    query_text,
                    max_tokens=self.client.config.get("max_tokens", 4096),
                    temperature=self.client.config.get("temperature", 0.7),
                    timeout=self.timeout,
                )
                latency = int((time.time() - start) * 1000)
                result = {
                    "prompt_id": prompt["id"],
                    "tier": prompt["tier"],
                    "category": prompt["category"],
                    "attack_type": prompt["attack_type"],
                    "prompt_text": prompt["prompt"],
                    "response": response["response"],
                    "tokens_used": response["tokens"],
                    "latency_ms": latency,
                    "success": True,
                    "vulnerability_type": prompt.get("expected_vulnerability"),
                    "attempt": attempt + 1,
                    "error": response.get("error"),
                }
                self._score_result(prompt, result)
                if self.defenses:
                    post = self._post_hook(
                        prompt["prompt"], pre.get("normalized", prompt["prompt"]),
                        result.get("response", ""), pre.get("preamble"),
                    )
                    result.update(self._defense_extra(pre, post))
                    if post.get("blocked_by") and self.defense_mode == "block":
                        result["extra_metadata_raw_response"] = result.get("response", "")
                        result["response"] = (
                            f"[blocked by {post['blocked_by']}: {post.get('pattern')}]"
                        )
                        result["blocked"] = True
                    elif result.get("defense_would_block"):
                        result["would_block_defense"] = result.get("would_block_defense")
                self._persist(result)
                return result
            except Exception as e:
                last_error = str(e)
                attempt += 1
                time.sleep(min(2 ** attempt, 8) * (0.8 + 0.4 * (attempt / 3)))

        result = {
            "prompt_id": prompt["id"],
            "tier": prompt["tier"],
            "category": prompt["category"],
            "prompt_text": prompt["prompt"],
            "success": False,
            "error": last_error,
            "attempt": attempt,
            "latency_ms": None,
        }
        self._persist(result)
        return result

    def run_conversation(self, convo: dict[str, Any]) -> dict[str, Any]:
        """Execute a multi-turn conversation via client.chat() with per-turn defenses."""
        turns: list[str] = list(convo.get("turns") or ([convo["prompt"]] if convo.get("prompt") else []))
        messages: list[dict[str, str]] = []
        transcript: list[dict[str, str]] = []
        tokens_used = 0
        pre: dict[str, Any] = {}
        # Optional system preamble when that defense is enabled.
        if self.defenses and "system_prompt_reinforcement" in self._defense_map:
            _pre = self._pre_hook(turns[0] if turns else "")
            if _pre.get("preamble"):
                messages.append({"role": "system", "content": _pre["preamble"]})
                pre = _pre
        for turn in turns:
            if self.defenses:
                hook = self._pre_hook(turn)
                if hook.get("blocked_by") and self.defense_mode == "block":
                    result = {
                        "prompt_id": convo["id"], "tier": convo.get("tier", 6),
                        "category": convo.get("category", "multi_turn"),
                        "attack_type": convo.get("attack_type", "conversational"),
                        "prompt_text": " // ".join(turns)[:500],
                        "response": "", "tokens_used": tokens_used, "latency_ms": 0,
                        "success": True, "vulnerability_type": convo.get("expected_vulnerability"),
                        "outcome": "refused", "vulnerable": False, "blocked": True,
                        "attack_detected": True, "signals": ["defense_pre_block:convo"],
                        "confidence": 1.0, "transcript": transcript,
                    }
                    result.update(self._defense_extra(hook, {}))
                    self._persist(result)
                    return result
            messages.append({"role": "user", "content": turn})
            try:
                out = self.client.chat(
                    messages,
                    max_tokens=self.client.config.get("max_tokens", 1024),
                    temperature=self.client.config.get("temperature", 0.7),
                    timeout=self.timeout,
                )
            except Exception as e:
                result = {"prompt_id": convo["id"], "tier": convo.get("tier", 6),
                          "category": convo.get("category"), "attack_type": convo.get("attack_type"),
                          "prompt_text": " // ".join(turns)[:500], "success": False,
                          "error": str(e), "transcript": transcript}
                self._persist(result)
                return result
            resp_text = out.get("response", "")
            tokens_used += out.get("tokens", 0)
            messages.append({"role": "assistant", "content": resp_text})
            transcript.append({"role": "user", "content": turn})
            transcript.append({"role": "assistant", "content": resp_text})
        final_response = transcript[-1]["content"] if transcript else ""
        verdict = self.judge.judge_conversation(convo, transcript, final_response)
        result = {
            "prompt_id": convo["id"], "tier": convo.get("tier", 6),
            "category": convo.get("category"), "attack_type": convo.get("attack_type"),
            "prompt_text": " // ".join(turns)[:500], "response": final_response,
            "tokens_used": tokens_used, "latency_ms": 0, "success": True,
            "vulnerability_type": convo.get("expected_vulnerability"),
            "transcript": transcript, **verdict,
        }
        if self.defenses:
            result.update(self._defense_extra(pre, {}))
        self._persist(result)
        return result

    def run_all_conversations(self) -> list[dict[str, Any]]:
        """Run all Tier-6 conversations sequentially (history can't parallelize safely)."""
        results = []
        for convo in ALL_CONVERSATIONS:
            results.append(self.run_conversation(convo))
        return results

    def _score_result(self, prompt: dict[str, Any], result: dict[str, Any]) -> None:
        """Attach a security verdict to a transport-successful result."""
        try:
            verdict = self.judge.judge(prompt, result)
            result.update(verdict)
        except Exception:
            result.setdefault("outcome", EVADED)
            result.setdefault("vulnerable", False)
            result.setdefault("attack_detected", False)
            result.setdefault("signals", [])
            result.setdefault("confidence", 0.5)

    def _persist(self, result: dict[str, Any]) -> None:
        """Persist result to database if available."""
        if not result.get("prompt_id"):
            return
        session = self._get_session()
        if not session:
            return
        try:
            db_result = TestResult(
                id=uuid.uuid4().hex,
                run_id=self.run_id,
                model_id=getattr(self.client, "model_id", "unknown"),
                prompt_id=result["prompt_id"],
                attack_category=result["category"],
                tier=result["tier"],
                prompt_text=result["prompt_text"][:500],
                response=result.get("response", "")[:2000],
                tokens_used=result.get("tokens_used", 0),
                latency_ms=result.get("latency_ms", 0),
                success=result.get("success", False),
                vulnerability_type=result.get("vulnerability_type"),
                extra_metadata={
                    "outcome": result.get("outcome", EVADED),
                    "vulnerable": result.get("vulnerable", False),
                    "attack_detected": result.get("attack_detected", False),
                    "signals": result.get("signals", []),
                    "confidence": result.get("confidence", 0.0),
                    "error": result.get("error"),
                    "defenses": result.get("defenses", []),
                    "defense_mode": result.get("defense_mode"),
                    "defense_blocked": result.get("defense_blocked", False),
                    "blocking_defense": result.get("blocking_defense"),
                    "block_reason": result.get("block_reason"),
                    "block_pattern": result.get("block_pattern"),
                    "defense_would_block": result.get("defense_would_block", False),
                    "would_block_defense": result.get("would_block_defense"),
                    "preamble_hash": result.get("preamble_hash"),
                    "normalizer_version": result.get("normalizer_version"),
                    "raw_response": (result.get("extra_metadata_raw_response", "") or "")[:2000],
                },
            )
            session.add(db_result)
            session.commit()
        except Exception:
            pass
        finally:
            session.close()

    def run_all(self) -> list[dict[str, Any]]:
        """Run all prompts against the model."""
        self.results = []
        if self.parallel > 1:
            return self._run_parallel()
        return self._run_sequential()

    def _run_sequential(self) -> list[dict[str, Any]]:
        for prompt in ALL_PROMPTS:
            result = self.run_prompt(prompt)
            self.results.append(result)
        return self.results

    def _run_parallel(self) -> list[dict[str, Any]]:
        """Run prompts in parallel with thread pool."""
        with ThreadPoolExecutor(max_workers=self.parallel) as executor:
            futures = {
                executor.submit(self.run_prompt, prompt): prompt
                for prompt in ALL_PROMPTS
            }
            for future in as_completed(futures):
                result = future.result()
                self.results.append(result)
        self.results.sort(key=lambda r: r["prompt_id"])
        return self.results

    def run_model_batch(
        self,
        clients: list[tuple[str, LLMClient]],
    ) -> dict[str, list[dict[str, Any]]]:
        """Run all prompts against multiple models."""
        batch_results: dict[str, list[dict[str, Any]]] = {}
        for model_name, client in clients:
            original_client = self.client
            self.client = client
            results = self.run_all()
            batch_results[model_name] = results
            self.client = original_client
        return batch_results

    def get_summary(self) -> dict[str, Any]:
        """Generate a summary of all results including security verdicts."""
        total = len(self.results)
        successful = sum(1 for r in self.results if r["success"])
        failed = total - successful
        avg_latency = (
            sum(r["latency_ms"] for r in self.results if r["latency_ms"]) / max(successful, 1)
        )
        vulnerable = sum(1 for r in self.results if r.get("vulnerable"))
        blocked = sum(1 for r in self.results if r.get("blocked"))
        neutral = sum(1 for r in self.results if r.get("outcome") == "clarified")
        defense_blocked = sum(1 for r in self.results if r.get("defense_blocked"))
        would_block = sum(1 for r in self.results if r.get("defense_would_block"))
        return {
            "total_tests": total,
            "successful": successful,
            "failed": failed,
            "success_rate": round(successful / total * 100, 2) if total > 0 else 0,
            "avg_latency_ms": round(avg_latency, 2),
            "total_tokens": sum(r["tokens_used"] for r in self.results),
            "parallel_workers": self.parallel,
            "vulnerable": vulnerable,
            "vulnerability_rate": round(vulnerable / total * 100, 2) if total > 0 else 0,
            "blocked": blocked,
            "blocked_rate": round(blocked / total * 100, 2) if total > 0 else 0,
            "neutral": neutral,
            "defense_blocked": defense_blocked,
            "defense_would_block": would_block,
            "defenses": self.defenses,
            "defense_mode": self.defense_mode,
        }

    def get_defense_effectiveness(self) -> dict[str, Any]:
        """Per-defense effectiveness by tier and attack type (real run data)."""
        by_defense: dict[str, dict[str, int]] = {}
        by_tier: dict[int, dict[str, dict[str, int]]] = {}
        by_attack: dict[str, dict[str, dict[str, int]]] = {}
        for r in self.results:
            names = [n for n in (r.get("blocking_defense"), r.get("would_block_defense")) if n]
            for name in names:
                d = by_defense.setdefault(name, {"blocked": 0, "total": len(self.results)})
                d["blocked"] += 1
                t = by_tier.setdefault(r.get("tier", 0), {}).setdefault(
                    name, {"blocked": 0, "total": 0})
                t["blocked"] += 1
                t["total"] += 1
                a = by_attack.setdefault(r.get("attack_type") or "error", {}).setdefault(
                    name, {"blocked": 0, "total": 0})
                a["blocked"] += 1
                a["total"] += 1
        for name, d in by_defense.items():
            d["effectiveness"] = round(d["blocked"] / d["total"] * 100, 2) if d["total"] else 0
        return {"by_defense": by_defense, "by_tier": by_tier, "by_attack_type": by_attack}

    def get_results_by_tier(self) -> dict[int, dict[str, Any]]:
        """Group results by tier with verdict breakdowns."""
        by_tier: dict[int, list[dict[str, Any]]] = {}
        for r in self.results:
            tier = r["tier"]
            by_tier.setdefault(tier, []).append(r)
        return {
            tier: {
                "count": len(r),
                "success": sum(1 for x in r if x["success"]),
                "vulnerable": sum(1 for x in r if x.get("vulnerable")),
                "blocked": sum(1 for x in r if x.get("blocked")),
            }
            for tier, r in by_tier.items()
        }

    def get_results_by_attack_type(self) -> dict[str, dict[str, Any]]:
        """Group results by attack type with verdict breakdowns."""
        by_type: dict[str, list[dict[str, Any]]] = {}
        for r in self.results:
            atype = r.get("attack_type") or "error"
            by_type.setdefault(atype, []).append(r)
        return {
            atype: {
                "count": len(r),
                "success": sum(1 for x in r if x["success"]),
                "vulnerable": sum(1 for x in r if x.get("vulnerable")),
                "blocked": sum(1 for x in r if x.get("blocked")),
            }
            for atype, r in by_type.items()
        }

    def export_results(self, format: str = "json") -> str:
        """Export results to specified format."""
        if format == "json":
            return json.dumps(self.results, indent=2)
        return str(self.results)


class BatchExecutor:
    """Parallel batch executor for testing multiple models simultaneously.

    Supports 50+ concurrent requests with circuit breaker and error recovery.
    """

    def __init__(
        self,
        max_concurrent: int = 50,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_timeout: int = 300,
    ) -> None:
        self.max_concurrent = max_concurrent
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.circuit_breaker_timeout = circuit_breaker_timeout
        self.circuit_states: dict[str, dict] = {}

    def check_circuit(self, model_name: str) -> bool:
        """Check if circuit breaker is open for a model."""
        state = self.circuit_states.get(model_name)
        if not state:
            return True
        if state["failures"] >= self.circuit_breaker_threshold:
            if time.time() - state["last_failure"] < self.circuit_breaker_timeout:
                return False
        return True

    def record_failure(self, model_name: str) -> None:
        """Record a failure for circuit breaker."""
        state = self.circuit_states.setdefault(
            model_name, {"failures": 0, "last_failure": 0}
        )
        state["failures"] += 1
        state["last_failure"] = time.time()

    def record_success(self, model_name: str) -> None:
        """Record a success to reset circuit breaker."""
        if model_name in self.circuit_states:
            self.circuit_states[model_name]["failures"] = 0
