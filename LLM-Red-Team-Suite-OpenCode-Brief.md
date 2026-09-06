# LLM-Red-Team-Suite: OpenCode Execution Brief

## PROJECT OVERVIEW

**Objective:**
Build enterprise-grade LLM security testing framework with flexible model support.
100% OpenCode execution. Support any LLM (closed APIs, open-source, local, custom).

---

## ARCHITECTURE REQUIREMENT

**Core Design Principle:**
- Abstract model client interface (plug-and-play for any LLM)
- Configuration-driven model selection (YAML)
- CLI flexibility: `--models claude,gpt4,llama,mistral,gemini` or `--models all` or `--models custom-model-1,custom-model-2`
- Users can easily add custom models without code changes
- Support multiple deployment types: API-based (Anthropic, OpenAI, Google, Replicate, etc.), Local (Ollama, vLLM), Custom deployments

---

## EXECUTION PHASES

### Phase 1: RESEARCH & DESIGN (1 week)
**Tasks:**
- Design 100 adversarial prompts across 4 tiers:
  * Tier 1 Basic (20): direct jailbreaks, simple extraction, straightforward contradictions
  * Tier 2 Intermediate (30): multi-turn attacks, obfuscation, nested roles, prompt smuggling, logical confusion
  * Tier 3 Advanced (25): adaptive prompts, meta-prompting, few-shot exploitation, token boundary attacks, context dilution
  * Tier 4 Real-World (25): supply chain injection, multi-user environments, RAG pipeline exploitation, LLM cascading, production inference attacks

- Design 40 architectural test vectors:
  * Tokenization (8): whitespace, UTF-8, token boundaries, OOV, special chars, encoding, collision, padding
  * Attention (7): long-context dilution, positional encoding, head targeting, Query/Key/Value, multi-head coordination, RoPE weaknesses, scaling attacks
  * Embedding (6): semantic drift, OOD perturbations, embedding inversion, adversarial examples, subspace capture, orthogonal perturbations
  * Training Artifacts (7): memorization detection, bias amplification, data poisoning, paraphrase extraction, catastrophic forgetting, mode collapse, distribution shift
  * Fine-tuning (5): instruction degradation, LoRA/adapter bypass, gradient attacks, few-shot regression, safety-tuning circumvention
  * Model-Specific (5 per model): Model-specific vulnerabilities (Claude RLHF, GPT-4 RL biases, Gemini multimodal, Llama fine-tuning, Mistral parameter efficiency)

**Output:** 100 structured adversarial prompts + 40 test vector specifications (YAML format)

---

### Phase 2: PROJECT SCAFFOLD & SETUP (3 days)
**Tasks:**
- Create production project structure
- Set up GitHub repository
- **Design abstract LLM client interface:**
  ```python
  class LLMClient(ABC):
      def __init__(self, model_id: str, config: dict): pass
      def query(self, prompt: str, **kwargs) -> dict: pass
      def supports_streaming(self) -> bool: pass
      def get_model_info(self) -> dict: pass
  ```
- Implement concrete clients:
  * Anthropic (Claude) API wrapper
  * OpenAI (GPT-4) API wrapper
  * Google (Gemini) API wrapper
  * Ollama client (local models)
- Create custom client template (for users to extend)
- **Implement configuration system:**
  ```yaml
  models:
    claude:
      type: api
      provider: anthropic
      model_id: claude-3-opus
      enabled: true
    custom:
      type: api
      provider: custom
      endpoint: https://...
      enabled: false
  ```
- Set up database schema + logging
- Configure pytest framework

**Output:** Production-ready extensible project scaffold

---

### Phase 3: RED TEAM ENGINE (2 weeks)
**Tasks:**
- Build abstract model runner (works with any LLM client)
- Implement parallel batch executor (50+ concurrent requests)
- Build response classifier:
  * Success/Failure/Partial detection
  * Response parsing
  * Metadata extraction (tokens, latency, confidence)
- Implement prompt variations engine:
  * Auto-mutate prompts
  * Generate permutations
  * Context variations
- **Build unified CLI:**
  ```bash
  llm-red-team run --all-enabled
  llm-red-team run --models claude,llama,custom-model
  llm-red-team run --tiers 1,2,3
  llm-red-team models list
  llm-red-team models add --name model-name --type api --provider custom
  llm-red-team report --format json --output results.json
  ```
- Implement configuration loader
- Add error recovery + timeout handling

**Output:** Full red team engine; can test 100 prompts against any number of models

---

### Phase 4: ARCHITECTURAL ANALYSIS (2 weeks)
**Tasks:**
- Implement tokenization attack module (8 test vectors):
  * Whitespace/control character boundary tests
  * UTF-8 encoding exploits
  * Token reconstruction attacks
  * Rare token handling
  * Run all tests against all models
  
- Implement attention probing module (7 test vectors):
  * Long-context dilution tests
  * Positional encoding attacks
  * Attention head targeting analysis
  * Run all tests against all models

- Implement embedding manipulation module (6 test vectors):
  * Semantic drift testing
  * OOD perturbation generation
  * Embedding space probing
  * Run all tests against all models

- Implement training artifact detector (7 test vectors):
  * Memorization tests
  * Bias amplification triggers
  * Data poisoning pattern detection
  * Run all tests against all models

- Implement fine-tuning vulnerability tester (5 test vectors):
  * Instruction degradation tests
  * LoRA/adapter bypass attempts
  * Multi-task forgetting triggers
  * Run all tests against all models

- Implement model-specific analyzers:
  * Auto-detect model type and run relevant tests
  * Generate model-specific vulnerability assessments

- Integrate all tests into unified framework

**Output:** 40 automated architectural tests; results database for any model configuration

---

### Phase 5: ATTRIBUTION ENGINE (1 week)
**Tasks:**
- Build vulnerability type classifier:
  * 8 categories: Prompt Injection, Jailbreak, Leakage, Capability Probing, Memory Extraction, Adversarial Robustness, Logic Manipulation, Output Exploitation
  * Classify every successful attack

- Build root cause analyzer:
  * Identify root causes: Tokenization Bypass, Attention Failure, Embedding Space, Training Artifact, RLHF Misalignment, Fine-tuning Regression, Architecture Limitation
  * Generate explanations for why attacks work

- Build severity scorer:
  * Exploitability (1-10): How easy is the attack?
  * Impact (1-10): What can attacker achieve?
  * Detectability (1-10): How obvious is it?
  * Uniqueness (1-10): Is this model-specific?
  * Combined Score = weighted(exploitability, impact, detectability, uniqueness)

- Build pattern matcher:
  * Cross-model correlation (which vulnerabilities appear in multiple models)
  * Attack success pattern analysis
  * Vulnerability clustering

- Create attribution database:
  * Link every successful attack to root cause
  * Store severity scores
  * Apply pattern tags
  * Works with any number of models

**Output:** Complete root cause analysis for every vulnerability; attribution database

---

### Phase 6: DEFENSE ENGINE (2 weeks)
**Tasks:**
- Implement 18 defense strategies:

  **Prompt-Level (5):**
  1. Contradiction detection (detect conflicting instructions)
  2. Role-play filtering (detect character assumption)
  3. System prompt reinforcement (explicit constraints)
  4. Semantic boundary marking (separate system from user)
  5. Instruction tokenization hardening (escape control characters)

  **Model-Level (5):**
  6. Output validation (scan for jailbreak indicators)
  7. Response filtering (pattern matching)
  8. Tokenization hardening (respect control boundaries)
  9. Embedding space constraints (detect adversarial inputs)
  10. Confidence thresholding (reject low-confidence outputs)

  **Pipeline-Level (4):**
  11. Context isolation (separate attention heads)
  12. Rate limiting + anomaly detection
  13. Input sanitization (detect adversarial patterns)
  14. Output modification (neutralize harmful content)

  **Architecture-Level (4):**
  15. Fine-tuning strategy (safety-aware LoRA)
  16. Auxiliary safety model (secondary validator)
  17. Constitutional AI (rule-based safety)
  18. Adversarial training data (expose during training)

- For each defense, implement:
  * Core logic
  * Effectiveness tester (% attacks blocked)
  * False positive analyzer (% legitimate queries blocked)
  * Performance profiler (latency impact)
  * Configuration system (enable/disable, parameters)

- Build adaptive recommender:
  * Suggest top N defenses based on vulnerability profile
  * Rank by effectiveness + cost trade-off
  * Generate defense stacking recommendations
  * Works with any model set

- Create defense evaluation framework:
  * Run each defense against all prompts
  * Per-model testing
  * Generate effectiveness matrix

**Output:** 18 fully implemented defense strategies; effectiveness matrix for any model configuration

---

### Phase 7: TESTING & DATA COLLECTION (2 weeks)
**Tasks:**
- Execute full test suite against all enabled models:
  * Run 100 prompts × M models = 100M tests
  * Run 40 architecture tests × M models = 40M tests
  * Parallel execution (auto-scale based on model count)
  * Timeout handling + error recovery

- Run defense evaluation:
  * Test 18 defenses against 100 prompts
  * Per-model testing
  * Parallel execution

- Aggregate results:
  * Store in structured database
  * Generate summary statistics
  * Flag anomalies

- Quality assurance:
  * Verify all tests executed
  * Check data consistency
  * Validate response parsing
  * Regenerate failed tests

**Output:** Complete results database; clean, analyzable data

---

### Phase 8: ANALYSIS ENGINE (2 weeks)
**Tasks:**
- Build vulnerability matrix generator:
  * Create heatmap: M models × 8 attack categories × success rate
  * Export to JSON, CSV, HTML
  * Dynamic dimensions (works with any model count)

- Build model ranker:
  * Overall security score per model (0-100)
  * Rank from most to least secure
  * Breakdown by vulnerability type
  * Trend analysis

- Build pattern analyzer:
  * Which attack types succeed most often?
  * Which models are vulnerable to what?
  * Correlation matrix (vulnerability overlap)
  * Predictive analysis

- Build defense effectiveness matrix:
  * Defense Strategy × LLM × Success Rate
  * Highlight which defenses work on which models
  * Cost-benefit analysis

- Build deployment advisor:
  * Recommend safest model per use case
  * Best defenses for each scenario
  * Cost-latency trade-off analysis
  * Risk assessment

- Build visualizer:
  * Vulnerability heatmaps
  * Model ranking charts
  * Attack success rate graphs
  * Defense effectiveness comparisons
  * Interactive dashboard (Vue/React with dynamic model selection)

**Output:** Complete analysis suite; all visualizations and reports

---

### Phase 9: REPORT GENERATION (1 week)
**Tasks:**
- Generate Vulnerability Assessment Report (60+ pages):
  * Executive summary (2 pages)
  * Methodology (5 pages)
  * Per-model analysis (dynamic: 10-15 pages per model)
  * Attack categorization + root cause (20 pages)
  * Severity rankings (5 pages)
  * Recommendations (8 pages)
  * Case studies (5 pages)

- Generate Defense Playbook (40+ pages):
  * Overview (2 pages)
  * Prompt-Level Defenses (8 pages): explanations, code, deployment guides, metrics
  * Model-Level Defenses (8 pages): same structure
  * Pipeline-Level Defenses (6 pages): same structure
  * Architecture-Level Defenses (6 pages): same structure
  * Best Practices + Emergency Response (10 pages)

- Generate Research Paper (25-30 pages):
  * Abstract
  * Introduction
  * Related Work
  * Novel Attack Taxonomy
  * Root Cause Attribution Framework
  * Architectural Vulnerability Analysis
  * Defense Effectiveness Evaluation
  * Comparative Security Assessment
  * Limitations & Future Work
  * References

- Generate executive summary + blog post

**Output:** Publication-quality reports (60 + 40 + 25+ pages)

---

### Phase 10: PRODUCTION TOOLS (1 week)
**Tasks:**
- Build ML-based injection detector:
  * Train on 100 adversarial prompts
  * Feature extraction
  * RandomForest or XGBoost classifier
  * Real-time prediction (<10ms)
  * Confidence scoring
  * Make pip installable

- Build supply chain validator:
  * Scan third-party prompts
  * Detect adversarial patterns
  * Flag suspicious prompts
  * Integration with common retrieval systems

- Build CI/CD integrations:
  * GitHub Actions template
  * GitLab CI template
  * Jenkins template
  * Scan prompts on commit
  * Fail builds if injection detected

- Build threat intelligence feed:
  * Catalog of 100 adversarial prompts (searchable)
  * Attack pattern descriptions
  * Root cause explanations
  * Defense recommendations
  * JSON API interface

- Create Docker container:
  * Full toolkit
  * Flexible model configuration
  * Easy deployment

**Output:** Production-ready tools; deployment guides; CI/CD templates

---

### Phase 11: DOCUMENTATION & RELEASE (1 week)
**Tasks:**
- Generate complete documentation:
  * README.md (quick start, installation, usage)
  * ARCHITECTURE.md (system design, module overview)
  * METHODOLOGY.md (research approach, validation)
  * API.md (function signatures, parameters, examples)
  * MODEL_ADDITION_GUIDE.md (how to add custom models)
  * DEPLOYMENT.md (production setup, scaling)
  * CONTRIBUTING.md (extension guide)

- Create video tutorials:
  * Installation & setup (5 min)
  * Running full suite (5 min)
  * Interpreting results (10 min)
  * Deploying defenses (10 min)
  * Adding custom models (5 min)

- Create interactive demo:
  * Web interface to run tests
  * Visualize vulnerabilities
  * Explore attack library
  * Test defenses
  * Generate custom reports
  * **Dynamic model selection**

- Package for release:
  * PyPI package (`pip install llm-red-team`)
  * GitHub releases
  * Docker Hub image
  * Conda package
  * Version tagging

- Create community resources:
  * Discussion forum setup
  * Issue templates
  * Pull request templates
  * Code of conduct

**Output:** Public-ready release; full documentation

---

## DELIVERABLES (Final)

### GitHub Repository
- Production Python package (pip installable)
- 100 adversarial prompts (YAML, categorized)
- 40 architectural test vectors (integrated)
- Abstract model client interface + concrete implementations
- Custom model template for users
- CLI with flexible model management
- Full documentation + model addition guide
- 10-15 example notebooks
- Docker deployment configuration
- CI/CD integration templates

### Reports & Papers
- 60+ page Vulnerability Assessment Report (dynamic per model set)
- 40+ page Defense Playbook
- 25+ page Research Paper
- Executive summary + blog post

### Tools
- ML-based injection detector (pip installable)
- Supply chain validator
- CI/CD integrations (GitHub Actions, GitLab, Jenkins)
- Threat intelligence feed + JSON API
- Docker container deployment
- Web-based interactive demo

### Analysis & Data
- Vulnerability matrix (M models × 8 categories × success rate)
- Model security rankings
- Defense effectiveness matrix
- Attack pattern analysis
- Root cause attribution database
- Interactive visualizations + dashboard

---

## DEFAULT TEST CONFIGURATION

**Default Models (Easily Configurable):**
- Claude (Anthropic API)
- GPT-4 (OpenAI API)
- Llama (Local via Ollama)
- Mistral (Local via Ollama)
- Gemini (Google API)

**Attacks & Tests:**
- 100 adversarial prompts (4 tiers)
- 40 architectural test vectors
- 18 defense strategies

**Note:** Any of these can be swapped, disabled, or supplemented with custom models through configuration.

---

## MODEL FLEXIBILITY SYSTEM

### Configuration Example
```yaml
models:
  claude:
    type: api
    provider: anthropic
    model_id: claude-3-opus
    api_key: ${ANTHROPIC_API_KEY}
    enabled: true
    
  gpt4:
    type: api
    provider: openai
    model_id: gpt-4
    api_key: ${OPENAI_API_KEY}
    enabled: true
    
  llama:
    type: local
    provider: ollama
    model_id: llama2:13b
    endpoint: http://localhost:11434
    enabled: true
    
  mistral:
    type: local
    provider: ollama
    model_id: mistral:7b
    endpoint: http://localhost:11434
    enabled: true
    
  gemini:
    type: api
    provider: google
    model_id: gemini-pro
    api_key: ${GOOGLE_API_KEY}
    enabled: false
    
  custom_model:
    type: api
    provider: custom
    endpoint: https://custom-api.com
    api_key: ${CUSTOM_API_KEY}
    enabled: false
```

### CLI Flexibility Examples
```bash
# Run with all enabled models
llm-red-team run --all-enabled

# Run with specific models
llm-red-team run --models claude,llama,mistral

# Run with custom models
llm-red-team run --models custom_model_1,custom_model_2

# Run specific tiers/tests
llm-red-team run --models all --tiers 1,2

# List available models
llm-red-team models list

# Add new model
llm-red-team models add --name new-model --type api --provider custom --endpoint https://...

# Generate reports for specific model set
llm-red-team report --models claude,gpt4 --format html --output report.html
```

---

## TIMELINE

| Phase | Weeks | Activity |
|-------|-------|----------|
| 1. Research & Design | 1-2 | Design 100 prompts + 40 test vectors |
| 2. Project Scaffold | 3 | Set up extensible framework |
| 3. Red Team Engine | 4-6 | Build attack toolkit (works with any model) |
| 4. Architecture Analysis | 7-8 | Implement 40 test vectors |
| 5. Attribution Engine | 9 | Build root cause analyzer |
| 6. Defense Engine | 10-12 | Implement 18 defense strategies |
| 7. Testing | 13-15 | Execute full suite |
| 8. Analysis | 16-17 | Generate analysis + visualizations |
| 9. Production Tools | 18 | Build detector, CI/CD, tools |
| 10. Documentation | 19 | Write guides + examples |
| 11. Release | 20 | Publish + announce |
| **TOTAL** | **20 weeks** | **Full production-ready framework** |

---

## SUCCESS CRITERIA

✅ 100 adversarial prompts (across 4 tiers)
✅ 40 architectural test vectors
✅ Works with any LLM (open, closed, local, custom)
✅ Default 5 models tested (configurable)
✅ Root cause attribution for every vulnerability
✅ 18 defense strategies tested
✅ Vulnerability matrix (M × 8)
✅ Model security ranking
✅ 60+ page assessment report
✅ 40+ page defense playbook
✅ 25+ page research paper
✅ Production ML-based injection detector
✅ CI/CD integrations (GitHub, GitLab, Jenkins)
✅ Interactive dashboard (dynamic model selection)
✅ Public GitHub repository (extensible, well-documented)
✅ Full documentation + model addition guide

---

## CONSTRAINTS

- ❌ No extracting training data
- ❌ No reverse-engineering model weights
- ❌ No exploiting vulnerabilities maliciously
- ❌ No publishing zero-days without disclosure
- ❌ No indefinite maintenance (time-boxed project)
- ❌ No ML training (too compute-intensive)

---

## READY TO START

All phases scoped. All deliverables defined. Architecture designed for flexibility.
OpenCode handles 100% of execution.

**Status: READY FOR OPENCODE EXECUTION**

---

## RECOMMENDED REFINEMENTS (Detailed)

### 1. Trim to MVP Scope

The full 20-week plan is overambitious. A phased MVP approach is more realistic and allows shipping a working product quickly:

| Phase | MVP Scope | Full Scope |
|-------|-----------|------------|
| Phase 1 | 20 prompts (Tier 1 only) | 100 prompts across 4 tiers |
| Phase 2 | 3 concrete clients (Claude, GPT-4, Ollama) + config | 4 clients + custom template |
| Phase 3 | Sequential runner with basic executor | Parallel batch (50+ concurrent) |
| Phase 4 | 8 tokenization vectors | All 40 vectors |
| Phases 5-11 | Defer to V2 | Full pipeline |

**Rationale:** Shipping a working MVP in ~6 weeks lets you validate the architecture, gather real findings, and iterate based on actual attack results rather than theoretical design.

---

### 2. Fix the `LLMClient` Interface

The current ABC is missing critical methods required for production use:

```python
class LLMClient(ABC):
    def __init__(self, model_id: str, config: dict): pass
    def query(self, prompt: str, **kwargs) -> dict: pass
    def chat(self, messages: list[dict], **kwargs) -> dict: pass
    def stream(self, prompt: str, **kwargs) -> Generator: pass
    def supports_streaming(self) -> bool: pass
    def get_model_info(self) -> dict: pass
    def get_token_count(self, text: str) -> int: pass
    def get_cost_estimate(self, prompt: str) -> float: pass
```

**Why each addition matters:**
- **`chat(messages)`**: Modern APIs (OpenAI, Anthropic, Google) all use chat-completion format — `query()` alone is insufficient for multi-turn attacks (Tier 2+ prompts)
- **`stream()`**: Essential for long-running red team tests without hanging; enables real-time progress tracking
- **`get_token_count(text)`**: Required for cost tracking, token-boundary attack vectors (Tier 3), and prompt length validation
- **`get_cost_estimate(prompt)`**: Lets users budget before running batches; prevents surprise API bills

---

### 3. Add a Mock/Simulator Client

Without API keys, no one can test the framework. Add a mock client:

```python
class MockClient(LLMClient):
    """Simulates LLM responses for testing without API access."""
    
    def __init__(self, model_id: str, config: dict):
        self.response_patterns = load_mock_responses(model_id)
    
    def query(self, prompt: str, **kwargs) -> dict:
        return {
            "response": self._generate_response(prompt),
            "tokens": random.randint(10, 500),
            "latency_ms": random.randint(50, 500),
            "metadata": {"simulated": True}
        }
    
    def chat(self, messages: list[dict], **kwargs) -> dict:
        # Process message history for multi-turn simulation
        pass
    
    def stream(self, prompt: str, **kwargs) -> Generator:
        # Simulate streaming chunks
        pass
    
    def get_token_count(self, text: str) -> int:
        return len(text.split())
```

**Benefits:**
- Pytest suite runs without API keys
- CI/CD pipelines don't burn credits
- Developers prototype locally
- Mock can simulate various model behaviors (vulnerable vs. secure responses)
- Enables unit testing of all phases independently

---

### 4. Fix the ML Training Contradiction

Phase 10 requires "Train on 100 adversarial prompts" but the constraints say "No ML training." Resolution:

- **Option A (Recommended):** Replace ML classifier with rule-based pattern matching (regex + keyword heuristics). Simpler, faster, no training needed. Start with 20 high-confidence patterns and expand as real data accumulates
- **Option B:** Keep ML but reframe as "fine-tuning a pre-trained open-source model" using existing open-source weights — not training from scratch
- **Option C:** Remove the ML detector entirely from Phase 10 and add it to V2 as an optional enhancement with proper data collection from Phase 7 results

**Recommendation:** Start with **Option A**. After Phase 7 generates real results, use that data to build a proper ML model in V2. This also aligns with the "No ML training" constraint.

---

### 5. Fix Phase 7 Test Volume

"100 prompts × M models = 100M tests" is mathematically incorrect and practically infeasible:

- 100 prompts × 5 models = **500 test calls** (not 100M)
- Each prompt runs **3 times** for statistical variance = 1,500 calls
- 40 architectural vectors × 5 models × 3 runs = **600 calls**
- **Total per full suite: ~2,100 calls**

**Practical implications:**
- Even at $0.01/call, full run costs ~$21
- At typical API rate limits, full run takes ~2-4 hours
- Need exponential backoff and retry logic built in
- Results must be cached to avoid re-running identical tests
- Should implement a `--dry-run` flag using MockClient to validate configuration before live execution

---

### 6. Add Missing Configuration Fields

The YAML config needs more fields for production reliability:

```yaml
models:
  claude:
    type: api
    provider: anthropic
    model_id: claude-3-opus-20240229
    api_key: ${ANTHROPIC_API_KEY}
    enabled: true
    max_tokens: 4096
    temperature: 0.7
    timeout: 30              # seconds
    retry_attempts: 3
    rate_limit: 10           # requests per minute
    headers: {}              # custom headers
    tags: [security, production]
```

**Why each field matters:**
- **`max_tokens`**: Controls cost per request, prevents runaway generations
- **`temperature`**: Affects reproducibility of results; lower for consistent attack testing
- **`timeout`**: Prevents hanging on unresponsive APIs
- **`retry_attempts`**: Essential for transient network failures
- **`rate_limit`**: Prevents API ban; critical for batch execution
- **`tags`**: Enables filtering by category (production, experimental, etc.)

---

### 7. Add Results Database Schema

Phase 2 mentions "Set up database schema" but doesn't specify it. Recommended schema:

```sql
-- Track all models
CREATE TABLE models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    model_id VARCHAR(100) NOT NULL,
    type VARCHAR(20) NOT NULL,  -- api, local, custom
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Track all adversarial prompts
CREATE TABLE prompts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tier INT NOT NULL CHECK (tier BETWEEN 1 AND 4),
    category VARCHAR(50) NOT NULL,
    prompt_text TEXT NOT NULL,
    attack_type VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Store all test results
CREATE TABLE test_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_id UUID REFERENCES models(id),
    prompt_id UUID REFERENCES prompts(id),
    attack_category VARCHAR(50),
    tier INT,
    prompt_text TEXT,
    response TEXT,
    tokens_used INT,
    latency_ms INT,
    success BOOLEAN,
    severity_score FLOAT,
    vulnerability_type VARCHAR(50),
    root_cause VARCHAR(100),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Track defense evaluations
CREATE TABLE defense_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    defense_strategy VARCHAR(100) NOT NULL,
    model_id UUID REFERENCES models(id),
    prompt_id UUID REFERENCES prompts(id),
    blocked BOOLEAN,
    false_positive BOOLEAN,
    latency_impact_ms INT,
    effectiveness_score FLOAT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_results_model ON test_results(model_id);
CREATE INDEX idx_results_prompt ON test_results(prompt_id);
CREATE INDEX idx_results_vuln_type ON test_results(vulnerability_type);
CREATE INDEX idx_results_created ON test_results(created_at);
```

---

### 8. Add Error Recovery Strategy

Phase 3 mentions "error recovery + timeout handling" but needs specifics:

**Retry Logic:**
- Exponential backoff: 2s → 4s → 8s with random jitter (±20%)
- Max 3 retries per request before marking as failed
- Only retry on idempotent operations (GET-like calls)
- Log all retries with increasing severity

**Circuit Breaker:**
- After 5 consecutive failures on a model, disable it for 5 minutes
- After 10 consecutive failures, disable for 15 minutes
- After 20 consecutive failures, disable for 1 hour and alert
- Automatic recovery test every 5 minutes while disabled
- Circuit state visible via `llm-red-team models status`

**Timeout Handling:**
- Default: 30s per request
- Configurable per model in YAML
- Streaming requests: 120s default
- On timeout: mark test as `failed: timeout`, save partial metadata

**Result Preservation:**
- Save results immediately after each test (not batch-at-end)
- Write to database AND local JSON backup
- On crash/restart, resume from last saved checkpoint
- Track `completed_prompts` and `failed_prompts` separately

**Fallback Strategy:**
- If primary model fails, optionally run on MockClient to continue validation
- Flag fallback results clearly in output (`"source": "mock-fallback"`)

---

### 9. Add Version Control & Git Workflow

Phase 2 says "Set up GitHub repository" but needs a defined branching strategy:

```
main           → Stable, tagged releases (v1.0.0, etc.)
develop        → Integration branch for next release
feature/phase-{n} → Per-phase feature branches
feature/mock-client → Isolated mock testing branch
bugfix/{issue} → Bug fixes
hotfix/{issue} → Critical production fixes
```

**Workflow:**
- PRs required for all merges to `develop` and `main`
- At least one reviewer approval needed
- Conventional commits format: `feat:`, `fix:`, `docs:`, `test:`
- Auto-generated changelogs per release using `auto-changelog` or `semantic-release`
- Branch protection: require CI passing before merge
- Tag releases with version numbers matching PyPI packages

---

### 10. Add Monitoring & Logging

Production needs observability built in from Phase 2:

**Structured Logging:**
```json
{
  "timestamp": "2026-09-06T12:00:00Z",
  "level": "INFO",
  "model": "claude",
  "prompt_id": "uuid-123",
  "tokens_used": 250,
  "latency_ms": 340,
  "success": true,
  "vulnerability_type": "prompt_injection"
}
```

**Metrics to Track:**
- Request count per model per hour
- Error rate (by error type: timeout, auth, rate_limit)
- Average latency per model
- Token usage per model per day
- Cost estimate per run
- Attack success rate trends

**Alerting:**
- Slack/webhook on sustained failure rate >10%
- Alert on API key expiry warnings
- Notify on circuit breaker trips
- Daily summary email with key metrics

**Log Retention:**
- Debug logs: 7 days
- Results data: 90 days (configurable)
- Aggregated metrics: 1 year
- Raw responses: 30 days (storage optimization)

---

### 11. Add Input Validation & Safety Checks

Before any test executes, validate inputs:

```python
class SafetyValidator:
    """Validates all inputs before execution."""
    
    @staticmethod
    def validate_prompt(prompt: str) -> ValidationResult:
        """Check for empty prompts, excessively long inputs, encoding issues."""
        errors = []
        if not prompt.strip():
            errors.append("Empty prompt")
        if len(prompt) > 10000:
            errors.append("Prompt exceeds 10000 characters")
        if not is_valid_encoding(prompt):
            errors.append("Invalid encoding detected")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)
    
    @staticmethod
    def validate_config(config: dict) -> ValidationResult:
        """Ensure all required config fields are present and valid."""
        required_fields = ["type", "provider", "model_id", "api_key"]
        errors = []
        for field in required_fields:
            if field not in config:
                errors.append(f"Missing required field: {field}")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)
```

**Why it matters:**
- Prevents accidental self-inflicted damage
- Catches configuration errors before they waste API credits
- Validates encoding before sending to models (prevents UTF-8 exploits from breaking the tester itself)
- Enforces the constraint "No extracting training data" by flagging suspicious prompts

---

### 12. Add CLI Enhancement Suggestions

Beyond the specified CLI, add these commands:

```bash
# Health check
llm-red-team health  # Verify all configured models are reachable

# Dry run with mock client
llm-red-team run --dry-run --models claude

# Resume interrupted test run
llm-red-team run --resume --session-id uuid-123

# Export results in various formats
llm-red-team export --format pdf --output report.pdf
llm-red-team export --format junit --output tests.xml  # CI integration

# Compare models
llm-red-team compare --models claude,gpt4 --metrics latency,success_rate

# Validate configuration
llm-red-team validate-config  # Check YAML, test connections, report issues
```

---

### 13. Add Dependency Management

Need a proper `pyproject.toml` or `setup.py` with pinned dependencies:

```toml
[project]
name = "llm-red-team"
version = "0.1.0"
description = "Enterprise LLM security testing framework"
requires-python = ">=3.10"

dependencies = [
    "httpx>=0.25.0",
    "openai>=1.0.0",
    "anthropic>=0.18.0",
    "google-generativeai>=0.3.0",
    "pyyaml>=6.0",
    "click>=8.1.0",
    "sqlalchemy>=2.0",
    "rich>=13.0",
    "tenacity>=8.2",
]

[project.optional-dependencies]
dev = ["pytest>=7.0", "pytest-asyncio", "black", "ruff", "mypy"]
local = ["ollama>=0.2.0"]
```

---

### 14. Add Testing Strategy

A comprehensive testing approach beyond just pytest:

| Test Type | Tool | Purpose |
|-----------|------|---------|
| Unit Tests | pytest | Individual functions, client methods |
| Integration Tests | pytest + MockClient | Full pipeline end-to-end |
| Load Tests | locust / pytest-benchmark | 50+ concurrent requests |
| Contract Tests | pytest | Verify all clients implement LLMClient ABC |
| Regression Tests | pytest | Ensure new changes don't break existing tests |
| Security Tests | bandit, safety | Scan for vulnerabilities in our own code |
| Type Checks | mypy | Static type validation |
| Linting | ruff | Code style enforcement |

**Test Pyramid:**
- 70% unit tests
- 20% integration tests
- 10% end-to-end tests

---

### 15. Summary of All Changes

| Area | Current State | Recommended Change | Priority |
|------|--------------|-------------------|----------|
| Scope | 100 prompts, 20 weeks | MVP: 20 prompts, 6 weeks, defer rest to V2 | High |
| Client Interface | `query()` only | Add `chat()`, `stream()`, token/cost methods | High |
| Testing | Requires API keys | Add MockClient for zero-config testing | High |
| ML | Contradictory constraint | Rule-based first, ML as V2 enhancement | High |
| Test Volume | "100M tests" | ~2,100 actual calls with caching | Medium |
| Config | Minimal fields | Add timeout, rate-limit, tags, max_tokens | Medium |
| Database | Mentioned but not defined | Full SQL schema specified | Medium |
| Error Handling | Mentioned but vague | Exponential backoff, circuit breaker, fallback | Medium |
| Git | "Set up repo" | Defined branching strategy + PR workflow | Low |
| Observability | Not mentioned | Logging, metrics, alerting framework | Low |
| Safety | Not mentioned | Input validation and safety checks | Medium |
| CLI | Basic commands | Added health, resume, compare, validate, export | Medium |
| Dependencies | Not specified | Full pyproject.toml with pinned versions | Medium |
| Testing Strategy | "pytest framework" | Comprehensive test pyramid defined | Medium |
| Documentation | Phase 11 only | Add inline code examples, inline docstrings | Low |

---

**Status: REFINED — Ready for implementation with MVP approach**
