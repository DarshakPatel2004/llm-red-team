# METHODOLOGY.md

## Research Approach

1. **Adversarial Prompt Design**: Prompts designed across 4 tiers from basic to real-world attacks
2. **Attack Taxonomy**: 8 vulnerability categories with 3 root cause families
3. **Validation**: Each test validated against known vulnerable model behaviors
4. **Reproducibility**: All tests are deterministic with configurable parameters

## Security Constraints

- No extracting training data
- No reverse-engineering model weights
- No malicious exploitation
- No zero-day disclosure without responsible disclosure
- No indefinite maintenance (time-boxed to 20 weeks)
- No ML training from scratch (rule-based first)

## Validation Methods

- Cross-model correlation for vulnerability confirmation
- Multiple prompt variants per vulnerability
- Statistical significance testing (3 runs minimum)
- False positive rate measurement for all defenses
- Cost-benefit analysis for defense recommendations
