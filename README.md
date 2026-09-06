# README.md

# LLM Red Team Suite

Enterprise-grade LLM security testing framework with flexible model support.

## Features

- **Model-Agnostic**: Works with any LLM (API, local, custom)
- **Abstract Client Interface**: Plug-and-play for any LLM provider
- **Configuration-Driven**: YAML-based model selection
- **CLI Flexibility**: `--models claude,gpt4,llama` or `--models all`
- **40 Architectural Test Vectors**: Tokenization, Attention, Embedding, Training
- **18 Defense Strategies**: Prompt, Model, Pipeline, Architecture level
- **Attribution Engine**: Root cause analysis and severity scoring
- **Production Tools**: ML injection detector, CI/CD integrations

## Quick Start

```bash
# Install
pip install llm-red-team

# List models
llm-red-team models list

# Run tests (dry-run with mock)
llm-red-team run --dry-run

# Run with specific models
llm-red-team run --models claude,gpt4

# Health check
llm-red-team health
```

## Installation

```bash
pip install llm-red-team
```

## Usage

```bash
# Run all enabled models
llm-red-team run --all-enabled

# Run with specific tiers
llm-red-team run --tiers 1,2,3

# Run dry-run with mock client
llm-red-team run --dry-run

# Add a custom model
llm-red-team models add --name my-model --type api --provider custom

# Generate report
llm-red-team report --format json --output results.json
```

## Configuration

Edit `configs/models.yaml` to configure models. See [MODEL_ADDITION_GUIDE.md](docs/MODEL_ADDITION_GUIDE.md) for details.

## License

MIT
