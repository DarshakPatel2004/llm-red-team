#!/bin/bash
# Build and package script
set -e

echo "Building LLM Red Team Suite..."

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest --cov=llm_red_team

# Lint
ruff check llm_red_team/

# Type check
mypy llm_red_team/

# Build package
python -m build

echo "Build complete!"
