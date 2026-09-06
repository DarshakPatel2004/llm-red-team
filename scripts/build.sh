#!/bin/bash
# Build script for LLM Red Team Suite
set -e
echo "Installing dependencies..."
pip install -e ".[dev]"
echo "Running tests..."
python -m pytest llm_red_team/tests/ -v --tb=short
echo "Running CLI validation..."
llm-red-team validate
echo "Running health check..."
llm-red-team health
echo "Build complete!"