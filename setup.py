#!/usr/bin/env python
"""Build script for LLM Red Team Suite."""

from setuptools import setup, find_packages

setup(
    name="llm-red-team",
    version="0.1.0",
    description="Enterprise LLM security testing framework",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.25.0",
        "openai>=1.0.0",
        "anthropic>=0.18.0",
        "google-generativeai>=0.3.0",
        "pyyaml>=6.0",
        "click>=8.1.0",
        "sqlalchemy>=2.0",
        "rich>=13.0",
        "tenacity>=8.2",
    ],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "llm-red-team=llm_red_team.api.cli:main",
        ],
    },
)
