#!/usr/bin/env bash
echo "PYTEST_ADDOPTS=-n $(python3 "$(dirname "$0")/worker_count.py")" >> "$GITHUB_ENV"
