#!/bin/bash

bbot_dir="$( realpath "$(dirname "$(dirname "${BASH_SOURCE[0]}")")")"
echo -e "[+] BBOT dir: $bbot_dir\n"

echo "[+] Checking code formatting with black"
echo "======================================="
black --check "$bbot_dir" || exit 1
echo

echo "[+] Linting with flake8"
echo "======================="
flake8 "$bbot_dir" || exit 1
echo

echo "[+] Testing with pytest"
pytest --exitfirst --disable-warnings --log-cli-level=ERROR "$bbot_dir" --cov=bbot/test/test_step_2/test_cli.py --cov-report="term-missing" --cov-config="$bbot_dir/test/coverage.cfg"
