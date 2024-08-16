#!/bin/bash

bbot_dir="$( realpath "$(dirname "$(dirname "${BASH_SOURCE[0]}")")")"
echo -e "[+] BBOT dir: $bbot_dir\n"

echo "[+] Checking code formatting with black"
echo "======================================="
black --check "$bbot_dir" || exit 1
echo

echo "[+] Linting with flake8"
echo "======================="
flake8 --select F,E722 --ignore F403,F405,F541 --per-file-ignores="*/__init__.py:F401,F403" "$bbot_dir" || exit 1
echo

if [ "${1}x" != "x" ] ; then
  MODULES=`echo ${1} | sed -e 's/,/ /g'`
  for MODULE in ${MODULES} ; do
    echo "[+] Testing ${MODULE} with pytest"
    pytest --exitfirst --disable-warnings --log-cli-level=ERROR "$bbot_dir" --cov=bbot/test/test_step_2/test_cli.py --cov-report="term-missing" --cov-config="$bbot_dir/test/coverage.cfg" -k ${MODULE}
  done
else
  echo "[+] Testing all modules with pytest"
  pytest --exitfirst --disable-warnings --log-cli-level=ERROR "$bbot_dir" --cov=bbot/test/test_step_2/test_cli.py --cov-report="term-missing" --cov-config="$bbot_dir/test/coverage.cfg"
fi
