#!/bin/sh
# Regenerates minified/: a copy of every fixture minified the way sites ship their code. Needs terser.
# AngularJS code that injects by parameter name stops working once minified, so it gets no copy.
set -e
cd "$(dirname "$0")"
rm -rf minified
find . -name '*.js' -not -path './minified/*' | sort | while read -r fixture; do
  head -n 1 "$fixture" | grep -q 'by parameter name' && continue
  mkdir -p "minified/$(dirname "$fixture")"
  terser "$fixture" --compress --mangle --output "minified/$fixture"
done
