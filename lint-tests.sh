#!/bin/bash

# Locally runs the same commands that the Github Action does.
# Run this script before pushing to avoid Github Push issues.

RED="\e[31m"
GREEN="\e[32m"
BLUE="\e[34m"
ENDCOLOR="\e[0m"

# Run Black
echo -e "${GREEN}Running Black${ENDCOLOR}"
black .
echo \

# Run Flake8
echo -e "${GREEN}Running Flake8${ENDCOLOR}"
flake8 --select F,E722 --ignore F403,F405,F541 --per-file-ignores="*/__init__.py:F401,F403"
echo -e "${BLUE}All Done!${ENDCOLOR}"

echo \

# Show Changes
echo -e "${GREEN}Showing Changes Made from Black & Flake8 (using git status)${ENDCOLOR}"
git status
echo \
