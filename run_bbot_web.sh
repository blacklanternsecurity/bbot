#!/bin/bash

set -euo pipefail

PLATFORM="${BBOT_DOCKER_PLATFORM:-}"

# Build the Docker image
if [ -n "${PLATFORM}" ]; then
    echo "[+] Building BBOT Guardian Docker image for ${PLATFORM}..."
    docker build --platform "${PLATFORM}" -t bbot-guardian .
else
    echo "[+] Building BBOT Guardian Docker image..."
    docker build -t bbot-guardian .
fi

# Run the container
echo "[+] Starting BBOT Guardian..."
echo "[+] Web Interface will be available at http://localhost:8765"

# Ensure scan directory exists on host to persist data
mkdir -p "$HOME/.bbot/scans"

ENV_ARG=""
TMP_ENV_FILE=""
if [ ! -z "$1" ]; then
    if [ -f "$1" ]; then
        echo "[+] Using .env file: $1"
        TMP_ENV_FILE="$(mktemp /tmp/bbot-guardian-env.XXXXXX)"
        # Docker --env-file does not understand shell-style inline comments or quoted values.
        # Normalize to plain KEY=VALUE lines.
        awk '
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            {
                eq = index($0, "=")
                if (eq == 0) next
                key = substr($0, 1, eq - 1)
                val = substr($0, eq + 1)

                gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
                sub(/[[:space:]]+#.*$/, "", val)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)

                if (val ~ /^".*"$/) {
                    val = substr(val, 2, length(val) - 2)
                }
                print key "=" val
            }
        ' "$1" > "$TMP_ENV_FILE"
        ENV_ARG="--env-file $TMP_ENV_FILE"
    else
        echo "[-] Error: .env file '$1' not found"
        exit 1
    fi
fi

RUN_PLATFORM_ARGS=()
if [ -n "${PLATFORM}" ]; then
    RUN_PLATFORM_ARGS+=(--platform "${PLATFORM}")
fi

DOCKER_TTY_ARGS=()
if [ -t 0 ] && [ -t 1 ]; then
    DOCKER_TTY_ARGS=(-it)
fi

docker run "${DOCKER_TTY_ARGS[@]:-}" --rm \
    "${RUN_PLATFORM_ARGS[@]:-}" \
    -p 8765:8765 \
    -v "$HOME/.bbot/scans:/root/.bbot/scans" \
    $ENV_ARG \
    --name bbot-guardian \
    bbot-guardian

if [ ! -z "$TMP_ENV_FILE" ] && [ -f "$TMP_ENV_FILE" ]; then
    rm -f "$TMP_ENV_FILE"
fi
