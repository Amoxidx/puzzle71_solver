#!/usr/bin/env bash
# Stops the disposable bitcoind regtest container started by regtest-up.sh. Idempotent: does
# nothing (and does not fail) if the container is not running.
set -euo pipefail

CONTAINER_NAME="p71-regtest"

if docker ps --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
    docker stop "${CONTAINER_NAME}" >/dev/null
    echo "regtest-down: stopped ${CONTAINER_NAME}" >&2
else
    echo "regtest-down: ${CONTAINER_NAME} was not running" >&2
fi
