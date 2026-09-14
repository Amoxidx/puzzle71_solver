#!/usr/bin/env bash
# Starts a disposable bitcoind regtest container for the `src/claim/` end-to-end tests
# (`tests/test_claim_regtest.rs`, all `#[ignore]`).
#
# RPC is bound to 127.0.0.1 only, never 0.0.0.0, even though bitcoind itself is told to listen
# on all interfaces inside its own network namespace (-rpcbind=0.0.0.0) — the Docker port
# publish flag `-p 127.0.0.1:18443:18443` is what actually restricts host-reachability.
set -euo pipefail

CONTAINER_NAME="p71-regtest"
RPC_PORT="18443"
RPC_USER="p71"
RPC_PASSWORD="p71regtest"
IMAGE="bitcoin/bitcoin:30.0"
TIMEOUT_SECONDS=60

if docker ps --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
    echo "regtest-up: ${CONTAINER_NAME} is already running; the claim regtest tests need a" >&2
    echo "regtest-up: fresh node — run scripts/regtest-down.sh first, then retry" >&2
    exit 1
fi

docker run -d --rm \
    --name "${CONTAINER_NAME}" \
    -p "127.0.0.1:${RPC_PORT}:${RPC_PORT}" \
    --entrypoint bitcoind \
    "${IMAGE}" \
    -regtest \
    -server \
    -txindex=1 \
    -fallbackfee=0.0002 \
    -rpcbind=0.0.0.0 \
    -rpcallowip=0.0.0.0/0 \
    -rpcuser="${RPC_USER}" \
    -rpcpassword="${RPC_PASSWORD}" \
    -printtoconsole >/dev/null

echo "regtest-up: waiting up to ${TIMEOUT_SECONDS}s for bitcoind RPC to answer..." >&2

deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
# `-sf` alone is not enough: while bitcoind is still loading the block index it answers RPC
# calls with HTTP 500 and a JSON-RPC error body (code -28, "Loading block index..."), so a
# response body of exactly `"error":null` is required too, not just a successful HTTP status.
until response=$(curl -sf -u "${RPC_USER}:${RPC_PASSWORD}" \
    --data-binary '{"jsonrpc":"1.0","id":"regtest-up","method":"getblockchaininfo","params":[]}' \
    -H 'content-type: application/json' \
    "http://127.0.0.1:${RPC_PORT}/" 2>/dev/null) && printf '%s' "${response}" | grep -q '"error":null'; do
    if [ "$(date +%s)" -ge "${deadline}" ]; then
        echo "regtest-up: bitcoind did not answer RPC within ${TIMEOUT_SECONDS}s" >&2
        docker logs "${CONTAINER_NAME}" >&2 || true
        docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || true
        exit 1
    fi
    sleep 1
done

echo "regtest-up: bitcoind is ready on 127.0.0.1:${RPC_PORT}" >&2
