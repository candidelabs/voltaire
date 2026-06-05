#!/usr/bin/env bash
# Local development setup for Voltaire bundler
#
# Prerequisites:
#   - anvil (Foundry): https://book.getfoundry.sh/getting-started/installation
#   - poetry: pip install poetry
#   - Python 3.13+
#   - docker (only when --with-postgres is passed)
#
# This script starts a local anvil node, deploys the required contracts,
# and launches the Voltaire bundler. Optionally also starts a local
# Postgres container and wires the bundler's persistent cache to it.
#
# Usage:
#   ./scripts/local-dev-setup.sh                 # SQLite (memory-only by default)
#   ./scripts/local-dev-setup.sh --with-postgres # Postgres-backed persistent cache
#
# Environment variables (all optional):
#   ANVIL_PORT       - Anvil JSON-RPC port (default: 8545)
#   BUNDLER_PORT     - Bundler RPC port (default: 3000)
#   CHAIN_ID         - Chain ID (default: 1337)
#   BUNDLER_SECRET   - Bundler signer private key
#   POSTGRES_PORT    - Postgres host port (default: 5432; only used with --with-postgres)
#
# The bundler RPC will be available at: http://127.0.0.1:3000/rpc
# The anvil node will be available at:  http://127.0.0.1:8545
# Postgres (when enabled) at:           postgresql://voltaire:voltaire@127.0.0.1:5432/voltaire

set -euo pipefail

WITH_POSTGRES=0
for arg in "$@"; do
    case "$arg" in
        --with-postgres) WITH_POSTGRES=1 ;;
        -h|--help)
            sed -n '1,30p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

ANVIL_PORT="${ANVIL_PORT:-8545}"
BUNDLER_PORT="${BUNDLER_PORT:-3000}"
CHAIN_ID="${CHAIN_ID:-1337}"
BUNDLER_SECRET="${BUNDLER_SECRET:-0x897368deaa9f3797c02570ef7d3fa4df179b0fc7ad8d8fc2547d04701604eb72}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_CONTAINER="voltaire-local-postgres"
POSTGRES_DSN="postgresql://voltaire:voltaire@127.0.0.1:${POSTGRES_PORT}/voltaire"
BUNDLER_ADDRESS=$(cast wallet address --private-key "$BUNDLER_SECRET" 2>/dev/null)
DETERMINISTIC_FACTORY="0x4e59b44847b379578588920ca78fbf26c0b4956c"
FACTORY_DEPLOYER="0x3fab184622dc19b6109349b94811493bf2a45362"

ENTRYPOINT_V06="0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
ENTRYPOINT_V07="0x0000000071727De22E5E9d8BAf0edAc6f37da032"
ENTRYPOINT_V08="0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108"
ENTRYPOINT_V09="0x433709009B8330FDa32311DF1C2AFA402eD8D009"

# Anvil default account[0] — pre-funded with 10000 ETH
ANVIL_FUNDER="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cleanup() {
    echo ""
    echo "Shutting down..."
    kill "$ANVIL_PID" 2>/dev/null || true
    kill "$BUNDLER_PID" 2>/dev/null || true
    if [ "$WITH_POSTGRES" = "1" ]; then
        # Leave the container's data intact so a re-run picks up the
        # warm cache. Operators who want a clean slate can
        # `docker rm -fv $POSTGRES_CONTAINER` themselves.
        docker stop "$POSTGRES_CONTAINER" >/dev/null 2>&1 || true
    fi
    exit 0
}
trap cleanup SIGINT SIGTERM

rpc() {
    curl -s -X POST "http://127.0.0.1:${ANVIL_PORT}" \
        -H 'Content-Type: application/json' \
        -d "$1"
}

# Extract deploy data from deploy.js for a given EntryPoint version.
# Usage: extract_deploy_data "v0.06" "entrypointDeployDataV6"
extract_deploy_data() {
    local version_label="$1"
    local var_name="$2"
    python3 -c "
import re
with open('$PROJECT_DIR/scripts/deploy.js') as f:
    content = f.read()
idx = content.find('Deploy Entrypoint $version_label')
section = content[idx:idx+200000]
match = re.search(r'var $var_name\s*=\s*\"(0x[0-9a-fA-F]+)\"', section)
print(match.group(1))
"
}

# ─── Start Postgres (optional) ────────────────────────────────
if [ "$WITH_POSTGRES" = "1" ]; then
    echo "=== Starting Postgres (port=$POSTGRES_PORT) ==="
    if ! command -v docker >/dev/null 2>&1; then
        echo "ERROR: --with-postgres requires docker"
        exit 1
    fi
    # Reuse the container across runs so the persistent cache
    # actually persists between bundler restarts. Only `docker run`
    # if the container doesn't already exist.
    if ! docker inspect "$POSTGRES_CONTAINER" >/dev/null 2>&1; then
        docker run -d \
            --name "$POSTGRES_CONTAINER" \
            -e POSTGRES_USER=voltaire \
            -e POSTGRES_PASSWORD=voltaire \
            -e POSTGRES_DB=voltaire \
            -p "$POSTGRES_PORT:5432" \
            postgres:16-alpine >/dev/null
    else
        docker start "$POSTGRES_CONTAINER" >/dev/null
    fi
    # Wait for Postgres to accept connections — the bundler will
    # otherwise see an open() failure and fall back to memory-only.
    for _ in $(seq 1 30); do
        if docker exec "$POSTGRES_CONTAINER" pg_isready -U voltaire >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    echo "Postgres ready at $POSTGRES_DSN"
fi

# ─── Start anvil ──────────────────────────────────────────────
echo "=== Starting anvil (chain_id=$CHAIN_ID, port=$ANVIL_PORT) ==="
# Gas limit must be ≥30M for EntryPoint deployment (~15M gas)
anvil --chain-id "$CHAIN_ID" --gas-limit 30000000 --port "$ANVIL_PORT" --block-time 1 &
ANVIL_PID=$!
sleep 2

EXPECTED_CHAIN_ID_HEX="0x$(printf '%x' "$CHAIN_ID")"
if ! rpc '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' | grep -q "$EXPECTED_CHAIN_ID_HEX"; then
    echo "ERROR: anvil failed to start"
    exit 1
fi
echo "anvil running (pid=$ANVIL_PID)"

# ─── Deploy deterministic deployer factory ────────────────────
echo "=== Deploying deterministic deployer factory ==="
rpc "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$ANVIL_FUNDER\",\"to\":\"$FACTORY_DEPLOYER\",\"value\":\"0x2386F26FC10000\",\"gas\":\"0x5208\"}],\"id\":1}" > /dev/null
rpc '{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xf8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222"],"id":1}' > /dev/null
echo "Deterministic factory deployed at $DETERMINISTIC_FACTORY"

# ─── Fund bundler signer ──────────────────────────────────────
echo "=== Funding bundler signer ==="
rpc "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$ANVIL_FUNDER\",\"to\":\"$BUNDLER_ADDRESS\",\"value\":\"0x56BC75E2D63100000\",\"gas\":\"0x5208\"}],\"id\":1}" > /dev/null
echo "Funded $BUNDLER_ADDRESS with 100 ETH"

# ─── Deploy EntryPoint v0.6 ──────────────────────────────────
echo "=== Deploying EntryPoint v0.6 ==="
DEPLOY_DATA=$(extract_deploy_data "v0.06" "entrypointDeployDataV6")
rpc "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$ANVIL_FUNDER\",\"to\":\"$DETERMINISTIC_FACTORY\",\"data\":\"$DEPLOY_DATA\",\"gas\":\"0x1C9C380\"}],\"id\":1}" > /dev/null
echo "EntryPoint v0.6 deployed at $ENTRYPOINT_V06"

# ─── Deploy EntryPoint v0.7 ──────────────────────────────────
echo "=== Deploying EntryPoint v0.7 ==="
DEPLOY_DATA=$(extract_deploy_data "v0.07" "entrypointDeployDataV7")
rpc "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$ANVIL_FUNDER\",\"to\":\"$DETERMINISTIC_FACTORY\",\"data\":\"$DEPLOY_DATA\",\"gas\":\"0x1C9C380\"}],\"id\":1}" > /dev/null
echo "EntryPoint v0.7 deployed at $ENTRYPOINT_V07"

# ─── Deploy EntryPoint v0.8 ──────────────────────────────────
echo "=== Deploying EntryPoint v0.8 ==="
DEPLOY_DATA=$(extract_deploy_data "v0.08" "entrypointDeployDataV8")
rpc "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$ANVIL_FUNDER\",\"to\":\"$DETERMINISTIC_FACTORY\",\"data\":\"$DEPLOY_DATA\",\"gas\":\"0x1C9C380\"}],\"id\":1}" > /dev/null
echo "EntryPoint v0.8 deployed at $ENTRYPOINT_V08"

# ─── Deploy EntryPoint v0.9 ──────────────────────────────────
# v0.9 uses a vanity address on mainnet. We deploy via the factory (produces a
# different address), then copy the runtime bytecode to the expected address.
echo "=== Deploying EntryPoint v0.9 ==="
DEPLOY_DATA=$(extract_deploy_data "v0.09" "entrypointDeployDataV9")
rpc "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$ANVIL_FUNDER\",\"to\":\"$DETERMINISTIC_FACTORY\",\"data\":\"$DEPLOY_DATA\",\"gas\":\"0x1C9C380\"}],\"id\":1}" > /dev/null

# Mine pending txs so all EntryPoints are available before continuing.
rpc '{"jsonrpc":"2.0","method":"anvil_mine","params":["0x4"],"id":1}' > /dev/null
sleep 1

# The factory deploys v0.9 to a non-vanity address. Get the runtime bytecode
# and place it at the expected mainnet vanity address using anvil_setCode.
V09_FACTORY_ADDR="0x40be45b895e2553602327bdf3adf2553d2a24a70"
RUNTIME_CODE=$(rpc "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getCode\",\"params\":[\"$V09_FACTORY_ADDR\",\"latest\"],\"id\":1}" | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])")
if [ ${#RUNTIME_CODE} -lt 10 ]; then
    echo "ERROR: Failed to fetch v0.9 runtime bytecode from $V09_FACTORY_ADDR"
    exit 1
fi
rpc "{\"jsonrpc\":\"2.0\",\"method\":\"anvil_setCode\",\"params\":[\"$ENTRYPOINT_V09\",\"$RUNTIME_CODE\"],\"id\":1}" > /dev/null
echo "EntryPoint v0.9 deployed at $ENTRYPOINT_V09 (via anvil_setCode)"

# ─── Deposit ETH into EntryPoints for bundler ──────────────────
echo "=== Depositing 10 ETH into each EntryPoint for bundler ==="
# depositTo(address) selector = 0xb760faf9
BUNDLER_PADDED="000000000000000000000000${BUNDLER_ADDRESS:2}"
for EP in "$ENTRYPOINT_V06" "$ENTRYPOINT_V07" "$ENTRYPOINT_V08" "$ENTRYPOINT_V09"; do
    rpc "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$ANVIL_FUNDER\",\"to\":\"$EP\",\"data\":\"0xb760faf9${BUNDLER_PADDED}\",\"value\":\"0x8AC7230489E80000\",\"gas\":\"0x30000\"}],\"id\":1}" > /dev/null
done
# Mine deposit txs before starting the bundler.
rpc '{"jsonrpc":"2.0","method":"anvil_mine","params":["0x4"],"id":1}' > /dev/null
echo "Deposited 10 ETH for bundler in all EntryPoints"

# ─── Summary ──────────────────────────────────────────────────
echo ""
echo "=== Local environment ready ==="
echo "  Anvil node:     http://127.0.0.1:${ANVIL_PORT}"
echo "  Chain ID:       $CHAIN_ID"
echo "  EntryPoint v06: $ENTRYPOINT_V06"
echo "  EntryPoint v07: $ENTRYPOINT_V07"
echo "  EntryPoint v08: $ENTRYPOINT_V08"
echo "  EntryPoint v09: $ENTRYPOINT_V09"
echo "  Bundler addr:   $BUNDLER_ADDRESS"
echo ""
echo "To deploy a smart account contract at a specific address:"
echo "  curl -X POST http://127.0.0.1:${ANVIL_PORT} -H 'Content-Type: application/json' \\"
echo "    -d '{\"jsonrpc\":\"2.0\",\"method\":\"anvil_setCode\",\"params\":[\"0xYOUR_ADDRESS\",\"0xBYTECODE\"],\"id\":1}'"
echo ""

# ─── Start bundler ────────────────────────────────────────────
# NOTE: Do NOT use --debug here — it disables automatic bundle submission.
# UserOps will be accepted into the mempool but never included on-chain.
echo "=== Starting Voltaire bundler ==="
cd "$PROJECT_DIR"

# Setting VOLTAIRE_CACHE_POSTGRES_URL is enough to enable persistent
# cache; no CLI flag needed. Leaving it unset keeps caches memory-only.
if [ "$WITH_POSTGRES" = "1" ]; then
    export VOLTAIRE_CACHE_POSTGRES_URL="$POSTGRES_DSN"
fi

poetry run python3 -m voltaire_bundler \
    --bundler_secret "$BUNDLER_SECRET" \
    --chain_id "$CHAIN_ID" \
    --rpc_port "$BUNDLER_PORT" \
    --ethereum_node_url "http://127.0.0.1:${ANVIL_PORT}" \
    --verbose --unsafe \
    --bundle_interval 2 \
    --disable_p2p \
    --eip7702 &
BUNDLER_PID=$!
sleep 3

echo ""
echo "=== Bundler RPC: http://127.0.0.1:${BUNDLER_PORT}/rpc ==="
echo ""
echo "Test with:"
echo "  curl -X POST http://127.0.0.1:${BUNDLER_PORT}/rpc -H 'Content-Type: application/json' \\"
echo "    -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_supportedEntryPoints\",\"params\":[],\"id\":1}'"
echo ""
echo "Press Ctrl+C to stop."
wait
