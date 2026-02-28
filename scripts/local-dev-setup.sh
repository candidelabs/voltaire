#!/usr/bin/env bash
# Local development setup for Voltaire bundler
#
# Prerequisites:
#   - anvil (Foundry): https://book.getfoundry.sh/getting-started/installation
#   - poetry: pip install poetry
#   - Python 3.13+
#
# This script starts a local anvil node, deploys the required contracts,
# and launches the Voltaire bundler.
#
# Usage:
#   ./scripts/local-dev-setup.sh
#
# Environment variables (all optional):
#   ANVIL_PORT       - Anvil JSON-RPC port (default: 8545)
#   BUNDLER_PORT     - Bundler RPC port (default: 3000)
#   CHAIN_ID         - Chain ID (default: 1337)
#   BUNDLER_SECRET   - Bundler signer private key
#
# The bundler RPC will be available at: http://127.0.0.1:3000/rpc
# The anvil node will be available at:  http://127.0.0.1:8545

set -euo pipefail

ANVIL_PORT="${ANVIL_PORT:-8545}"
BUNDLER_PORT="${BUNDLER_PORT:-3000}"
CHAIN_ID="${CHAIN_ID:-1337}"
BUNDLER_SECRET="${BUNDLER_SECRET:-0x897368deaa9f3797c02570ef7d3fa4df179b0fc7ad8d8fc2547d04701604eb72}"
BUNDLER_ADDRESS="0x084178a5fd956e624fcb61c3c2209e3dcf42c8e8"
DETERMINISTIC_FACTORY="0x4e59b44847b379578588920ca78fbf26c0b4956c"
FACTORY_DEPLOYER="0x3fab184622dc19b6109349b94811493bf2a45362"
ENTRYPOINT_V08="0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108"

# Anvil default account[0] — pre-funded with 10000 ETH
ANVIL_FUNDER="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cleanup() {
    echo ""
    echo "Shutting down..."
    kill "$ANVIL_PID" 2>/dev/null || true
    kill "$BUNDLER_PID" 2>/dev/null || true
    exit 0
}
trap cleanup SIGINT SIGTERM

rpc() {
    curl -s -X POST "http://127.0.0.1:${ANVIL_PORT}" \
        -H 'Content-Type: application/json' \
        -d "$1"
}

# ─── Start anvil ──────────────────────────────────────────────
echo "=== Starting anvil (chain_id=$CHAIN_ID, port=$ANVIL_PORT) ==="
# Gas limit must be ≥30M for EntryPoint deployment (~15M gas)
anvil --chain-id "$CHAIN_ID" --gas-limit 30000000 --port "$ANVIL_PORT" --block-time 1 &
ANVIL_PID=$!
sleep 2

if ! rpc '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' | grep -q "0x539"; then
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

# ─── Deploy EntryPoint v0.8 ──────────────────────────────────
echo "=== Deploying EntryPoint v0.8 ==="
DEPLOY_DATA=$(python3 -c "
import re
with open('$PROJECT_DIR/scripts/deploy.js') as f:
    content = f.read()
idx = content.find('Deploy Entrypoint v0.08')
section = content[idx:idx+200000]
match = re.search(r'var entrypointDeployDataV8\s*=\"(0x[0-9a-fA-F]+)\"', section)
print(match.group(1))
")
rpc "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$ANVIL_FUNDER\",\"to\":\"$DETERMINISTIC_FACTORY\",\"data\":\"$DEPLOY_DATA\",\"gas\":\"0x1C9C380\"}],\"id\":1}" > /dev/null
echo "EntryPoint v0.8 deployed at $ENTRYPOINT_V08"

# ─── Deposit ETH into EntryPoint for bundler ──────────────────
echo "=== Depositing 10 ETH into EntryPoint for bundler ==="
# depositTo(address) selector = 0xb760faf9
BUNDLER_PADDED="000000000000000000000000${BUNDLER_ADDRESS:2}"
rpc "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$ANVIL_FUNDER\",\"to\":\"$ENTRYPOINT_V08\",\"data\":\"0xb760faf9${BUNDLER_PADDED}\",\"value\":\"0x8AC7230489E80000\",\"gas\":\"0x30000\"}],\"id\":1}" > /dev/null
echo "Deposited 10 ETH for bundler in EntryPoint"

# ─── Summary ──────────────────────────────────────────────────
echo ""
echo "=== Local environment ready ==="
echo "  Anvil node:     http://127.0.0.1:${ANVIL_PORT}"
echo "  Chain ID:       $CHAIN_ID"
echo "  EntryPoint v08: $ENTRYPOINT_V08"
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
poetry run python3 -m voltaire_bundler \
    --bundler_secret "$BUNDLER_SECRET" \
    --chain_id "$CHAIN_ID" \
    --rpc_port "$BUNDLER_PORT" \
    --ethereum_node_url "http://127.0.0.1:${ANVIL_PORT}" \
    --verbose --unsafe \
    --bundle_interval 2 \
    --disable_p2p \
    --disable_v6 \
    --disable_entrypoints_code_check \
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
