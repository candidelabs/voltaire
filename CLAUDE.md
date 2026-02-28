# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Voltaire is a modular and lightning-fast Python-Rust Bundler for Ethereum EIP-4337 Account Abstraction. It consists of two main components:
- **voltaire_bundler**: Python package handling the core bundler logic, RPC server, mempool management, and user operation processing
- **voltaire_p2p**: Rust component providing P2P networking capabilities using libp2p

## Development Commands

### Installation and Setup
```bash
# Install dependencies
poetry install

# Set correct Python version
poetry env use python3.13

# Install Rust build dependencies (for P2P component)
sudo apt install musl-tools
rustup target add x86_64-unknown-linux-musl
```

### Building
```bash
# Build the Rust P2P component
poetry run build_p2p

# This compiles the Rust code and copies the binary to the project root
```

### Linting and Type Checking
```bash
# Run linting and type checking
poetry run lint

# This runs both flake8 and mypy on the voltaire_bundler package
```

### Testing
```bash
# Run tests with pytest
poetry run pytest

# Run specific test file
poetry run pytest tests/v6/test_rpc.py
```

### Running the Bundler
```bash
# Basic run command (after setting environment variables)
poetry run python3 -m voltaire_bundler --bundler_secret $BUNDLER_SECRET --chain_id 1337 --verbose --ethereum_node_url $ETHEREUM_NODE_URL

# Docker deployment
docker run --net=host --rm -ti ghcr.io/candidelabs/voltaire/voltaire-bundler:latest --bundler_secret $BUNDLER_SECRET --rpc_url $RPC_URL --rpc_port $PORT --ethereum_node_url $ETHEREUM_NODE_URL --chain_id $CHAIN_ID --verbose --unsafe --disable_p2p
```

### Local Development Setup
```bash
# One-command setup: starts anvil, deploys all EntryPoints (v0.6-v0.9), and launches the bundler
./scripts/local-dev-setup.sh

# Bundler RPC: http://127.0.0.1:3000/rpc
# Anvil node:  http://127.0.0.1:8545
# Chain ID:    1337
```

To start only the bundler (if anvil and contracts are already running):
```bash
poetry run python3 -m voltaire_bundler \
  --bundler_secret 0x897368deaa9f3797c02570ef7d3fa4df179b0fc7ad8d8fc2547d04701604eb72 \
  --chain_id 1337 --rpc_port 3000 \
  --ethereum_node_url http://127.0.0.1:8545 \
  --verbose --unsafe --bundle_interval 2 \
  --disable_p2p --eip7702
```

**Important CLI flags:**
- `--debug`: Disables automatic bundle submission. UserOps stay in mempool until `debug_bundler_sendBundleNow` is called manually. Do NOT use for end-to-end testing.
- `--unsafe`: Skips `debug_traceCall` validation (required for local dev without tracing support)
- `--disable_v6`: Skip v0.6 EntryPoint
- `--disable_entrypoints_code_check`: Skip checking if all EntryPoints are deployed
- `--eip7702`: Enable EIP-7702 authorization tuple support (required for 7702 accounts)
- `--bundle_interval N`: Seconds between bundle submission attempts (default: 2)

## Architecture Overview

### Core Components

1. **ExecutionEndpoint** (`voltaire_bundler/execution_endpoint.py`):
   - Central coordinator managing all bundler operations
   - Handles user operation validation, mempool management, and bundle execution
   - Integrates with Ethereum nodes and manages different EntryPoint versions (v0.6, v0.7, v0.8, v0.9)

2. **Mempool Management**:
   - `LocalMempoolManagerV6`: Handles v0.6 EntryPoint operations
   - `LocalMempoolManagerV7`: Handles v0.7 EntryPoint operations
   - `LocalMempoolManagerV8`: Handles v0.8 EntryPoint operations
   - `LocalMempoolManagerV9`: Handles v0.9 EntryPoint operations
   - Each version has different validation rules and gas handling

3. **Bundle Management** (`voltaire_bundler/bundle/bundle_manager.py`):
   - Groups user operations into bundles for efficient execution
   - Handles gas estimation and fee calculation
   - Manages bundle submission to the network

4. **RPC Server** (`voltaire_bundler/rpc/rpc_http_server.py`):
   - Provides JSON-RPC interface for bundler operations
   - Implements EIP-4337 bundler RPC methods
   - Handles health checks and metrics

5. **P2P Networking** (`voltaire_p2p/`):
   - Rust-based P2P component using libp2p
   - Handles mempool synchronization between bundlers
   - Can be disabled with `--disable_p2p` flag

### User Operation Handling

- **UserOperationV6**: Handles v0.6 format user operations
- **UserOperationV7V8**: Handles v0.7 and v0.8 format user operations
- **UserOperationHandler**: Contains validation and processing logic
- **Gas Management**: Separate gas managers for different EntryPoint versions (`gas/`)

### Configuration

- Main configuration is handled through CLI arguments in `cli_manager.py`
- Environment variables can be set using `scripts/init-params`
- Poetry scripts are defined in `pyproject.toml` for common tasks

### Testing

- Tests are organized by EntryPoint version in `tests/v6/`
- Uses pytest with asyncio support
- Integration tests validate against the official bundler spec tests

## Development Notes

- The project uses Python 3.13+ with async/await patterns throughout
- Rust component is built as a static binary and integrated with Python via IPC
- Supports multiple Ethereum node URLs for redundancy
- Implements comprehensive reputation management and validation
- Modular design allows running with or without P2P networking

### Simulation Contracts & Bytecode

The bundler estimates gas by injecting simulation bytecode via `eth_call` state overrides at the EntryPoint address. The bytecode JSON files live in `voltaire_bundler/contracts/`:

- `EntryPointSimulationsV7WithBinarySearch.json`
- `EntryPointSimulationsV8WithBinarySearch.json`
- `EntryPointSimulationsV9WithBinarySearch.json`

**Critical**: These JSON files must contain **runtime bytecode** (`deployedBytecode`), NOT init/deployment bytecode (`bytecode`). When recompiling with Foundry, use `deployedBytecode.object` from the compiler output:

```python
# Correct — runtime bytecode for state overrides
data['deployedBytecode']['object']

# WRONG — init code, will cause eth_call to return bytecode instead of executing
data['bytecode']['object']
```

Source Solidity contracts are in the same directory. They import from account-abstraction via HTTPS URLs. To compile locally with Foundry, replace the HTTPS imports with local paths and set up remappings (see `/tmp/voltaire-compile` pattern).

### EntryPoint Addresses

- **v0.6**: `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`
- **v0.7**: `0x0000000071727De22E5E9d8BAf0edAc6f37da032`
- **v0.8**: `0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108`
- **v0.9**: `0x433709009B8330FDa32311DF1C2AFA402eD8D009`