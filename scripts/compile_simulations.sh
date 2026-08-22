#!/usr/bin/env bash
#
# Recompile the EntryPointSimulations*WithBinarySearch contracts and refresh
# the runtime-bytecode JSON files consumed by the gas managers.
#
# The .sol sources in voltaire_bundler/contracts import account-abstraction
# (and OpenZeppelin) via GitHub HTTPS URLs, which Foundry cannot resolve.
# This script clones the pinned dependency versions, rewrites the HTTPS
# imports to remapped local paths, builds each contract with forge, and
# extracts `deployedBytecode.object` (runtime bytecode — NOT the init
# `bytecode.object`; see CLAUDE.md "Simulation Contracts & Bytecode") into
# the matching JSON file.
#
# Usage:
#   ./scripts/compile_simulations.sh [v6|v7|v8|v9 ...]   # default: all four
#
# Requirements: foundry (forge), git, python3, network access.
# The build workspace is cached in ${COMPILE_WORKDIR:-/tmp/voltaire-compile}
# so repeat runs skip the clones.
#
# NOTE: kept bash-3.2 compatible (macOS default shell) — no associative arrays.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS_DIR="$REPO_ROOT/voltaire_bundler/contracts"
WORKDIR="${COMPILE_WORKDIR:-/tmp/voltaire-compile}"

AA_REPO="https://github.com/eth-infinitism/account-abstraction.git"
OZ_REPO="https://github.com/OpenZeppelin/openzeppelin-contracts.git"

aa_ref_for()   { case "$1" in v6) echo "v0.6.0";; v7) echo "releases/v0.7";; v8) echo "releases/v0.8";; v9) echo "releases/v0.9";; esac; }
contract_for() { case "$1" in v6) echo "EntryPointSimulationsV6WithBinarySearch";; v7) echo "EntryPointSimulationsV7WithBinarySearch";; v8) echo "EntryPointSimulationsV8WithBinarySearch";; v9) echo "EntryPointSimulationsV9WithBinarySearch";; esac; }
# The simulation bytecode is never deployed on-chain (it is injected via
# eth_call state overrides), so solc/evm targets only need to produce code
# the target chains can execute.
solc_for()     { case "$1" in v6) echo "0.8.17";; v7) echo "0.8.23";; v8|v9) echo "0.8.28";; esac; }
evm_for()      { case "$1" in v6) echo "paris";; v7) echo "shanghai";; v8|v9) echo "cancun";; esac; }

clone_pinned() {
    # clone_pinned <repo-url> <ref> <dest-dir>
    local repo="$1" ref="$2" dest="$3"
    if [ -d "$dest/.git" ]; then
        echo "  using cached clone $dest"
        return
    fi
    echo "  cloning $repo @ $ref"
    git clone --quiet --depth 1 --branch "$ref" "$repo" "$dest"
}

oz_ref_for() {
    # Read the @openzeppelin/contracts version pin out of the cloned
    # account-abstraction package.json (falls back across dep sections).
    local aa_dir="$1"
    python3 - "$aa_dir/package.json" <<'EOF'
import json, sys
pkg = json.load(open(sys.argv[1]))
for section in ("dependencies", "devDependencies", "peerDependencies"):
    version = pkg.get(section, {}).get("@openzeppelin/contracts")
    if version:
        print("v" + version.lstrip("^~="))
        break
else:
    print("")
EOF
}

build_version() {
    local version="$1"
    local name aa_ref aa_dir project
    name="$(contract_for "$version")"
    aa_ref="$(aa_ref_for "$version")"
    if [ -z "$name" ]; then
        echo "unknown version '$version' (expected v6|v7|v8|v9)" >&2
        exit 1
    fi
    aa_dir="$WORKDIR/aa-$(echo "$aa_ref" | tr '/' '-')"
    project="$WORKDIR/build-$version"

    echo "== $name (account-abstraction @ $aa_ref) =="
    clone_pinned "$AA_REPO" "$aa_ref" "$aa_dir"

    # OpenZeppelin: v6 pins v4.9.6 directly in its import URL; the others
    # follow whatever the account-abstraction release pins.
    local oz_ref oz_dir=""
    if [ "$version" = "v6" ]; then
        oz_ref="v4.9.6"
    else
        oz_ref="$(oz_ref_for "$aa_dir")"
    fi
    if [ -n "$oz_ref" ]; then
        oz_dir="$WORKDIR/oz-$oz_ref"
        clone_pinned "$OZ_REPO" "$oz_ref" "$oz_dir"
    fi

    rm -rf "$project"
    mkdir -p "$project/src"

    # Rewrite the GitHub HTTPS imports to remapped local paths.
    sed -E \
        -e 's#https://github.com/eth-infinitism/account-abstraction/blob/[^"]*/contracts/#account-abstraction/contracts/#g' \
        -e 's#https://github.com/OpenZeppelin/openzeppelin-contracts/blob/[^"]*/contracts/#@openzeppelin/contracts/#g' \
        "$CONTRACTS_DIR/$name.sol" > "$project/src/$name.sol"

    {
        echo "account-abstraction/=$aa_dir/"
        if [ -n "$oz_dir" ]; then
            echo "@openzeppelin/contracts/=$oz_dir/contracts/"
        fi
    } > "$project/remappings.txt"

    cat > "$project/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
solc_version = "$(solc_for "$version")"
evm_version = "$(evm_for "$version")"
optimizer = true
optimizer_runs = 1000000
EOF

    (cd "$project" && forge build)

    # Extract the runtime bytecode into the two-key JSON shape that
    # voltaire_bundler/utils/load_bytecode.py expects.
    python3 - "$project/out/$name.sol/$name.json" "$CONTRACTS_DIR/$name.json" "$name" <<'EOF'
import json, sys
artifact_path, target_path, name = sys.argv[1:4]
artifact = json.load(open(artifact_path))
runtime = artifact["deployedBytecode"]["object"]
assert runtime.startswith("0x60"), f"unexpected runtime bytecode prefix: {runtime[:10]}"
with open(target_path, "w") as f:
    json.dump({"contractName": name, "bytecode": runtime}, f)
print(f"  wrote {target_path} ({len(runtime)} hex chars)")
EOF
}

if [ "$#" -gt 0 ]; then
    versions="$*"
else
    versions="v6 v7 v8 v9"
fi

mkdir -p "$WORKDIR"
for version in $versions; do
    build_version "$version"
done
echo "done."
