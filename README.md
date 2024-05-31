<div align="center">
  <h1 align="center">Voltaire</h1>
</div>

<!-- PROJECT LOGO -->

<div align="center">
  <img src="https://github.com/candidelabs/voltaire/assets/7014833/603d130d-62ce-458e-b2f6-31597b5279ab">
  <p>
    <b>
      Modular and lighting-fast Python Bundler for Ethereum EIP-4337 Account Abstraction
    </b>
   </p>
</div>

# Using an instance

For a quick bundler instance, use one of our [public hosted endpoints](https://docs.candide.dev/wallet/bundler/rpc-endpoints/) for your development.

# Deployment

Deploy Voltaire using the latest docker image

```
docker run --net=host --rm -ti ghcr.io/candidelabs/voltaire/voltaire-bundler:latest --bundler_secret $BUNDLER_SECRET --rpc_url $RPC_URL --rpc_port $PORT --ethereum_node_url $ETHEREUM_NODE_URL --chain_id $CHAIN_ID --verbose --unsafe --disable_p2p
```

# Development

## Ubuntu: Get started testing the bundler in 5 minutes 

### Install Poetry
```
curl -sSL https://install.python-poetry.org | python3 -
```
### Install dependencies
```
poetry install
```

### Make sure you are using the right python version

```
poetry env use python3.11
```

### Install Docker

Follow the installation guide to install [docker on ubuntu](https://docs.docker.com/engine/install/ubuntu/)

### Post docker installation

Follow the instruction for docker's [post linux instalation](https://docs.docker.com/engine/install/linux-postinstall/)  

### Start geth
```
docker run --rm -ti --name geth -p 8545:8545 ethereum/client-go:v1.10.26 \
  --miner.gaslimit 12000000 \
  --http --http.api personal,eth,net,web3,debug \
  --http.vhosts '*,localhost,host.docker.internal' --http.addr "0.0.0.0" \
  --ignore-legacy-receipts --allow-insecure-unlock --rpc.allow-unprotected-txs \
  --dev \
  --verbosity 4 \
  --nodiscover --maxpeers 0 --mine --miner.threads 1 \
  --networkid 1337
```

### Deploy the EntryPoint and fund the signer (in another terminal)
```
geth --exec 'loadScript("scripts/deploy.js")' attach http://0.0.0.0:8545
```

### Set env values
```
source scripts/init-params 
```

### Run the bundler
```
poetry run python3 -m voltaire_bundler --entrypoint $ENTRYPOINT --bundler_secret $BUNDLER_SECRET --chain_id 1337 --verbose
```

### Test the bundler by cloning `eth-infinitism/bundler-spec-tests`

Follow the instruction in <a href='https://github.com/eth-infinitism/bundler-spec-tests'>eth-infinitism/bundler-spec-tests</a> to install dependencies and run the test

## P2P rust section development

### Install Rust
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Install build dependencies
```
sudo apt install musl-tools
rustup target add x86_64-unknown-linux-musl
```

### Build the rust section using poetry script
```
poetry run build_p2p
```

## Contributions

Thank you for considering contributing to open-source code! We welcome contributions and are grateful for even the smallest of fixes. 

If you want to contribute today or follow along with the contributor discussion, you can use our main discord to chat with us about the development of Voltaire.

<!-- LICENSE -->
## License
LGPL

<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

None of this would have been possible without the following teams and organizations below: 

* <a href='https://eips.ethereum.org/EIPS/eip-4337'>EIP-4337: Account Abstraction via Entry Point Contract specification </a>
* <a href='https://github.com/eth-infinitism/bundler'>eth-infinitism/bundler</a>
* Voltaire is funded exclusively by [The Ethereum Foundation](https://ethereum.foundation/)
* <a href='https://github.com/sigp/lighthouse'>Lighthouse: Ethereum consensus client</a>
