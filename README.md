<div align="center">
  <h1 align="center">Voltaire</h1>
</div>

<!-- PROJECT LOGO -->

<div align="center">
  <img src="https://user-images.githubusercontent.com/7014833/220775957-8add0c20-97d0-4bad-8f7c-fefb6df52ae2.png" height=600>
  <p>
    <b>
      Modular, developer-friendly and lighting-fast Python Bundler for Ethereum EIP-4337 Account Abstraction
    </b>
   </p>
</div>

*The project is still work in progress.*

<p>
  <a href="https://discord.gg/NM5HakA9nC">
    <img 
      src="https://img.shields.io/discord/985647134378430515?logo=discord"
      alt="chat on Discord">
  </a>
</p>

# Deployment

Deploy Voltaire using the latest docker image

```
docker run --net=host --rm -ti ghcr.io/candidelabs/voltaire/voltaire-bundler:latest --entrypoint $ENTRYPOINT --bundler_secret $BUNDLER_SECRET --rpc_url $RPC_URL --rpc_port $PORT --ethereum_node_url $ETHEREUM_NODE_URL --chain_id $CHAIN_ID --verbose
```

# Development

The information provided is only a rough estimate based on the current implementation. We plan on publishing more documentation for different developer audiences as we move forward.

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

Follow the installation guide to install [docker on ubunutu](https://docs.docker.com/engine/install/ubuntu/)

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

## Contributions

Thank you for considering contributing to open-source code! We welcome contributions and are grateful for even the smallest of fixes. 

We will be publishing guidelines on how to contribute as we move forward with Voltaire's development.

If you want to contribute today or follow along with the contributor discussion, you can use our main discord to chat with us about the development of Voltaire.

# Status

The project is not ready for production use. We hope to have a full implentation sometimes in April/May 2023, followed by optimizations. In the meantime, we're working on making sure this repo is well-documented, abstracted and tested.

<!-- LICENSE -->
## License
LGPL

<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

None of this would have been possible without the following teams and organizations below: 

* <a href='https://eips.ethereum.org/EIPS/eip-4337'>EIP-4337: Account Abstraction via Entry Point Contract specification </a>
* <a href='https://github.com/eth-infinitism/bundler'>eth-infinitism/bundler</a>
* Voltaire is funded exclusively by [The Ethereum Foundation](https://ethereum.foundation/)
