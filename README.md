<!-- PROJECT LOGO -->

<div align="center">
  <h1 align="center">Voltaire - EIP-4337 python Bundler</h1>
</div>

<div align="center">
<img src="https://user-images.githubusercontent.com/7014833/203773780-04a0c8c0-93a6-43a4-bb75-570cb951dfa0.png" height =200>
</div>

# About

Voltaire - EIP-4337 python Bundler<br/>

# Development

### Install Poetry
```
curl -sSL https://install.python-poetry.org | python3 -
```
### Install dependencies
```
poetry install
```

### Install Docker
```
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### run script to start geth and deploy the entrypoint
```
source scripts/run-geth.sh
```

### run the bundler
```
poetry run python3 main.py `cat entrypoints` --verbose
```

### Test the bundler by cloning <a href='https://github.com/eth-infinitism/bundler-spec-tests'>bundler-spec-tests</a> 
```
pdm run pytest -rA -W ignore::DeprecationWarning --url  http://localhost:3000/rpc --entry-point `cat /location/to/file/entrypoints` --ethereum-node http://0.0.0.0:8545 tests/rpc/
```

<!-- LICENSE -->
## License
LGPL

<!-- ACKNOWLEDGMENTS -->
## Acknowledgments
* <a href='https://github.com/eth-infinitism/bundler'>eth-infinitism/bundler</a>
* <a href='https://eips.ethereum.org/EIPS/eip-4337'>EIP-4337: Account Abstraction via Entry Point Contract specification </a>