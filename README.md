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

# Development

The information provided is only a rough estimate based on the current implementation. We plan on publishing more documentation for different developer audiences as we move forward.

## Ubuntu: Get started in 5 minutes 

Voltaire requires `Python3.11` or above well as some tools to compile its dependencies. On Ubuntu, the `python3.11-dev` & `libpython3.11-dev` package contains everything we need

```
apt-get install python3.11-dev
```

```
apt-get install libpython3.11-dev
```

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

### Start geth and deploy the EntryPoint
```
source scripts/run-geth.sh
```

### Run the bundler in a new terminal
```
poetry run python3 main.py `cat entrypoints` --verbose
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
