docker run --rm -ti --name geth -p 8545:8545 ethereum/client-go:v1.10.26 \
  --miner.gaslimit 12000000 \
  --http --http.api personal,eth,net,web3,debug \
  --http.vhosts '*,localhost,host.docker.internal' --http.addr "0.0.0.0" \
  --ignore-legacy-receipts --allow-insecure-unlock --rpc.allow-unprotected-txs \
  --dev \
  --verbosity 4 \
  --nodiscover --maxpeers 0 --mine --miner.threads 1 \
  --networkid 1337 &
  # --password notsosecret &

sleep 3
rm -r keystore/*

docker cp geth:tmp/`docker exec -i geth ls tmp| grep go` keystore

mv keystore/*/* keystore
rmdir keystore/go-ethereum*

poetry run python scripts/init-geth.py > entrypoints

fg

rm entrypoints
rm -r keystore/*