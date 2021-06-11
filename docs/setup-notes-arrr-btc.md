

### Install Bitcoin

```bash
sudo add-apt-repository ppa:luke-jr/bitcoincore
sudo apt-get update
sudo apt-get install bitcoind
```

Generated rpcuser with this command:
```bash
openssl rand -base64 12
OQRgjhRr1MgmzOGa
openssl rand -base64 12
hy4cRk49BmOlkrLT
```

Set `bitcoin.conf` with:

```bash
regtest=1
rpcuser=OQRgjhRr1MgmzOGa
rpcpassword=hy4cRk49BmOlkrLT
txindex=1
prune=0
server=1
```




### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Can add the source command to ~/.bashrc as well for consistency in new terminal sessions
source $HOME/.cargo/env
```




### Install Electrs

```bash
git clone https://github.com/romanz/electrs.git
cd electrs
cargo build

# Configure `electrs.toml` file
# Example electrs.toml file:
# auth="BITCOIN_RPC_USER:BITCOIN_RPC_PASSWORD"
# txid_limit=0

nano electrs.toml

# Then add rpcuser and rpcpassword from `bitcoin.conf` to it as explained in example:
cat electrs.toml
auth="OQRgjhRr1MgmzOGa:hy4cRk49BmOlkrLT"
txid_limit=0

# Run `electrs` with the daemon directory path to regtest

./target/debug/electrs --network regtest

# It will give output like this
satinder@asmr:~/electrs$ ./target/debug/electrs --network regtest
Config { log: StdErrLog { verbosity: Error, quiet: false, show_level: true, timestamp: Off, modules: [], writer: "stderr", color_choice: Auto }, network_type: Regtest, db_path: "./db/regtest", daemon_dir: "/home/satinder/.bitcoin/regtest", blocks_dir: "/home/satinder/.bitcoin/regtest/blocks", daemon_rpc_addr: V4(127.0.0.1:18443), electrum_rpc_addr: V4(127.0.0.1:60401), monitoring_addr: V4(127.0.0.1:24224), jsonrpc_import: false, index_batch_size: 10, bulk_index_threads: 4, tx_cache_size: 10485760, txid_limit: 0, server_banner: "Welcome to electrs 0.8.10 (Electrum Rust Server)!", blocktxids_cache_size: 10485760 }
```



### Install Electrum Client Wallet

```bash
# Install Dependencies
sudo apt-get install python3-pyqt5 libsecp256k1-0 python3-cryptography python3-pip
pip3 install requests

# Download and Run Electrum Wallet
wget https://download.electrum.org/4.1.2/Electrum-4.1.2.tar.gz
tar zxvf Electrum-4.1.2.tar.gz
cd Electrum-4.1.2
./run_electrum --regtest -s 0.0.0.0:60401:t
```

It will prompt for the setup wizard for wallet.
Just go with the standard wallet, and generate a seed.

Mine is:
`before famous verify learn sock audit drink artwork shaft inquiry palm else`

Go to "Recieve" tab in Electrum client GUI, and generate a new address. Example mine is:
`bcrt1qsd2e0wtz8f684085cwugsr7jxlnwmcjheaqzft`

After that using `bitcoin-cli` generate new blocks:
```bash
bitcoin-cli generatetoaddress 110 bcrt1qsd2e0wtz8f684085cwugsr7jxlnwmcjheaqzft
```

It will generate 110 new blocks, and give 50 rewards each to your address supplied in that command.
These will be visible in Electrum transaction history.

Open another terminal window/tab and also generate this electrum client's own rpc username, password and port:

```bash
./run_electrum --regtest getconfig rpcuser
user
./run_electrum --regtest getconfig rpcpassword
aLZ5jdyVaBRvvbMn6Frsgg==
./run_electrum --regtest setconfig rpcport 8899
true
```

In this case, it is:
- rpc username: user
- rpc password: aLZ5jdyVaBRvvbMn6Frsgg==
- rpc port: 8899



### Install Pirate

```bash
sudo apt-get install build-essential pkg-config libc6-dev m4 g++-multilib autoconf libtool libncurses-dev unzip git python zlib1g-dev wget bsdmainutils automake libboost-all-dev libssl-dev libprotobuf-dev protobuf-compiler libqrencode-dev libdb++-dev ntp ntpdate nano software-properties-common curl libevent-dev libcurl4-gnutls-dev cmake clang libsodium-dev -y
git clone https://github.com/PirateNetwork/pirate --branch dev_gettreestate
cd pirate
./zcutil/fetch-params.sh
./zcutil/build.sh -j$(nproc)
sudo ln -s $(pwd)/src/pirate-cli /usr/local/bin/pirate
sudo ln -s $(pwd)/src/pirated /usr/local/bin/

# You can download Pirate's blockchain bootstrap copy
# if you wish to sync the full blockchain faster.
# It is indeed less secure than syncing directly with the network.
# But for this test, I'm just chosing to get the bootstrap and move on with testing.

# Make Pirate data directory
mkdir -p ~/.komodo/PIRATE
cd ~/.komodo/PIRATE/
# Download bootstrap file, and extract it there
wget https://eu.bootstrap.dexstats.info/ARRR-bootstrap.tar.gz
tar zxvf ARRR-bootstrap.tar.gz

# Start pirated as daemon with this command
pirated -daemon
```




### Install asmr

```bash
git clone https://github.com/satindergrewal/asmr --branch arrr
cd asmr
git checkout zcash
cargo build
cp -av config_example config

# Edit config/bitcoin.json
# Use the address which has funds from Electrum client
# And use the rpc info generated from Electrum client earlier
# So, based on that my config/bitcoin.json looks like this
# We can ignore btc_url configuration, for now, as per dev
cat config/bitcoin.json
{
  "url": "http://user:aLZ5jdyVaBRvvbMn6Frsgg==@127.0.0.1:8899",
  "destination": "bcrt1qnxwuvle07f0jeuhg3cc42jp8c4h7htwrpvgx9e",
  "refund": "bcrt1qnxwuvle07f0jeuhg3cc42jp8c4h7htwrpvgx9e",

  "btc_url": "http://user:pass@127.0.0.1:18443"
}

# Edit config/piratechain.json
# Use the address with funds in destination field
# For refund address use the second generated shielded address
# For RPC, use rpc info from ~/.komodo/PIRATE/PIRATE.conf
# So, my config/piratechain.json looks like this:
cat config/piratechain.json
{
  "url": "http://user3791441600:pass572c6265d90b01b81626cbb9572e19d125ba3ff08d4af478709dd9830363223130@127.0.0.1:45453",
  "destination": "zs1yh8n7cnkgrw38fzfyt7h8kg7mdxjwd0aqjet3lv5t2ahyhm45gq4wq5hampg4h6e89j95hem973",
  "refund": "zs1yh8n7cnkgrw38fzfyt7h8kg7mdxjwd0aqjet3lv5t2ahyhm45gq4wq5hampg4h6e89j95hem973"
}
```


Open a new tab and run this command as host:

```bash
# Host node
./target/debug/asmr host 0.0.0.0:2931 btc-arrr
```

In another new tab, run the following command as client node:

```bash
# Client node
./target/debug/asmr client 0.0.0.0:2931 btc-arrr
```



