

<!-- ### Install Bitcoin

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
``` -->




### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Can add the source command to ~/.bashrc as well for consistency in new terminal sessions
source $HOME/.cargo/env
```




<!-- ### Install Electrs

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
``` -->



### Install Electrum Client Wallet

```bash
# Install Dependencies
sudo apt-get install python3-setuptools python3-pip

# Download and Run Electrum Wallet
wget https://download.electrum.org/4.1.2/Electrum-4.1.2.tar.gz
python3 -m pip install --user Electrum-4.1.2.tar.gz
./run_electrum --testnet
```

It will prompt for the setup wizard for wallet.
Just go with the standard wallet, and generate a seed.

Go to "Recieve" tab in Electrum client GUI, and generate a new address. Example mine is:
`tb1q0qdptk8n8u33eqacy64pje7f8f0a3f063tsw3e`

Go to websites like the following to get some TESTNET BTC:
- https://coinfaucet.eu/en/btc-testnet/

<!-- After that using `bitcoin-cli` generate new blocks:
```bash
bitcoin-cli generatetoaddress 110 bcrt1qsd2e0wtz8f684085cwugsr7jxlnwmcjheaqzft
```

It will generate 110 new blocks, and give 50 rewards each to your address supplied in that command.
These will be visible in Electrum transaction history. -->

Open another terminal window/tab and also generate this electrum client's own rpc username, password and port:

```bash
satinder@ubuntu:~$ ./run_electrum --testnet getconfig rpcpassword
kSrMi2YenWN9vBFPnHORDw==
satinder@ubuntu:~$ ./run_electrum --testnet getconfig rpcuser
user
satinder@ubuntu:~$ ./run_electrum --testnet getconfig rpcport
satinder@ubuntu:~$ ./run_electrum --testnet setconfig rpcport 8899
true
satinder@ubuntu:~$ ./run_electrum --testnet getconfig rpcport
8899
satinder@ubuntu:~$ 
```

In this case, it is:
- rpc username: user
- rpc password: kSrMi2YenWN9vBFPnHORDw==
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
  "url": "http://user:kSrMi2YenWN9vBFPnHORDw==@127.0.0.1:8899",
  "destination": "tb1qu6g85w5kzedpngvcy79fjz7ngasr2lze4a4cv9",
  "refund": "tb1qu6g85w5kzedpngvcy79fjz7ngasr2lze4a4cv9",

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
  "destination": "zs1q48ph859rd4jrtpmq2p2yhp6u8yvqlh2mqlff3xj7ce80guy9n7laj9j0qkw4v6at3ycxld2248",
  "refund": "zs1q48ph859rd4jrtpmq2p2yhp6u8yvqlh2mqlff3xj7ce80guy9n7laj9j0qkw4v6at3ycxld2248"
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

## First atomic swap between tBTC and ARRR
Following are the dertails of one of the first atomic swap done between tBTC and ARRR using [asmr](https://github.com/satindergrewal/asmr), which is originally developed by [Meros Cryptocurrency](https://meroscrypto.io) developers.

**Test Date/Time/Zone:** 15 June, midnight, NZST

### Final asmr atomic swap results
```bash
asmr Testnet Bitcoin (tBTC) Address: tb1qu6g85w5kzedpngvcy79fjz7ngasr2lze4a4cv9
asmr Mainnet Pirate Chain (ARRR) Address: zs1q48ph859rd4jrtpmq2p2yhp6u8yvqlh2mqlff3xj7ce80guy9n7laj9j0qkw4v6at3ycxld2248
```

```bash
# asmr in-swap tBTC Address and tx details
tBTC Address provided by Host: tb1q08l6jhx9eqfx7kyndxqvzyfcc85exqhtxfznsw
tBTC tx ID: 4cb773fdf30fbf7e594594ecd1189f0fbb46fc074f1f51ec989cd47d4b7a45fc
Amount Sent: 1.2 + 0.002 (fee) mBTC
```
Sent tBTC transaction detail screenshot from Electrum Client:
![Sent_tBTC_small_img](https://user-images.githubusercontent.com/12998093/121906982-bcfa6800-cd7f-11eb-8c60-556c49ba9c4b.png)


```bash
# asmr in-swap ARRR Address and tx details
ARRR Address provided by Client: zs1gfwpxyn6ezn4xsj08wqghe60gft6jc6vv0gmyzjxr9v69mn2pxydg9ydmp08ledzukqcq582zf3
ARRR tx ID: ef4b2634b6a40f50fb9b72f8c6e69a1318369807aa9b499a954c2e5d18c9bbdf
Amount Sent: 0.1 + 0.0001 (fee) ARRR
```

```json
satinder@ubuntu:~$ pirate z_getoperationstatus '["opid-eb35918e-1a45-4eb1-b85c-3710ce669263"]'
[
  {
    "id": "opid-eb35918e-1a45-4eb1-b85c-3710ce669263",
    "status": "success",
    "creation_time": 1623677010,
    "result": {
      "txid": "ef4b2634b6a40f50fb9b72f8c6e69a1318369807aa9b499a954c2e5d18c9bbdf"
    },
    "execution_secs": 3.145586364,
    "method": "z_sendmany",
    "params": {
      "fromaddress": "zs1dqlvgkla8wtlqyj45cdns0ttruh0gj6njn6glnn9efl9ruhhmem5y7jzarzsdruu2frnqfcdfvt",
      "amounts": [
        {
          "address": "zs1gfwpxyn6ezn4xsj08wqghe60gft6jc6vv0gmyzjxr9v69mn2pxydg9ydmp08ledzukqcq582zf3",
          "amount": 0.1
        }
      ],
      "minconf": 1,
      "fee": 0.0001
    }
  }
]
```


#### Recieved tBTC:
- tBTC Address: tb1qu6g85w5kzedpngvcy79fjz7ngasr2lze4a4cv9
- tBTC tx ID: b3b601cc7008a6a649e99f9febb3e9029714b5c8c07d2103e91e1d71cdce4461
- tBTC Amount: 1.024 tBTC

Recieved tBTC transaction detail screenshot from Electrum Client:
![recieved_tBTC_small_img](https://user-images.githubusercontent.com/12998093/121907156-e87d5280-cd7f-11eb-8bc5-97f6aa699020.png)



#### Recieved ARRR:
- ARRR Address: zs1q48ph859rd4jrtpmq2p2yhp6u8yvqlh2mqlff3xj7ce80guy9n7laj9j0qkw4v6at3ycxld2248
- ARRR tx ID: 0f7baca17791d2d8fa7850a56dcb9c29ba6f42158895ba94d0ef08389275e039
- ARRR Amount: 0.09990000

```json
satinder@ubuntu:~$ pirate z_listunspent 0 9999999 false '["zs1q48ph859rd4jrtpmq2p2yhp6u8yvqlh2mqlff3xj7ce80guy9n7laj9j0qkw4v6at3ycxld2248"]'
[
  {
    "txid": "0f7baca17791d2d8fa7850a56dcb9c29ba6f42158895ba94d0ef08389275e039",
    "outindex": 1,
    "confirmations": 31,
    "rawconfirmations": 31,
    "spendable": true,
    "address": "zs1q48ph859rd4jrtpmq2p2yhp6u8yvqlh2mqlff3xj7ce80guy9n7laj9j0qkw4v6at3ycxld2248",
    "amount": 0.09990000,
    "memo": "f600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "change": false
  }
]
satinder@ubuntu:~$ 
```

#### YouTube recording of this tBTC and ARRR atomic swap session
If you are patient enough, here's the video recording of this whole session on my YouTube channel:
https://youtu.be/HcVXvv1ybTI

#### Full (almost) log of both asmr host and client terminals
Here's the full terminal log of both host and client asmr console with Rust Debugging enabled.
I later found that my terminal had cut off the long logs due to some default limits of cutting old standard outputs from console session.
But anyway, there's some log if anyone wants to look at, or can have a look at the video above which can fill the missing gaps from the text log details.

asmr host console log: https://pastebin.ubuntu.com/p/6SM2S5chk2/

asmr client console log: https://pastebin.ubuntu.com/p/7jKKbZCfKg/


**Special thanks to [@VecDequer](https://github.com/VecDequer/) for all the help he gave to make it work.**
