
### Install Bitcoin
On macOS just install it with homebrew command

```bash
brew install bitcoin
```

Generated rpcuser with this command:
```bash
openssl rand -base64 12
TbbIwKA3Qa4Lm08d
openssl rand -base64 12
3Ykrm3uafDBLJYGI
```

Set `bitcoin.conf` with:

```bash
regtest=1
rpcuser=TbbIwKA3Qa4Lm08d
rpcpassword=3Ykrm3uafDBLJYGI
txindex=1
prune=0
server=1
```




### Install Electrs

```bash
git clone https://github.com/romanz/electrs.git
cd electrs
cargo build

# Configure `electrs.toml` file
# Example electrs.toml file:
# auth="user:pass"
# txid_limit=0

nano electrs.toml

# Then add rpcuser and rpcpassword from `bitcoin.conf` to it as explained in example:
cat electrs.toml
txid_limit=0

# Run `electrs` with the daemon directory path to regtest

./target/debug/electrs --network regtest --daemon-dir /Users/satinder/Library/Application\ Support/Bitcoin/regtest

# It will give output like this
Config { log: StdErrLog { verbosity: Error, quiet: false, show_level: true, timestamp: Off, modules: [], writer: "stderr", color_choice: Auto }, network_type: Regtest, db_path: "./db/regtest", daemon_dir: "/Users/satinder/Library/Application Support/Bitcoin/regtest/regtest", blocks_dir: "/Users/satinder/Library/Application Support/Bitcoin/regtest/regtest/blocks", daemon_rpc_addr: V4(127.0.0.1:18443), electrum_rpc_addr: V4(127.0.0.1:60401), monitoring_addr: V4(127.0.0.1:24224), jsonrpc_import: false, index_batch_size: 10, bulk_index_threads: 8, tx_cache_size: 10485760, txid_limit: 0, server_banner: "Welcome to electrs 0.8.10 (Electrum Rust Server)!", blocktxids_cache_size: 10485760 }
```



### Install Electrum Client

Just download a copy of wallet from https://electrum.org/#download

On macOS run it via command line:

```bash
cd /Applications/Electrum.app/Contents/MacOS
./run_electrum --regtest -s 0.0.0.0:60401:t
```

It will prompt for the setup wizard for wallet.
Just go with the standard wallet, and generate a seed.

Mine is:
`solid recipe wild chaos squeeze involve aunt describe capital enlist grief theory`

Go to "Recieve" tab in Electrum client GUI, and generate a new address. Example mine is:
`bcrt1qynl4mk7wz9mekt3nh8dmdmm7prcf7vxlja8v2q`

After that using `bitcoin-cli` generate new blocks:
```bash
bitcoin-cli generatetoaddress 110 bcrt1qynl4mk7wz9mekt3nh8dmdmm7prcf7vxlja8v2q
```

It will generate 110 new blocks, and give 50 rewards each to your address supplied in that command.
These will be visible in Electrum transaction history.

Also generate this electrum client's own rpc username, password and port:

```bash
./run_electrum --regtest getconfig rpcuser
user
./run_electrum --regtest getconfig rpcpassword
BVrkwZ0BLuF-F2jzd-Wxhw==
./run_electrum --regtest setconfig rpcport 8899
true
```

In this case, it is:
rpc username: user
rpc password: BVrkwZ0BLuF-F2jzd-Wxhw==
rpc port: 8899


Once finished with the rpc generation of Electum Client. Restart the Electrum client.
To restart, close Electrum Client to exit it's process. Once exited. start Electum client again with the same command:
```bash
./run_electrum --regtest -s 0.0.0.0:60401:t
```






### Install Zcash on macOS

Build using instructions from here:
https://zcash.readthedocs.io/en/latest/rtd_pages/macOS-build.html

I had issue building with some error related to `bdb`. So, I first went to `depends` and built that and tried building zcash again.

```bash
brew install git pkgconfig automake autoconf libtool coreutils
sudo easy_install pip3
sudo pip3 install pyblake2 pyzmq

git clone https://github.com/zcash/zcash.git
cd zcash/
git checkout v4.4.0
./zcutil/fetch-params.sh
./zcutil/clean.sh
cd depends/
make
cd ..
./zcutil/build.sh -j$(sysctl -n hw.ncpu)

# Make symlink to system bin directory
sudo ln -s $(pwd)/src/zcashd /usr/local/bin
sudo ln -s $(pwd)/src/zcash-cli /usr/local/bin
sudo ln -s $(pwd)/src/zcash-tx /usr/local/bin
```

Start Zcash in `regtest` mode:

```bash
# Generate random strings for rpc username and password
openssl rand -base64 12
4R79Aoksu6APFrzr
openssl rand -base64 12
KYbLWFfjSX55EvnB

# Then setup zcash.conf with these values. Once done your zcash.conf will look like this:
cat ~/Library/Application\ Support/Zcash/zcash.conf

regtest=1
nuparams=5ba81b19:1
nuparams=76b809bb:1
nuparams=2bb40e60:1
nuparams=f5b9230b:1
nuparams=e9ff75a6:1
rpcuser=4R79Aoksu6APFrzr
rpcpassword=KYbLWFfjSX55EvnB

# Now start zcashd as daemon
zcashd -daemon

# We now need to generate 110 new blocks on this regtest network
zcash-cli --regtest generate 110

# Generate a new shielded address
zcash-cli --regtest z_getnewaddress
zregtestsapling1nnl802ghvn4m7pg28eyd764ejpumls05kqvjhmee60malja63ns37zxa9ntadcxqsqpwg2y3mpj

# Send the newly generated coinbase balance to this sheilded address:
zcash-cli --regtest z_shieldcoinbase "*" zregtestsapling1nnl802ghvn4m7pg28eyd764ejpumls05kqvjhmee60malja63ns37zxa9ntadcxqsqpwg2y3mpj

# Generate few more blocks to confirm this command's transaction
zcash-cli --regtest generate 10

# Now you can check the balance
zcash-cli --regtest z_gettotalbalance
{
  "transparent": "62.50",
  "private": "62.49999",
  "total": "124.99999"
}

zcash-cli --regtest z_getbalance zregtestsapling1nnl802ghvn4m7pg28eyd764ejpumls05kqvjhmee60malja63ns37zxa9ntadcxqsqpwg2y3mpj
62.49999000


# Generate one more shielded address, which will be required in setting up asmr config
zcash-cli --regtest z_getnewaddress
zregtestsapling1f72n4fhwnsav9evzlm09fuq8vq2m3kd0gtjqg34krzh86hdpxnvqwuh3udg77rqhrn8kgmcqnvu
```








### Install asmr

```bash
git clone github.com/MerosCrypto/asmr
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
  "url": "http://user:BVrkwZ0BLuF-F2jzd-Wxhw==@127.0.0.1:8899",
  "destination": "bcrt1qynl4mk7wz9mekt3nh8dmdmm7prcf7vxlja8v2q",
  "refund": "bcrt1qynl4mk7wz9mekt3nh8dmdmm7prcf7vxlja8v2q",

  "btc_url": "http://user:pass@127.0.0.1:18443"
}

# Edit config/zcashshielded.json
# Use the address with funds in destination field
# For refund address use the second generated shielded address
# For RPC, use rpc info from zcash.conf
# So, my config/zcashshielded.json looks like this:
cat config/zcashshielded.json
{
  "url": "http://4R79Aoksu6APFrzr:KYbLWFfjSX55EvnB@127.0.0.1:18232",
  "destination": "zregtestsapling1f72n4fhwnsav9evzlm09fuq8vq2m3kd0gtjqg34krzh86hdpxnvqwuh3udg77rqhrn8kgmcqnvu",
  "refund": "zregtestsapling1f72n4fhwnsav9evzlm09fuq8vq2m3kd0gtjqg34krzh86hdpxnvqwuh3udg77rqhrn8kgmcqnvu"
}
```

NOTE: In my setup I did setup the zaddress already having funds as "destination", but it looks confusing in later transaction outputs from my tests, so I edited the notes to just use the same address for both "destination" and "refund" as per recommendation by the dev.


Open a new tab and run this command as host:

```bash
# Host node
./target/debug/asmr host 0.0.0.0:2931 btc-zec
```

In another new tab, run the following command as client node:

```bash
# Client node
./target/debug/asmr client 0.0.0.0:2931 btc-zec
```


**Host node:**
In about 30 seconds you'll see prompt similar to this:
```bash
Send to bcrt1qgxje3e2gr506hlzfq5fpuxyvs0n7qu7fmjpvqf and this will automatically proceed when funds are confirmed.
```

Go to Electrum client, and send any amount to this address.
In my case, I used `500 mBTC`, and sent those to `bcrt1qgxje3e2gr506hlzfq5fpuxyvs0n7qu7fmjpvqf`

After that generate 1 BTC block to confirm this transaction. In my case I did this:
```bash
bitcoin-cli generatetoaddress 1 bcrt1qynl4mk7wz9mekt3nh8dmdmm7prcf7vxlja8v2q
```

Then wait about a minute, and then mine 1 more:
```bash
bitcoin-cli generatetoaddress 1 bcrt1qynl4mk7wz9mekt3nh8dmdmm7prcf7vxlja8v2q
```


**Client node:**
Then client node will prompt user to confirm the amounts they will recieve, like this:
```bash
You will receive 49982400 satoshis. Continue (yes/no)? yes
```
Type yes to continue

In about 30 seconds Client node should print the Zcash address similar to this:
```bash
Send to zregtestsapling1wcaktuma3cfanlag0zwa2903m9qw7ltfjdfrr8erluqjfyd8nxvek6vsrucgqlsnu5q4yguqhv6 and this will automatically proceed when funds are confirmed.
```

Go to terminal window/tab to send any amount of Zcash for this swap. In my case I sent 15 ZEC:
```bash
zcash-cli --regtest z_sendmany "zregtestsapling1nnl802ghvn4m7pg28eyd764ejpumls05kqvjhmee60malja63ns37zxa9ntadcxqsqpwg2y3mpj" '[{"address": "zregtestsapling1wcaktuma3cfanlag0zwa2903m9qw7ltfjdfrr8erluqjfyd8nxvek6vsrucgqlsnu5q4yguqhv6", "amount": 15.0}]'
opid-c00183c5-fcc7-462d-9eb0-0cc6489943c5

# To check the transaction's detail check opid status
zcash-cli --regtest z_getoperationstatus '["opid-c00183c5-fcc7-462d-9eb0-0cc6489943c5"]'
[
  {
    "id": "opid-c00183c5-fcc7-462d-9eb0-0cc6489943c5",
    "status": "success",
    "creation_time": 1622802708,
    "result": {
      "txid": "aa1bf86af234b1dbc4e66e99bd039625f060bbd4de06f12cd4e3ba9e94bc69a5"
    },
    "execution_secs": 2.922707,
    "method": "z_sendmany",
    "params": {
      "fromaddress": "zregtestsapling1nnl802ghvn4m7pg28eyd764ejpumls05kqvjhmee60malja63ns37zxa9ntadcxqsqpwg2y3mpj",
      "amounts": [
        {
          "address": "zregtestsapling1wcaktuma3cfanlag0zwa2903m9qw7ltfjdfrr8erluqjfyd8nxvek6vsrucgqlsnu5q4yguqhv6",
          "amount": 15.0
        }
      ],
      "minconf": 1,
      "fee": 1e-05
    }
  }
]
```

Mine about 10 blocks in zcash:
```bash
zcash-cli --regtest generate 10
```


**Host node:**
In about 30 seconds or so, you'll see a pormpt asking the units ot ZEC host is recieving is OK. Type yes to continue:
```bash
You will receive 1500000000 atomic units of ZEC. Continue (yes/no)? yes
```

By this point it was showing single `z_listunspent` output for my wallet
```bash
zcash-cli --regtest z_listunspent
[
  {
    "txid": "aa1bf86af234b1dbc4e66e99bd039625f060bbd4de06f12cd4e3ba9e94bc69a5",
    "outindex": 1,
    "confirmations": 10,
    "spendable": true,
    "address": "zregtestsapling1nnl802ghvn4m7pg28eyd764ejpumls05kqvjhmee60malja63ns37zxa9ntadcxqsqpwg2y3mpj",
    "amount": 47.49998000,
    "memo": "f600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "change": true
  }
]
```


Then generate a block in BTC:
```bash
bitcoin-cli generatetoaddress 1 bcrt1qynl4mk7wz9mekt3nh8dmdmm7prcf7vxlja8v2q
```


Then I generated another 10 blocks in Zcash and then I saw 2 `z_listunspent`
```bash
zcash-cli --regtest z_listunspent
[
  {
    "txid": "aa1bf86af234b1dbc4e66e99bd039625f060bbd4de06f12cd4e3ba9e94bc69a5",
    "outindex": 1,
    "confirmations": 20,
    "spendable": true,
    "address": "zregtestsapling1nnl802ghvn4m7pg28eyd764ejpumls05kqvjhmee60malja63ns37zxa9ntadcxqsqpwg2y3mpj",
    "amount": 47.49998000,
    "memo": "f600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "change": true
  },
  {
    "txid": "e8a87cffe4614ac72763d612c3d67fdbb07de4ec90a4c61ac62650f180bfe6b4",
    "outindex": 0,
    "confirmations": 10,
    "spendable": true,
    "address": "zregtestsapling1nnl802ghvn4m7pg28eyd764ejpumls05kqvjhmee60malja63ns37zxa9ntadcxqsqpwg2y3mpj",
    "amount": 14.99990000,
    "memo": "f600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "change": false
  }
]
```


