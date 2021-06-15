

### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Can add the source command to ~/.bashrc as well for consistency in new terminal sessions
source $HOME/.cargo/env
```



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



### Install VerusCoin

You can get Verus Wallet(s) from here: https://verus.io/wallet

For this test I had to use a developer github repository because the required API `z_gettreestate` was missing in already published wallets.

So, I cloned the following github repo and build it in my Ubuntu 18.04 LTS VM machine:

```bash
# Install dependencies
sudo apt-get install build-essential pkg-config libc6-dev m4 g++-multilib autoconf libtool ncurses-dev unzip git zlib1g-dev wget bsdmainutils automake curl -y

# Clone VRSC repo
git clone https://github.com/miketout/VerusCoin -b dev
cd VerusCoin
./zcutil/fetch-params.sh

# Download and install VRSC mainnet blockchain bootstrap to sync wallet quick for testing
# This script will prompt you to select bootstrap files installation location.
# Just select default and when prompted again input 1 and enter
./vcutil/./vcutil/fetch-bootstrap.sh

# Build VRSC
./zcutil/build.sh -j$(nproc)

# Once build finishes start verusd daemon
cd src/
./verusd
```

Once you started `verusd` it will create it's RPC details in `~/.komodo/VRSC/VRSC.conf`, which we can use later while setting up asmr verus config file.



### Install asmr

```bash
git clone https://github.com/satindergrewal/asmr --branch vrsc
cd asmr
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

# Edit config/veruscoin.json
# Use the address with funds in destination field
# For refund address use the second generated shielded address
# For RPC, use rpc info from ~/.komodo/VRSC/VRSC.conf
# So, my config/veruscoin.json looks like this:
cat config/veruscoin.json
{
  "url": "http://user1003274960:pass7b2c63ee906c6db84debb465620899cf7ff9d5714fc2a8fece5d9c6309ea8483e8@127.0.0.1:27486",
  "destination": "zs1u7c5mqlzdc8gnnvge3qudtwpzf5qpujsr8ct8s0ptk2ncayy8t03ndztgs9a8l70qgkyy5ttcdr",
  "refund": "zs1u7c5mqlzdc8gnnvge3qudtwpzf5qpujsr8ct8s0ptk2ncayy8t03ndztgs9a8l70qgkyy5ttcdr"
}
```


Open a new tab and run this command as host:

```bash
# Host node
./target/debug/asmr host 0.0.0.0:2931 btc-vrsc
```

In another new tab, run the following command as client node:

```bash
# Client node
./target/debug/asmr client 0.0.0.0:2931 btc-vrsc
```

## First atomic swap between Testnet BTC and VRSC
Following are the details of one of the first atomic swap done between Testnet BTC and VRSC using [asmr](https://github.com/satindergrewal/asmr), which is originally developed by [Meros Cryptocurrency](https://meroscrypto.io) developers.

**Test Date/Time/Zone:** 15 June, 9:40 PM - 10:10 PM, NZST

### Final asmr atomic swap results
```bash
asmr Testnet Bitcoin (tBTC) Address: tb1qu6g85w5kzedpngvcy79fjz7ngasr2lze4a4cv9
asmr Mainnet Pirate Chain (ARRR) Address: zs1u7c5mqlzdc8gnnvge3qudtwpzf5qpujsr8ct8s0ptk2ncayy8t03ndztgs9a8l70qgkyy5ttcdr
```

#### asmr in-swap Testnet BTC Address and tx details
```bash
Testnet BTC from asmr: tb1qzwrul7wxzgt53kdpzhkjk3h6t8pqw6t695h3v4
Testnet BTC Sent tx ID: da16a1b2fa92c57af7c42ba2fac1bc33948f74c67c7779ec2e676b2977c8c0c0
Amount Sent: 1.643 + 0.002 tBTC
```
Testnet BTC blockchain explorer link: https://www.blockchain.com/btc-testnet/tx/da16a1b2fa92c57af7c42ba2fac1bc33948f74c67c7779ec2e676b2977c8c0c0

Sent Testnet BTC transaction detail screenshot from Electrum Client:


#### asmr in-swap Mainnet VRSC Address and tx details
```bash
Mainnet VRSC, asmr swap provided address: zs1x749j9txmp74qwlvca4sr0l5c0ezea5er3a428gs3sfkvw6ez37l6gjfsng2730yap45z4aunw9
Mainnet VRSC sent tx ID: ffbb65e5ad12a2ac001a39a11bab054c8d6a4da68b5f8577f5440b20ec32af1b
Amount Sent: 0.3 + 0.0001 fee VRSC
```
Mainnet VRSC blockchain explorer link: https://explorer.verus.io/tx/ffbb65e5ad12a2ac001a39a11bab054c8d6a4da68b5f8577f5440b20ec32af1b


```json
satinder@asmr:~/VerusCoin/src$ ./verus z_sendmany "zs15taqke2uwpdlns24aaps0cnm007w7ly37tfhkj54a7j8u5q0fm2wjjulfylnv4utzypd2zrqdlu" '[{"address": "zs1x749j9txmp74qwlvca4sr0l5c0ezea5er3a428gs3sfkvw6ez37l6gjfsng2730yap45z4aunw9", "amount": 0.3}]'
opid-a478b31c-c9b8-4468-b3c9-0f1a526ebe3a
satinder@asmr:~/VerusCoin/src$ ./verus z_getoperationstatus '["opid-a478b31c-c9b8-4468-b3c9-0f1a526ebe3a"]'
[
  {
    "id": "opid-a478b31c-c9b8-4468-b3c9-0f1a526ebe3a",
    "status": "success",
    "creation_time": 1623750614,
    "result": {
      "txid": "ffbb65e5ad12a2ac001a39a11bab054c8d6a4da68b5f8577f5440b20ec32af1b"
    },
    "execution_secs": 2.967848482,
    "method": "z_sendmany",
    "params": {
      "fromaddress": "zs15taqke2uwpdlns24aaps0cnm007w7ly37tfhkj54a7j8u5q0fm2wjjulfylnv4utzypd2zrqdlu",
      "amounts": [
        {
          "address": "zs1x749j9txmp74qwlvca4sr0l5c0ezea5er3a428gs3sfkvw6ez37l6gjfsng2730yap45z4aunw9",
          "amount": 0.3
        }
      ],
      "minconf": 1,
      "fee": 0.0001
    }
  }
]
```


#### Recieved Testnet BTC:
```bash
Recieved Testnet BTC Address: tb1qu6g85w5kzedpngvcy79fjz7ngasr2lze4a4cv9
Recieved Testnet BTC tx ID: 5e2a6311028aa664fc49df26a49e049d7e55fb5d608d2c82e7cfb970a11d9069
Recieved Testnet BTC Amount:  1.467 tBTC
```
Testnet BTC blockchain explorer link: https://www.blockchain.com/btc-testnet/tx/5e2a6311028aa664fc49df26a49e049d7e55fb5d608d2c82e7cfb970a11d9069

Recieved Testnet BTC transaction detail screenshot from Electrum Client:



#### Recieved Mainnet VRSC:
```bash
Recieved Mainnet VRSC Address: zs1u7c5mqlzdc8gnnvge3qudtwpzf5qpujsr8ct8s0ptk2ncayy8t03ndztgs9a8l70qgkyy5ttcdr
Recieved Mainnet VRSC tx ID: 3fe6b96aadc2e9b466a9783c62e9e36f5aa29fd5ccefa0715d92ae643bbb4daf
Recieved Mainnet VRSC Amount:  0.29990000 VRSC
```
Mainnet VRSC blockchain explorer link: https://explorer.verus.io/tx/3fe6b96aadc2e9b466a9783c62e9e36f5aa29fd5ccefa0715d92ae643bbb4daf

```json
satinder@asmr:~/VerusCoin/src$ ./verus z_getbalance zs1u7c5mqlzdc8gnnvge3qudtwpzf5qpujsr8ct8s0ptk2ncayy8t03ndztgs9a8l70qgkyy5ttcdr
0.29990000
satinder@asmr:~/VerusCoin/src$ ./verus z_listunspent 0 9999999 false '["zs1u7c5mqlzdc8gnnvge3qudtwpzf5qpujsr8ct8s0ptk2ncayy8t03ndztgs9a8l70qgkyy5ttcdr"]'
[
  {
    "txid": "3fe6b96aadc2e9b466a9783c62e9e36f5aa29fd5ccefa0715d92ae643bbb4daf",
    "outindex": 1,
    "confirmations": 3,
    "spendable": true,
    "address": "zs1u7c5mqlzdc8gnnvge3qudtwpzf5qpujsr8ct8s0ptk2ncayy8t03ndztgs9a8l70qgkyy5ttcdr",
    "amount": 0.29990000,
    "memo": "f600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "change": false
  }
]
satinder@asmr:~/VerusCoin/src$ 
```

#### YouTube recording of this Testnet BTC and VRSC atomic swap session
If you are patient enough, here's the video recording of this whole session on my YouTube channel:

https://youtu.be/Dq9chHPJGfk

#### Full log of both asmr host and client terminals
Here's the full terminal log of both host and client asmr console with Rust Debugging enabled.

asmr host console log: https://pastebin.ubuntu.com/p/DySC68v4wj/

asmr client console log: https://pastebin.ubuntu.com/p/4sxd6pjRsm/


**Special thanks to [@VecDequer](https://github.com/VecDequer/) for all the help he gave to make it work with Testnet BTC and ARRR swaps. Becuase of that I was able to make this Testnet BTC and VRSC swap in less time and with ease.**
