Build
  Library
  =======
  First build the asmr rust crate, by executing 'cargo build'
  in the top level directory. The project requires the rust nightly
  version, due to dependencies of the library that cannot be build
  using a stable rustc release.

  To build a release (non debug), use the command: cargo build --release
  The debug build is inside target/debug and 
  the release build is inside target/release
  This example project uses the debug build.

  C++ example project
  ===================
  The build environment assumes Gnu/Linux with the C++ compiler
  preinstalled. On Debian & derivatives, run 'apt-get install
  build-essential' to install the basic compiler and build
  environment.

  The header file for libasmr is included in this directory (C++).
  Its called libasmr.h. To use the library with other projects
  you need to include this H file along with the library, residing in
  ../target/debug/

  To build the example programs, run 'make' in the C++
  sub directory. Two applications will be created: 
  *atomic_swap_host
     - The host controls the swap
     - The host issues commands to the client as the swap progresses. The
       commands are intented to be send over a network link.
     - The host sends BTC to the client and receives Arrr from the client
  *atomic_swap_client
     - The client participates in the swap
     - The client waits for commands that it receives from the host
     - The client received BTC from the host and sends Arrr to the host

Current limitations and future considerations
  1) The C++ implementation does not currently send all communication
     between the host & client over the TCP/IP connection. This is simply
     due to a lack of time on the part of the developer. A data file is
     shared on the hard drive between the host & client where the data
     exceeds 1500 bytes. Future implementation may address this shortfall.
     This means that both the host & client must be executed on the same
     PC from the same sub directory (C++). 
     Therefore, the applications demonstrate the functionality of a swap 
     on the BTC & Arrr block chains, but its currently only used to 
     exchange the funds between your own wallets.
  2) Not all the refund paths have been implemented.
  3) The C++ wrapper applications starts the state machines inside the
     asmr libraries. From that point the host C++ application retrieves
     data from the library and send the command over the network to
     the clien't C++ application. At the client side the command is
     send to its internal library. The client retrieves the result from
     the library and send the result back over the network to the host.
     The host again provides the result to its internal library. In
     this way the C++ wrapper only acts as a 'post box' to exchange
     communication between the host&client libraries.
     Another important function of the library is to save necessary
     state information. In the event that the swap is disrupted and
     restarted, the host&client can resynchronise and carry on with
     the swap. This session data is stored on disk in files called
     host_session and client_session.
     This data is currently managed by the library itself and not
     by the C++ wrapper. In order to make the library completely
     implementation independent, the session data will have to be
     maintained and managed by the C++ (or future) applications.
  4) Once a swap is finalised, the session files need to be removed
     manually: host_session and client_session. If these files are
     erased prematurely the state information is lost and by defenition
     the funds that are locked up in the intermediate steps of the
     swap transaction.
  5) Due to the session files maintained by the library, only one
     swap can be performed at a given time.
  6) The amount of funds swapped between the parties are not captured
     by in the config file or session file. If one of the two parties
     fund their account with too little funds the swap will currently
     still continue. A solution will be to capture the expected value
     of the swap beforehand. The implementation must then verify the
     actual received funds against this value to determine if the
     swap can continue or if it must be terminated and the funds
     refunded.
  7) The fees levied by the miners does obscure the actual amount that will
     be received by the client. For instance, if you start off by sending
     0.497 milliBTC to the funding address a fee of 0.003 mBTC is levied. 
     Therefore, from your wallet 0.5mBTC is deducted in total. 
   
     From the funding to the lock transaction, a fee of 0.094mBTC is charged
     by the network. Therefore, the funding address ends up 
     with 0.403mBTC

     From the lock transaction to the destination address of the client,
     a fee of 0.082mBTC is charged by the network. Therefore, the client
     ends up with 0.321mBTC.
     
     The host started off by spending 0.5mBTC and the client gets 0.321mBTC.
     Since a small amount is used in this example transaction and the
     fees are calculated by the amount of data (bytes) that makes up the
     transaction, irrespective of the value (BTC) of the transaction, this
     has caused the fees to be 35.8% of the transaction amount.
  
     In the case of Arrr, the funds are a lot less than with BTC. The 
     transaction steps involve sending funds from the host->funding address
     and the client redeeming the funds from the funding address. Therefore,
     there are 2 transactions on the blockchain, each taking their share
     of fees.

     When the client funds the Arrr address, the full amount is send to
     the funding address and the network fees subtracted additionally
     from the client's Arrr balance.
     When the fees in the funding address is redeemed by the host,
     the network fee is subtracted from the available funds in the
     funding adress and the host only ends up receiving the balance.
     In this case 0.1milliArrr is subtracted as network fee.
   
     Client pays 0.5mArr, but actually spends a total of 0.6 mArrr:
       Funding address receives 0.5 mArrr and 0.1 goes towards network fees
     Host redeems the 0.5 mArrr in the funding address: 
       0.1 mArrr is deducted for network fees and the host receives 0.4mArrr
    
     For the small amounts used in the example, the fees are equal to 33%
     of the transaction amount.

     A mechanism will have to be devised to accurately illustrate the fees
     to the host & client prior to engaging in the swap, otherwise the 
     parties may accuse one another of not sending the agreed upon funds.

Setup
  Prior to starting the swap, the host and client applications must be
  configured. They must be able to communicate with the BTC & Pirate
  wallets of each participant. Each application (host & client) is
  set up to interact with its owners wallets. 
  Furthermore, the host requires the BTC address of the client and the
  client requires the Arrr address of the host. The setup of these
  fields are described below:

  Wallet: BTC
  -----------
  The atomic swap can work with a bitcoin core full node wallet
  or an Electrum lightweight wallet. For test purposes, the Electrum
  wallet is easier to use, since it doesn't require the full testnet
  blockchain to be downloaded.
  Download the wallet from https://electrum.org/#download
  Required dependency on Linux: apt-get install libsecp256k1 

  First time launch of the wallet:
  If you've just downloaded and installed the wallet, the first time
  you run the application it will create its configuration files inside
  your home directory (~). The directory is: ~/.electrum
  We will edit the config file in the further steps. 
  The most important step of setting up the application is to save the 
  wallet seed (also called the secret) in a safe place, independent of 
  the PC that it is running on. Preferably a piece of paper that is not
  subject to electronic failure. The seed can later be used to restore the 
  wallet (and the funds in side it) if a failure occurrs in the electronic
  BTC wallet.

  Fund the wallet:
  You can fund the wallet from a 'faucet', which send small amounts of
  BTC for free. These funds can be used for test purposed. There is a
  BTC testnet faucet at: https://testnet-faucet.mempool.co
  Inside your wallet, click on the Receive tab and then the New Address
  button. A text box will appear with your new address. Use this address
  at the faucet website so that it can send the funds to you.

  RPC access to the BTC wallet:
  Shut down the application, if it is running.
  Edit the BTC Electrum config file: ~/.electrum/config
  Copy the values for the rpcuser and rpcpassword:
    "rpcpassword": "XXXXXXXXXXXXXXXXXXXXXXX==",
    "rpcuser": "user"
  Edit the asmr BTC config file:
    mkdir ../config
    cp ../config_example/bitcoin.json ../config
    joe ../config/bitcoin.json  (or any other suitable editor)
      Update "url": with the Electrum config values:
        "url": "http://user:XXXXXXXXXXXXXXXXXXXXXXX==@127.0.0.1:8899"
      Note: Use the actual values from the BTC config file, not the examples shown here
  
  Adresses: BTC
  The host sends BTC to the client. The host requires the BTC adres
  of the client. The 'destination' field is used by asmr host to know
  where to send the BTC to. The 'refund' field is used by the asmr host
  to claim its BTC back (refund) if the swap could not be completed.

  In this example the exchange of the address performed manually and outside
  the scope of the example application.

  To obtain a new adres from the Electrum wallet
    Launch the wallet: ./run_electrum --testnet
    On the GUI, select the Receive tab. Click New Address. 
    Copy the address from the text box that appears.

  Host: 
    The host must obtain the BTC address from the client. For this example
    they must use e-mail or an instant messanger application to communicate
    and negotiate the exchange.

    Edit the asmr BTC config file:
    joe ../config/bitcoin.json
      Update "destination" with the BTC adres obtained from the client.

      Update "refund" with the new adres that was obtained from your 
      wallet. Its important that your own adres is in the 'refund' field,
      otherwise you won't be able to claim your BTC funds back if the
      swap could not be completed.
  
  Wallet: Pirate
  --------------
  The Treasure Chest full node wallet is required to perform the
  atomic swap at the time of writing of this document. The 'dev'
  branch of the github repository has a specific instruction added,
  called 'get_tree_state' which is required by the atomic swap.
  Until the instruction is rolled into the main production release,
  use the dev branch.
  The pirate blockchain is approximately 14GB of data. You also need
  the zcash encryption parameters (sapling & sprout parameters) 
  which can be obtained from the pirate.black website. The encryption
  parameters must be extracted in ~/.zcash-params

  First time launch of the wallet:
  If you've just downloaded and installed the wallet, the first time
  you run the application it will create its configuration files inside
  your home directory (~). The directory is: ~/.komodo/PIRATE
  We will edit the config file in the further steps.

  During the launch of the application the encryption parameters will be
  verified. Then the wallet will sync to the blockchain. Only after the
  sync is completed will the menu features of the wallet be accessible.
  The use of a BIP39 seed phrase for the wallet is being introduced. 
  If you run the latest wallet application, save your seed phrase,
  like with the BTC wallet, in a safe location using a paper or other
  non-electronic medium. You only need the seed to restore your wallet
  (and available funds) in the future.

  Fund the wallet:
  PirateChain doesn't have a testnet. You need to perform the tests using
  real coins. You can send 0.5 milli Arrr at a time, which isn't costing
  any real money. 
  You can purchase Arrr at tradeogre.com or kucoin.com and send the coins
  (withdraw) them to an address in your wallet.

  RPC access to the Pirate wallet:
  Edit the Arrr config file: ~/.komodo/PIRATE/PIRATE.conf
  Copy the values for the rpcuser and rpcpassword:
     rpcuser=user1234567890
     rpcpassword=passXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
  Edit the asmr Arrr config file:
    mkdir ../config
    cp ../config_example/piratechain.json ../config
    joe ../config/piratechain.json
      Update "url": with the Arrr config values:
        "url": "http://user123456789:passXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX@127.0.0.1:45453",
      Note: Use the actual values from the config file, not the examples shown here

  Adresses: Arrr
  The client sends Arrr to the host. The client requires the Arrr adres
  of the host. The 'destination' field is used by the asmr client to know
  where to send the Arrr to. The 'refund' field is used by the asmr client
  to claim its Arrr back (refund) if the swap could not be completed.

  In this example the exchange of the address performed manually and outside
  the scope of the example application.

  To obtain a new adres from the Pirate wallet:
    ./pirate-qt-linux
    Select the Receive tab. Click the New button. 
    The new address will appear in the main window. Right-click on the
    address and select 'Copy Address'

  Client: Edit the asmr Arrr config file:
    joe ../config/piratechain.json
      Update "destination" with the Arrr adres obtained from the host.

      Update "refund" with the new adres that was obtained from your 
      wallet. Its important that your own adres is in the 'refund' field,
      otherwise you won't be able to claim your Arrr funds back if the
      swap could not be completed.

How long does it take to perform the swap:
  The blockchain confirmations determine how quickly the steps of the swap
  proceeds. This is unfortunately on the network/miner level and outside our
  control. Offering more fees might incentivise the miners to pick our
  transactions up quicker. The typical swap step durations are as follow:
  Start (T0)     : Funded BTC address
  +16 minutes: Detected 1 confirmation of the BTC funds. Submit the BTC 
               lock transaction
  +9  minutes: BTC locked, waiting for client to confirm BTC lock.
  +1  minute:  Client confirmed BTC lock. Waiting for client to fund the
               Arrr account.
  +10 minutes: Arrr funds confirmed after 8 block confirmations
  +1  minutes: The host & client finalise the swap and submit their 
               redeeming transactions
 --------------
  37 minutes

Executing the swap:
  Launch the BTC and Pirate wallets. Make sure they're connected
  and synced to the networks. Make sure the wallets are funded.
  If you've just send funds to the wallets, first let the incomming
  funds meet their required confirmations (6 for BTC & 8 for Arrr)
  before starting the swap.

  Open two terminal windows. Navigate both to the C++ directory.

  Launch atomic_swap_host in one terminal and atomic_swap_client
  in another.

  The host will prompt you to deposit funds to a newly generated
  BTC 'funding' address. 
  
  From the BTC Electrum wallet, you as the BTC owner send your 
  funds to this address.

  The host will verify on the blockchain that the funding
  address have 1 confirmation.

  The host will then submit the funds to the 'lock' address.
  The host will verify on the blockchain that the lock
  address have 1 confirmation.

  The host will then prompt the client to confirm if it also
  sees the funds in the locked transaction. Once the host &
  client are satisfied about the locked BTC funds, the client
  will prompt the user to send the Arrr coins to the new
  funding address.

  From the Arrr Treasure chest wallet, you as the Arrr owner
  send your funds to this address.

  The client will verify on the blockchain that the funding
  address have 8 confirmations.

  Once the Arrr funds are secured, the host will send an
  encoded form of a secret to the client. The client can
  redeem its BTC using this encoded secret from the host.
  As part of the claiming of the funds by the client, the
  transaction in the blockchain contains information that 
  the host can use to redeem the Arrr funds.

  The client will redeem its BTC as soon as it 
  received the encoded secret from the host.

  As soon as the host detects the BTC transaction on the 
  blockchain it will retrieve the relevant data from it,
  construct the Arrr transaction and submit it to the 
  Arrr blockchain.

  Both parties have claimed their funds and the swap is
  completed.

Linker
Linking multiple rust libraries in a C or C++ program causes this 
error:  lib.rs:105: multiple definition of `rust_eh_personality';

Two work arounds are proposed: When using debug builds of the
rust libraries, they will link in the C/C++ app without giving
this error.

Alternatively, use these linker flags:
  LDFLAGS="-Wl,--allow-multiple-definition"

This was discussed at: https://github.com/rust-lang/rust/issues/44322

