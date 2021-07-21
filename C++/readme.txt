Build
  Library
  =======
  First build the asmr rust crate, by executing 'cargo build'
  in the top directory. To build a release (non debug), use
  the command: cargo build --release
  The debug build is inside target/debug and 
  the release build is inside target/release

  Two compile errors may appear in a support crate (secp256kfun-0.1.5) which can be
  fixed as follow:
    ~/.cargo/registry/src/github.com-1ecc6299db9ec823/secp256kfun-0.1.5/src/lib.rs
    Line 1: remove 'external_doc': 
      #![feature(rustc_attrs, min_specialization)]
    
    ~/.cargo/registry/src/github.com-1ecc6299db9ec823/secp256kfun-0.1.5/src/backend/parity/constant_time.rs
    Line 220: Comment out: 
      //scalar.cond_neg_assign(Choice::from(neg as u8));  

  C++ example
  ===========
  The build environment assumes Gnu/Linux with the C++ compiler
  preinstalled. On Debian & derivatives, run 'apt-get install
  build-essential' to install the basic compiler and build
  environment.

  The header file for libasmr is included in this directory.
  Its called libasmr.h. To use the library with other projects
  you need to include this H file.

  To build the example programs, just run 'make' in the C++
  sub directory. Two applications are created: 
    atomic_swap_host
     - The host controls the swap
     - The host issues commands to the client as the swap progresses
     - The host sends BTC to the client and receives Arrr from the client
    atomic_swap_client
     - The client participating in the swap
     - The client responds to the commands received from the host
     - The client received BTC from the host and sends Arrr to the host

Setup
  Prior to starting the swap, the host and client applications must be
  configured. They must be able to communicate with the BTC & Pirate
  wallets of each participant. Each application (host & client) is
  set up to interact with its owners wallets. 
  Furthermore, the host requires the BTC address of the client and the
  client requires the Arrr address of the host. The setup of these
  fields are described below:

  Wallet: BTC
  The atomic swap can work with a bitcoin core full node wallet
  or an Electrum lightweight wallet. For test purposes, the Electrum
  wallet is easier to use, since it doesn't require the full testnet
  blockchain to be downloaded.

  RPC access for asmr to BTC:
  Edit the BTC Electrum config file: ~/.electrum/config
  Copy the values for the rpcuser and rpcpassword:
    "rpcpassword": "XXXXXXXXXXXXXXXXXXXXXXX==",
    "rpcuser": "user"
  Edit the asmr BTC config file:
    mkdir ../config
    cp ../config_example/bitcoin.json ../config
    joe ../config/bitcoin.json
      Update "url": with the Electrum config values:
        "url": "http://user:XXXXXXXXXXXXXXXXXXXXXXX==@127.0.0.1:8899"
      Note: Use the actual values from the config file, not the examples shown here
  
  Adresses: BTC
  The host sends BTC to the client. The host requires the BTC adres
  of the client. The 'destination' field is used by asmr host to know
  where to send the BTC to. The 'refund' field is used by the asmr host
  to claim its BTC back (refund) if the swap could not be completed.

  The party acting as host of the swap needs to communicate with the 
  party thats acting as client to obtain their BTC address. This is
  the adres where the BTC funds are send to from the host to the client.

  To obtain a new adres from the Electrum wallet:
    ./run_electrum --testnet
    Select the Receive tab. Click New Address. 
    Copy the address in the window text box that appears.

  Host: Edit the asmr BTC config file:
    joe ../config/bitcoin.json
      Update "destination" with the BTC adres obtained from the client.

      Update "refund" with the new adres that was obtained from your 
      wallet. Its important that your own adres is in the 'refund' field,
      otherwise you won't be able to claim your BTC funds back if the
      swap could not be completed.
  
  Wallet: Pirate
  The Treasure Chest full node wallet is required to perform the
  atomic swap at the time of writing of this document. The dev
  branch of the github repository has a specific instruction added,
  called 'get_tree_state' which is required by the atomic swap.
  Until the instruction is rolled into the main production release,
  use the dev branch.
  The pirate blockchain is approximately 14GB of data, which can
  take a long time to download/sync to the main net.

  RPC access for asmr to Pirate:
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

  The party acting as client of the swap needs to communicate with the 
  party thats acting as host to obtain their Arrr address. This is
  the adres where the Arrr funds are send to from the client to the host.

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

Executing the swap:


  
Using the library
=================


Linker
=====
Linking multiple rust libraries in a C or C++ program causes this 
error:  lib.rs:105: multiple definition of `rust_eh_personality';

Two work arounds are proposed: When using debug builds of the
rust libraries, they will link in the C/C++ app without giving
this error.

Alternatively, use these linker flags:
  LDFLAGS="-Wl,--allow-multiple-definition"

This was discussed at: https://github.com/rust-lang/rust/issues/44322