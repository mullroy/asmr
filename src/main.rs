#![deny(unused_must_use)]

mod crypt_engines;
mod coins;
mod cli;
mod dl_eq;

#[cfg(test)]
mod tests;
use crc16::*;

use std::{panic, time::Duration};

use anyhow::Context;
use log::{error, info};
use structopt::StructOpt;
use std::fs;
use std::fs::OpenOptions;
use std::io::prelude::*;

use futures::prelude::*;
use tokio::{
  prelude::*,
  time::timeout,
  net::{TcpStream, TcpListener}
};

use crate::{
  coins::{
    *,
    btc::{host::BtcHost, verifier::BtcVerifier},
    arrr::{client::ArrrClient, verifier::ArrrVerifier}
  },
  cli::{ScriptedCoin, UnscriptedCoin, Cli}
};

const MAGIC: &[u8] = b"ASMR";
const MAGIC_RESPONSE: &[u8] = b"ConfirmASMR";
const MAX_ITEM_LENGTH: u32 = 256 * 1024; // 256 KB. The largest transmitted data is the DL EQ Proof which is still less than this
const TIMEOUT: Duration = Duration::from_secs(60 * 60); // 1 hour


#[tokio::main]
async fn main() {
  env_logger::init();

  let opts = Cli::from_args();
  let scripted_config2 = opts.scripted_config.clone()
    .unwrap_or_else(|| format!("config/{:?}.json", opts.pair.scripted).to_lowercase().into());
  let unscripted_config2 = opts.unscripted_config.clone()
    .unwrap_or_else(|| format!("config/{:?}.json", opts.pair.unscripted).to_lowercase().into());
    
    
  let scripted_config : String ="./config/bitcoin.json".to_string();
  let unscripted_config : String ="./config/piratechain.json".to_string();
  println!("scripted config: {:#?}",scripted_config);
  println!("unscripted config: {:#?}",unscripted_config);

  let mut listen_handle = None;
  if opts.host_or_client.is_host() {
    let mut scripted_host: AnyScriptedHost = match opts.pair.scripted {
      ScriptedCoin::Bitcoin => BtcHost::new(&scripted_config).map(Into::into),
    }.expect("Failed to create scripted host");
    
    //println!("options.pari.unscripted: {}",opts.pair.unscripted);
    
    let mut unscripted_verifier: AnyUnscriptedVerifier = match opts.pair.unscripted {
      UnscriptedCoin::PirateChain => ArrrVerifier::new(&unscripted_config).await.map(Into::into)
    }.expect("Failed to create unscripted verifier");



    // Have the host also host the server socket
    // As this is a proof of concept, this is a valid simplification
    // It simply removes the need to add another config flag/switch
    let opts = opts.clone();
    listen_handle = Some(tokio::spawn(async move {
      let mut listener = TcpListener::bind(opts.tcp_address).await
        .expect("Failed to create TCP listener");
      info!("Listening as host on {}", opts.tcp_address);
      let (stream, addr) = listener.accept().await
        .expect("Failed to accept incoming TCP connection");
      info!("Got connection from {}", addr);

      let swap_fut = panic::AssertUnwindSafe(host(
        opts,
        stream,
        &mut scripted_host,
        &mut unscripted_verifier
      )).catch_unwind();
      let swap_res = timeout(TIMEOUT, swap_fut).await;
      let attempt_refund = match swap_res {
        // Timeout
        Err(_) => {
          panic!("Host swap timed out");
          //true
        }
        // Panic occurred
        Ok(Err(_)) => true,
        // Normal error
        Ok(Ok(Err(err))) => {
          panic!("Error attempting host swap: {:?}", err);
          //true
        },
        // Success
        Ok(Ok(Ok(()))) => false,
      };
      if attempt_refund {
        //scripted_host.refund(unscripted_verifier).await.expect("Couldn't call refund");
        println!("Attempting refund with unscripted_verifier");
      }
    }));
  }

  if opts.host_or_client.is_client() {
    let mut unscripted_client: AnyUnscriptedClient = match opts.pair.unscripted {
      UnscriptedCoin::PirateChain => ArrrClient::new(&unscripted_config).await.map(Into::into),
    }.expect("Failed to create unscripted client");
    let mut scripted_verifier: AnyScriptedVerifier = match opts.pair.scripted {
      ScriptedCoin::Bitcoin => BtcVerifier::new(&scripted_config).map(Into::into),
    }.expect("Failed to create scripted verifier");

    let stream = TcpStream::connect(opts.tcp_address).await.expect("Failed to connect to host");
    let swap_fut = panic::AssertUnwindSafe(client(
      opts,
      stream,
      &mut unscripted_client,
      &mut scripted_verifier
    )).catch_unwind();
    let swap_res = timeout(TIMEOUT, swap_fut).await;
    let attempt_refund = match swap_res {
      // Timeout
      Err(_) => {
        panic!("Client swap timed out");
        //true
      }
      // Panic occurred
      Ok(Err(_)) => true,
      // Normal error
      Ok(Ok(Err(err))) => {
        panic!("Error attempting client swap: {:?}", err);
        //true
      },
      // Success
      Ok(Ok(Ok(()))) => false,
    };
    if attempt_refund {
      unscripted_client.refund(scripted_verifier).await.expect("Couldn't call refund");
    }
  }

  if let Some(listen_handle) = listen_handle {
    listen_handle.await.expect("Swap host panicked");
  }
}

//Host: cmd: Command | state machine nr
//Client: Echo the cmd received from the host
async fn write(stream: &mut TcpStream, cmd: &[u8], value: &[u8]) -> anyhow::Result<()> {
  let len = value.len() as u32 + 1;
  assert!(len <= MAX_ITEM_LENGTH);
  let len = len.to_le_bytes();
  stream.write_all(&len).await?;
  stream.write_all(&cmd).await?;
  stream.write_all(value).await?;
  Ok(())
}

//Host:   Send cmd, which client reads.
//Client: Echo cmd, which host reads
async fn read(stream: &mut TcpStream) -> (Vec<u8>, Vec<u8>) {
  let mut len_buf = [0u8; 4];
  let mut cmd = vec![0u8; 1];
  let mut _result = stream.read_exact(&mut len_buf).await;
  
  let mut len = u32::from_le_bytes(len_buf);
  if len > MAX_ITEM_LENGTH {
    panic!("Attempted to read {} byte item, longer than maximum", len);
  }
  if len == 0 { 
    //println!("Did not read any data");
    cmd[0]=255;
    return (cmd.clone(),cmd)
  }
  if len < 2 {
    panic!("Length must be 2 or larger: {}", len);
  }
    
  _result = stream.read_exact(&mut cmd).await;
  
  len = len - 1;
  let mut buf = vec![0u8; len as usize];
  _result = stream.read_exact(&mut buf).await;
  
  //Return the data
  (cmd,buf)
}

//b_is_host=1 -- Host session, 0-- Client session
fn read_session_key(b_is_host: u8, s_key: &str, s_value: &mut String)
{
  let local_value;  //str
  
  let data;
  
  s_value.clear(); //blank variable
  
  if b_is_host==1
  {
    data = fs::read_to_string("./host_session");
  }
  else
  {
    data = fs::read_to_string("./client_session");
  }
  
  let data = match data {
      Ok(file) => file,
      Err(_error) => {
          println!("No session file found. Assuming new session");
          return;
      },
  };
  
  let split_data = data.split("\n");    
  
  print!("session: {}:",s_key);
  for s in split_data {    
    if s.split("=").count()==2
    {
      let vec_split_item = s.split("=").collect::<Vec<&str>>();
      if vec_split_item[0] == s_key
      {        
        local_value = vec_split_item[1];
        *s_value = local_value.to_string();    //str to String::
        if s_value.len()>64
        {
          let ca_vec = hex::decode( s_value.clone() ).unwrap();
          let ca_bytes:&[u8] = &ca_vec;

          let crc = State::<ARC>::calculate( &ca_bytes[..]);
          println!("len={}, crc={:02x?}",s_value.len(), crc);            
        }
        else
        {
          println!("{}",s_value);            
        }
        return;
      }
    }
  }
  println!("<Not in session>");
}

//b_is_host=1 -- Host session, 0-- Client session
fn write_session_key(b_is_host: u8, s_key: &str, s_value: &str)
{    
  
  let mut file;
      
  if b_is_host==1
  {
    file = OpenOptions::new()
      .create(true)
      .write(true)
      .append(true)
      .open("./host_session")
      .unwrap();
  }
  else
  {
    file = OpenOptions::new()
      .create(true)
      .write(true)
      .append(true)
      .open("./client_session")
      .unwrap();
  }      
      

  if let Err(e) = writeln!(file, "{}={}", s_key,s_value)
  {
    eprintln!("Couldn't write to file: {}", e);
  }
}

async fn host(opts: Cli,
              mut stream: TcpStream,
              host: &mut AnyScriptedHost,
              verifier: &mut AnyUnscriptedVerifier)
              -> anyhow::Result<()> {
  let mut i_state :u8;
  i_state=0;
  let mut _b_state_enter=true;
  
  let mut verifier_keys = Vec::new();
  let mut verifier_keys_crc : u16 = 0;
  let mut client_keys;
  let mut address = String::new();
   
  let mut i_verify_lock_counter : u16 =0;
  
  let mut cmd = vec![0u8; 1];
  cmd[0]=0; //0=Handshake, 1=Exchange Host/Client keys, 2=Confirm Host/Client keys checksum
            //3=host_lock_and_refund_sig keys, 4=Confirm host_lock_and_refund_sig
  
  println!("HOST enter");
  println!("-----------------------------------------------------------------------------------------------");
  loop {
    tokio::time::delay_for(std::time::Duration::from_secs(1)).await; //Prevent while() to max out CPU
    
    if i_state == 0  //Initialise
    {
      println!("HOST: #0 initialise session");
      host.init_session();
      println!("-----------------------------------------------------------------------------------------------");
  
      // Verify the protocol using magic bytes
      println!("HOST: #0 Send: Handshake to client");
      stream.write_all(MAGIC).await.context("Failed to write magic bytes")?;
      write(&mut stream, &cmd, opts.pair.to_string().as_bytes()).await.context("Failed to write pair name to socket")?;
      println!("HOST: #0 Wait for response");      
      //let mut magic = vec![0u8; MAGIC_RESPONSE.len()];
      //stream.read_exact(&mut magic).await.context("Failed to read magic bytes")?;      
      let (_response_code, magic) = read(&mut stream).await;
     
      anyhow::ensure!(magic == MAGIC_RESPONSE, "Bad magic bytes - is the client an ASMR instance?");
      println!("HOST: #0 Received: Handshake from client");      
      
      // Generate keys | Restore keys from session
      // Namely the DL EQ proof, scripted lock/refund keys, and scripted destination key
      println!("HOST: #0 Generate new keys|Restore keys from session");
      verifier_keys = host.generate_keys(verifier).await;      
      verifier_keys_crc = State::<ARC>::calculate( &verifier_keys[..]);
      
      let mut str_value = String::new();
      println!("trying to read state_client_keys_exchanged");
      read_session_key(1, "state_client_keys_exchanged", &mut str_value);   
      
      let mut str_hex_client_keys = String::new();
      read_session_key(1, "client_keys",&mut str_hex_client_keys);
      
      if str_value.len()==0             || //Keys not yet exchanged
         str_value != "1"               || //Keys not yet exchanged
         str_hex_client_keys.len() == 0    //Error: state_client_keys_exchanged set, but client keys not stored.
      {
        println!("HOST: State->1 : Exchange keys");
        _b_state_enter=true;
        i_state=1;
      }
      else
      {
        println!("HOST: State->2 : Verify key checksums");
        _b_state_enter=true;
        i_state=2;
      }
    }    
    else if i_state==1 //Exchange keys
    {
            
      println!("-----------------------------------------------------------------------------------------------");      
      println!("HOST: #1 Send: Verifier keys to client. crc={:02x}",verifier_keys_crc);
      cmd[0]=1; 
      let _result = write(&mut stream, &cmd, &verifier_keys).await.context("Failed to write verifier_keys");       
      println!("HOST: #1 Wait for response");
      
      let (response_code, rx_data) = read(&mut stream).await;                
      if response_code[0] != 1 // 1 = Exchange Host/Client keys
      {
        error!("State error: Send cmd=1, expected response=1, got {}", response_code[0]);
        panic!();
      }
      println!("HOST: #1 Read: Client keys");
      client_keys = rx_data.clone();
      let str_hex_client_keys = hex::encode( client_keys.clone() );
      write_session_key(1, "client_keys", &str_hex_client_keys);

      let client_keys_crc = State::<ARC>::calculate( &client_keys[..]);
      println!("HOST: #1 Client_keys: len={} CRC:{:02x?}",client_keys.len(),client_keys_crc);
      host.verify_keys(&client_keys, verifier).context("Couldn't verify client DlEq proof")?;
      println!("HOST: #1 DlEq proof verified");

      write_session_key(1, "state_client_keys_exchanged", "1");

      //State: BTC account funded?
      println!("HOST: State->3 : BTC account funded?");
      _b_state_enter=true;
      i_state=3;
    }
    else if i_state==2 //Verify exchanged keys
    {
      let mut str_hex_client_keys = String::new();
      read_session_key(1, "client_keys",&mut str_hex_client_keys);
      let ca_vec = hex::decode( str_hex_client_keys.clone() ).unwrap();
      let ca_bytes:&[u8] = &ca_vec;
      let client_keys_crc = State::<ARC>::calculate( &ca_bytes[..]);
      client_keys = ca_vec;
      
      if _b_state_enter==true
      {
        _b_state_enter=false;
        println!("-----------------------------------------------------------------------------------------------");      
        println!("HOST: #2 Send: Verify key checksums. host crc={:02x} client crc={:02x}",verifier_keys_crc, client_keys_crc);        
      }
      
      let mut tx_data = vec![0u8; 4];
      let mut _tmp16 : u16 = 0;
      _tmp16 = verifier_keys_crc >> 8;      
      tx_data[0] = _tmp16 as u8;
      tx_data[1] = verifier_keys_crc as u8;
      
      _tmp16 = client_keys_crc >> 8;      
      tx_data[2] = _tmp16 as u8;
      tx_data[3] = client_keys_crc   as u8;

      cmd[0]=2; //2=Confirm Host/Client keys checksum
      let _result = write(&mut stream, &cmd, &tx_data).await.context("Failed to verify host/client key checksums");       
      
      let (response_code, rx_data) = read(&mut stream).await;
      if response_code[0] != 2 //2=Confirm Host/Client keys checksum
      {
        println!("HOST: #2 State error: Send cmd=2, expected response=2, got {}", response_code[0]);
        panic!();
      }      

      if rx_data[0] == 0      // Did not yet receive the host key 
      {
        println!("HOST: #2 Verify host/client key checksums: Client reported that it has not yet received the host key");
        panic!();
      }
      else if rx_data[0] == 1 // Received host key crc doesn't match our host key in the session
      {
        println!("HOST: #2 Verify host/client key checksums: Client reported that the host key checksum doesn't match its checksum");
        panic!();
      }
      else if rx_data[0] == 2 // Received client key crc doesn't match our client key 
      {
        println!("HOST: #2 Verify host/client key checksums: Client reported that the client key checksum doesn't match its checksum");
        panic!();
      }
      else if rx_data[0] == 3 // Success, CRCs match
      {
        println!("HOST: #2 Verify host/client key checksums: Success");
      }
      else                    // Unknown
      {
        println!("HOST: #2 Verify host/client key checksums: Result code unknown: {}",rx_data[0]);
        panic!();
      }

      
      host.verify_keys(&client_keys, verifier).context("Couldn't verify client DlEq proof")?;
      println!("HOST: #2 DlEq proof verified");

      println!("HOST: State->3 : BTC account funded?");
      _b_state_enter=true;
      i_state=3;
    }
    else if i_state==3 //BTC account funded?
    {    
      if _b_state_enter==true
      {
        _b_state_enter=false;
        
        address = host.generate_deposit_address(); //Generate new funding adres || restore existing adres from session.        
        println!("-----------------------------------------------------------------------------------------------");
        println!("HOST: #3 BTC funding address: {}", address);
                
        let mut s_value = String::new();
        read_session_key(1, "state_btc_funded",&mut s_value);
        if s_value.len() == 0 //Not funded
        {      
          println!("Send your BTC to the funding address. The swap transaction will proceed as soon as the funds are detected on the blockchain.");
        }
        else
        {
          println!("HOST: #3 Account was already funded.");
          println!("HOST: State->4 : Exchange signatures");
          _b_state_enter=true;
          i_state=4;
          continue;
        }
      }
      
      let b_value = host.get_if_funded( &address.clone() ).await;
      if b_value==true
      {
        println!("HOST: #3 Detected BTC funding");
        
        let mut s_value = "1";
        write_session_key(1, "state_btc_funded",&mut s_value);
        
        //Generate and store the refund transaction
        println!("HOST: #3 Store refund transaction");
        host.generate_funding_address_refund().await.context("Could't generate the unlock transaction")?;      
        
        println!("HOST: State->4 : Exchange signatures");
        _b_state_enter=true;
        i_state=4;
      }
    }
    else if i_state==4 //Exchange signatures
    { 
      if _b_state_enter==true
      {
        _b_state_enter=false;
        println!("-----------------------------------------------------------------------------------------------");
        println!("HOST: #4 Exchange signatures");
      }

      
      //Create signature | restore object data from session:
      let host_lock_and_refund_sig = host.create_lock_and_prepare_refund().await.context("Couldn't create the BTC lock")?;      
      let host_lock_and_refund_sig_crc = State::<ARC>::calculate( &host_lock_and_refund_sig[..]);                

      
      //Host_lock_and_refund and Client_refund_and_spend in the session?
      let mut state_signatures_exchanged          = String::new();
      let mut str_hex_host_lock_and_refund_sig    = String::new();
      let mut str_hex_client_refund_and_spend_sig = String::new();
      
      
      read_session_key(1, "state_signatures_exchanged", &mut state_signatures_exchanged);
      read_session_key(1, "host_lock_and_refund_sig",   &mut str_hex_host_lock_and_refund_sig);
      read_session_key(1, "client_refund_and_spend_sig",&mut str_hex_client_refund_and_spend_sig);
      
      let client_refund_and_spend_sig;
      
      if state_signatures_exchanged != "1"
      {        
        // We use our own intermediate address to ensure the transaction isn't malleable, a problem with BTC solved via SegWit
        println!("HOST: #4 Send: Lock & refund signature to client. crc={:02x}",host_lock_and_refund_sig_crc);
        cmd[0]=4;
        let _result = write(&mut stream, &cmd, &host_lock_and_refund_sig).await;
               
        println!("HOST: #4 Wait for response");
        let (response_code, rx_data) = read(&mut stream).await;
        if response_code[0] != 4 //4=host_lock_and_refund_sig keys
        {
          error!("State error: Send cmd=4, expected response=4, got {}", response_code[0]);
          panic!();
        }
        client_refund_and_spend_sig = rx_data;
        println!("HOST: #4 Received: client refund and spend sig");
        
        //Verify signatures:
        host.verify_refund_and_spend(&client_refund_and_spend_sig)?;
        println!("HOST: #4 Refund and spend signature verified");
        
        let mut str_value = "1";
        write_session_key(1, "state_signatures_exchanged", &mut str_value);      
        str_hex_host_lock_and_refund_sig = hex::encode( host_lock_and_refund_sig.clone() );
        write_session_key(1, "host_lock_and_refund_sig", &str_hex_host_lock_and_refund_sig);
        str_hex_client_refund_and_spend_sig = hex::encode( client_refund_and_spend_sig.clone() );
        write_session_key(1, "client_refund_and_spend_sig", &str_hex_client_refund_and_spend_sig); 
        
        //State: Lock BTC funds
        println!("HOST: State->6 : Lock BTC funds");
        _b_state_enter=true;
        i_state=6;
      } 
      else
      { 
        if str_hex_host_lock_and_refund_sig.len() == 0 ||
           str_hex_client_refund_and_spend_sig.len() == 0
        {
          error!("HOST: #4 Session indicates signatures were exchanged, but the contents of the signatures are empty");
          panic!();
        }
      
        //State: Lock BTC funds
        println!("HOST: State->5 : Verify signatures ");
        _b_state_enter=true;
        i_state=5;
      }
    }
    else if i_state==5 //Verify signatures
    {     
      let mut str_value = String::new();
      read_session_key(1, "state_signatures_exchanged",&mut str_value);
      if str_value != "1"
      {
        println!("-----------------------------------------------------------------------------------------------");      
        error!("HOST: #5 Verify signature checksums: Session reported that the signatures was not exchanged");
        panic!();
      }
      let mut str_hex_host_lock_and_refund_sig = String::new();      
      read_session_key(1, "host_lock_and_refund_sig",&mut str_hex_host_lock_and_refund_sig);      
      let ca_vec = hex::decode( str_hex_host_lock_and_refund_sig.clone() ).unwrap();
      let ca_bytes:&[u8] = &ca_vec;
      //let host_lock_and_refund_sig = ca_bytes.clone();
      let host_lock_and_refund_sig_crc = State::<ARC>::calculate( &ca_bytes[..]);
      
      let mut str_hex_client_refund_and_spend_sig = String::new();      
      read_session_key(1, "client_refund_and_spend_sig",&mut str_hex_client_refund_and_spend_sig);      
      let ca_vec = hex::decode( str_hex_client_refund_and_spend_sig.clone() ).unwrap();
      let ca_bytes:&[u8] = &ca_vec;
      let client_refund_and_spend_sig = ca_bytes.clone();
      let client_refund_and_spend_sig_crc = State::<ARC>::calculate( &ca_bytes[..]);
            
      if _b_state_enter==true
      {
        _b_state_enter=false;
        println!("-----------------------------------------------------------------------------------------------");      
        println!("HOST: #5 Verify signature checksums. host crc={:02x} client crc={:02x}",host_lock_and_refund_sig_crc, client_refund_and_spend_sig_crc);
      }
      
      let mut tx_data = vec![0u8; 4];
      let mut _tmp16 : u16 = 0;
      _tmp16 = host_lock_and_refund_sig_crc >> 8;      
      tx_data[0] = _tmp16 as u8;
      tx_data[1] = host_lock_and_refund_sig_crc as u8;
      
      _tmp16 = client_refund_and_spend_sig_crc >> 8;      
      tx_data[2] = _tmp16 as u8;
      tx_data[3] = client_refund_and_spend_sig_crc as u8;

      cmd[0]=5; //5=Verify signature checksums
      let _result = write(&mut stream, &cmd, &tx_data).await.context("Failed to verify signature checksums");
      
      // Next, we have to receive the client's signature for the refund
      // As well as the client's encrypted signature for our claim of the refund
      let (response_code, rx_data) = read(&mut stream).await;
      if response_code[0] != 5 //5=Verify signature checksums
      {
        error!("HOST: #5 State error: Send cmd=5, expected response=5, got {}", response_code[0]);
        panic!();
      }      

      if rx_data[0] == 0      // Did not yet receive the host signature
      {
        error!("HOST: #5 Verify signature checksums: Client reported that it has not yet received the host signature");
        panic!();
      }
      else if rx_data[0] == 1 // Received host signature mismatch
      {
        error!("HOST: #5 Verify signature checksums: Host signature mismatch");
        panic!();
      }
      else if rx_data[0] == 2 // Received client signature mismatch
      {
        error!("HOST: #5 Verify signature checksums: Client signature mismatch");
        panic!();
      }
      else if rx_data[0] == 3 // Success, CRCs match
      {
        println!("HOST: #5 Verify signature checksums: Success");
      }
      else                    // Unknown
      {
        error!("HOST: #5 Verify signature checksums: Result code unknown: {}",rx_data[0]);
        panic!();
      }
      
      host.verify_refund_and_spend(&client_refund_and_spend_sig)?;
      println!("HOST: #5 Refund and spend signature verified");
      // Our failure path is secured, we can publish the lock
      
      read_session_key(1, "state_lock_transaction", &mut str_value);
      if str_value != "1"
      {
        println!("HOST: State->6 : Lock BTC funds");
        _b_state_enter=true;
        i_state=6;
      }
      else
      {
        println!("HOST: State->7 : Exchange client buy-from-lock transaction (BTC funds already locked.)");
        _b_state_enter=true;
        i_state=7;      
      }
    }
    else if i_state==6
    {
      if _b_state_enter==true
      {
        _b_state_enter=false;
        println!("-----------------------------------------------------------------------------------------------");      
        println!("HOST: #6 Lock BTC funds");        
        host.publish_lock().await.context("Couldn't publish the lock")?;
        //FIXIT: Save engine.lock_script & engine.lock_script_bytes?
      }
      
      let mut str_value = String::new();
      read_session_key(1, "state_lock_transaction", &mut str_value);      
      if str_value != "1"
      {
        error!("HOST: #6 Could not publish the BTC funds to the lock transaction");
        panic!();  
      }    

      
      read_session_key(1, "state_client_buy-from-lock_exchanged", &mut str_value);   
      if str_value!="1"
      {      
        //FIXIT: Must create & store the refund from the lock transaction
        println!("HOST: State->7 : Exchange client buy-from-lock transaction");
        _b_state_enter=true;
        i_state=7;
      }
      else
      {
        read_session_key(1, "state_client_btc_funds_locked", &mut str_value);   
        if str_value!="1"
        {
          println!("HOST: State->8 : Client: BTC funds locked?");
          _b_state_enter=true;
          i_state=8;
        }
        else
        {
          println!("HOST: State->9 : Host: Arrr funds locked?");
          _b_state_enter=true;
          i_state=9;
        }          
      }
    }
    else if i_state==7 //Client buy-from-lock transaction
    {
      // In order for the client to be able to now purchase from our lock, we need to prepare buy transaction for them
      // This is sent over with an encrypted signature so when they publish the decrypted version, we learn their key
      if _b_state_enter==true
      {
        _b_state_enter=false;
        println!("-----------------------------------------------------------------------------------------------");      
        println!("HOST: #7 Exchange client buy-from-lock transaction");        
      }

      let mut ca_encrypted_sign_r1 = [0u8; 32];
      let mut ca_encrypted_sign_r2 = [0u8; 32];
      let mut str_hex_encrypted_sign_r1= String::new();
      let mut str_hex_encrypted_sign_r2= String::new();
      
      read_session_key(1, "encrypted_sign_r1", &mut str_hex_encrypted_sign_r1);
      read_session_key(1, "encrypted_sign_r2", &mut str_hex_encrypted_sign_r2);
      if str_hex_encrypted_sign_r1.len()==0 ||
         str_hex_encrypted_sign_r2.len()==0
      {
        //ca_encrypted_sign_r1 = OsRng; //Scalar::random(&mut OsRng);
        //ca_encrypted_sign_r2 = OsRng; //Scalar::random(&mut OsRng);
        getrandom::getrandom(&mut ca_encrypted_sign_r1)?;
        getrandom::getrandom(&mut ca_encrypted_sign_r2)?;
        
        str_hex_encrypted_sign_r1 = hex::encode(ca_encrypted_sign_r1);
        str_hex_encrypted_sign_r2 = hex::encode(ca_encrypted_sign_r2);
      
        write_session_key(1, "encrypted_sign_r1", &mut str_hex_encrypted_sign_r1);
        write_session_key(1, "encrypted_sign_r2", &mut str_hex_encrypted_sign_r2);        
      }
      else
      {
        let ca_vec = hex::decode(str_hex_encrypted_sign_r1.clone()).unwrap();
        let ca_bytes:&[u8] = &ca_vec;
        let mut ca32_bytes : [u8;32] = Default::default();
        ca32_bytes.copy_from_slice(&ca_bytes[0..32]);   
        ca_encrypted_sign_r1 = ca32_bytes;
        
        let ca_vec = hex::decode(str_hex_encrypted_sign_r2.clone()).unwrap();
        let ca_bytes:&[u8] = &ca_vec;
        let mut ca32_bytes : [u8;32] = Default::default();
        ca32_bytes.copy_from_slice(&ca_bytes[0..32]);   
        ca_encrypted_sign_r2 = ca32_bytes;
        
      }      
    
      //Need to execute prepare_buy_for_client in order to initialise self.encrypted_signature,
      //which is used in the final step to unlock the ARRR
      let client_buy_from_lock     = host.prepare_buy_for_client(&ca_encrypted_sign_r1,&ca_encrypted_sign_r2).await.context("Couldn't prepare the buy")?;
      let client_buy_from_lock_crc = State::<ARC>::calculate( &client_buy_from_lock[..]);  
      println!("HOST: #7 Client_buy_from_lock: len={}, CRC:{:02x?}", client_buy_from_lock.len(), client_buy_from_lock_crc);      
    
      let mut s_value = String::new();
      read_session_key(1, "state_client_buy-from-lock_exchanged", &mut s_value);
      if s_value != "1"
      {            
        println!("HOST: #7 Send client buy-from-lock");
        cmd[0]=7; //7=Client buy-from-lock transaction
        let _result = write(&mut stream, &cmd, &client_buy_from_lock).await.context("Failed to write client_buy_from_lock");      
      
        let (response_code, rx_data) = read(&mut stream).await;                
        if response_code[0] != 7 
        {
          error!("State error: Send cmd=7, expected response=7, got {}", response_code[0]);
          panic!();
        }
        print!("HOST: #7 Read: Client respose:");
        let response = rx_data.clone();
        if response.len()<=0 ||
           response[0] != 1
        {
          error!("State error: Client could not verify the buy-from-lock transaction");
          panic!();
        }
        println!(" buy-from-lock confirmed");
        write_session_key(1, "state_client_buy-from-lock_exchanged", "1");
      }
      
      //State:      
      //Even if the locked BTC funds are confirmed, the client needs to restore
      //the lock height. Its done in state 8.
      println!("HOST: State->8 : Client: BTC funds locked?");
      _b_state_enter=true;
      i_state=8;
    }        
    else if i_state==8 //Client: BTC funds locked?
    { 
      if _b_state_enter==true
      {
        _b_state_enter=false;
        println!("-----------------------------------------------------------------------------------------------");      
        println!("HOST: #8 Does client see BTC funds in the locked transaction?");
        println!("         (Wait 20 seconds / reply)");
        i_verify_lock_counter=0;
      }
      
      let mut s_value = String::new();
      read_session_key(1, "state_client_verified_btc_funds_locked", &mut s_value);
      if s_value != "1"
      {
        cmd[0]=8; //8=Client: See locked BTC funds?
        //Note: No data to send. Pad data with one [u8]
        let mut tx_data = vec![0u8; 1];
        tx_data[0]=0;
        println!("write cmd 8");
        let _result = write(&mut stream, &cmd, &tx_data).await.context("Failed to write 'BTC funds locked?'");
        println!("wrote cmd 8, wait for response");
        let (response_code, rx_data) = read(&mut stream).await;
        println!("got response");
        if response_code[0] != 8 
        {
          error!("State error: Send cmd=8, expected response=8, got {}", response_code[0]);
          panic!();
        }
        
        i_verify_lock_counter+=1; //20 second intervals
        println!("HOST: #8 Read: Client respose");
        let response = rx_data.clone();
        if response.len()<=0  ||
          response[0] == 0       //BTC locked funds transaction not detected or # of confirmations < 1
        {
          println!("Client could not yet verify the locked BTC funds ({}/6)",i_verify_lock_counter);
          
          if i_verify_lock_counter>=6 //2:00
          {
            println!("Timeout waiting for client to verify the locked BTC funds");
            panic!();
          }
        }
        else if response[0]==1   //Client verified BTC funds is locked
        {
          println!("Client verified BTC funds are locked. Waiting for client to verify that Arrr is funded");
          i_verify_lock_counter=0;
          
          write_session_key(1, "state_client_verified_btc_funds_locked", "1");

          println!("HOST: State->9 : Client: Arrr funds locked?");
          _b_state_enter=true;
          i_state=9;                          
        }
        else
        {
          println!("Invalid response from client: {}",response[1]);
          panic!();
        }
      }
      else
      {
        //Send cmd=8 so that the client can restore its session variables 
        cmd[0]=8; //8=Client: See locked BTC funds?
        //Note: No data to send. Pad data with one [u8]
        let mut tx_data = vec![0u8; 1];
        tx_data[0]=0;
        println!("write cmd 8");
        let _result = write(&mut stream, &cmd, &tx_data).await.context("Failed to write 'BTC funds locked?'");
        println!("wrote cmd 8, wait for response");
        let (response_code, rx_data) = read(&mut stream).await;
        println!("got response");
        if response_code[0] != 8 
        {
          error!("State error: Send cmd=8, expected response=8, got {}", response_code[0]);
          panic!();
        }
      
        if rx_data[0]==1   //Client verified BTC funds is locked
        {
          println!("HOST: State->9 : Client: Arrr funds locked?");
          _b_state_enter=true;
          i_state=9;
        }
        else
        {
          println!("Invalid response from client");
          panic!();          
        }  
      }
    }
    else if i_state==9 //Client: Arrr funds locked?
    {
      if _b_state_enter==true
      {
        _b_state_enter=false;
        println!("-----------------------------------------------------------------------------------------------");      
        println!("HOST: #9 Confirm from client if the Arrr funds are locked?");
        println!("         (Wait 20 seconds / reply)");
        i_verify_lock_counter=0;
      }
      
      let mut s_value = String::new();
      read_session_key(1, "state_client_verified_arrr_funds_locked", &mut s_value);
      if s_value != "1"
      {
        cmd[0]=9; //9=Client: Arrr funds locked?
        //Note: No data to send. Pad data with one [u8]
        let _result = write(&mut stream, &cmd, &cmd).await.context("Failed to write 'ARRR funds locked?'");
        
        let (response_code, rx_data) = read(&mut stream).await;
        if response_code[0] != 9
        {
          error!("State error: Send cmd=9, expected response=9, got {}", response_code[0]);
          panic!();
        }
        
        i_verify_lock_counter+=1; //20 second intervals
        println!("HOST: #9 Read: Client respose");
        let response = rx_data.clone();
        if response.len()<=0  ||
          response[0] == 0       //Arrr locked funds transaction not detected or # of confirmations < 1
        {
          println!("Client could not verify if the ARRRR funds are locked ({}/12)",i_verify_lock_counter);
          tokio::time::delay_for(std::time::Duration::from_secs(10)).await;
          if i_verify_lock_counter>=12 //2:00
          {
            println!("Timeout waiting for client to verify the locked ARRR funds");
            panic!();
          }
        }
        else if response[0]==1   //Client verified ARRR funds are locked
        {
          println!("Client verified ARRR funds are locked");
          i_verify_lock_counter=0;
          
          write_session_key(1, "state_client_verified_arrr_funds_locked", "1");
          println!("HOST: State->10 : Client: Arrr funds locked?");
          _b_state_enter=true;
          i_state=10;
        }
        else
        {
          println!("Invalid response from client: {}",response[1]);
          panic!();
        }
      }
      else
      {
        println!("HOST: State->10 : Client: Arrr funds locked?");
        _b_state_enter=true;
        i_state=10;
      }
    }
    else if i_state==10 //Host: ARRR funds locked?
    {
      if _b_state_enter==true
      {
        println!("------------------------------------------------------------------------");
        println!("HOST : #10 Funds deposited?");
        _b_state_enter=false;
      }
      
      //let mut s_value = String::new();
      //read_session_key(1, "state_host_verified_arrr_funds_locked", &mut s_value);
      //if s_value != "1"
      //{
        //Have to run each time to have engine.host&engine.witness populated.
        //Alternatively, store vars in session and restore for future runs
        let result = verifier.verify_and_wait_for_send(false).await.context("Couldn't verify and wait for the unscripted send")?;
        println!("result: {}",result);      
        if result==0
        {
          println!("ARRR funds not yet detected");
        }
        else
        {
          println!("ARRR funds detected");
          println!("HOST: State->11 : Share secret"); 
          _b_state_enter=true;
          i_state=11;
         
          let mut s_value = String::new();
          read_session_key(1, "state_host_verified_arrr_funds_locked", &mut s_value);
          if s_value != "1"
          {
            write_session_key(1, "state_host_verified_arrr_funds_locked", "1");
          }
        }
      //}
      //else
      //{
      //  -- Fixit: store host&witness and restore during rerun to save time
      //  println!("ARRR funds already detected");
      //  println!("HOST: State->11 : Share secret"); 
      //  _b_state_enter=true;
      //  i_state=11;      
      //}
    }
    else if i_state==11 //Host: Share secret
    {
      if _b_state_enter==true
      {
        println!("------------------------------------------------------------------------");
        println!("Host: #11 Share secret");
        _b_state_enter=false;
      }      
      
      let mut s_value = String::new();
      read_session_key(1, "state_secret_shared", &mut s_value);
      if s_value != "1"
      {
        // Now that we've verified both transactions are on their networks and confirmed, we transmit the swap secret   
        let secret_crc = State::<ARC>::calculate( &host.swap_secret()[..]);  
        
        println!("HOST: #11 write secret:{:02x?} crc={:02x?}",host.swap_secret(), secret_crc);  
        cmd[0]=11;
        write( &mut stream, &cmd, &host.swap_secret() ).await?;
        
        let (response_code, rx_data) = read(&mut stream).await;                
        if response_code[0] != 11 
        {
          error!("State error: Send cmd=11, expected response=11, got {}", response_code[0]);
          panic!();
        }
        print!("HOST: #11 Read: Client respose:");
        let response = rx_data.clone();
        if response.len()<=0 ||
           response[0] != 1
        {
          error!("State error: Client did not receive the secret");
          panic!();
        }        
        
        write_session_key(1, "state_secret_shared", "1");
      }
      else
      {
        println!("Secret already shared");
        println!("HOST: State->12 : BTC redeemed?"); 
        _b_state_enter=true;
        i_state=12;              
      }
    }
    else if i_state==12
    {
      println!("------------------------------------------------------------------------");
      println!("HOST: #12 Wait for client to buy the BTC from the lock transaction.");
      let mut s_value=String::new();
      read_session_key(1,"state_arrr_redeemed", &mut s_value);
      if s_value.len() == 0
      {
        println!("Redeem Arrr");
        verifier.finish(host).await.context("Couldn't finish buying the unscripted coin")?;
        
        write_session_key(1,"state_arrr_redeemed","1");
      }
      break;
    }
  }
  /*
  println!("-----------------------------------------------------------------------------------------------");
  // Next, we have to receive the client's signature for the refund
  // As well as the client's encrypted signature for our claim of the refund
  println!("HOST: #4 Refund_and_spend_signature");
  
  let mut str_hex_refund_and_spend_sig = String::new();
  read_session_key("client__refund_and_spend_sig",&mut str_hex_refund_and_spend_sig);
  let refund_and_spend_sig;
  if (str_hex_refund_and_spend_sig.len() == 0)
  {  
    println!("HOST: #4 Read refund_and_spend_sig");

  }
  else
  {
    println!("HOST: #4 Session: refund_and_spend_sig");
    let ca_vec = hex::decode( str_hex_refund_and_spend_sig.clone() ).unwrap();
    //let client_keys_recast:&[u8] = &ca_vec;
    refund_and_spend_sig = ca_vec;
  }
  
  let refund_and_spend_sig_crc = State::<ARC>::calculate( &refund_and_spend_sig[..]); 
  println!("HOST: #4 Verify refund_and_spend_sig, len={}, crc={:02x?}\n{:02x?}", refund_and_spend_sig.len(), refund_and_spend_sig_crc, refund_and_spend_sig);
  host.verify_refund_and_spend(&refund_and_spend_sig)?;
  println!("HOST: #4 Refund and spend signature verified");
    
  println!("-----------------------------------------------------------------------------------------------");    
  // Once we have our failure path secured, we publish the lock and move on
  println!("Host: #5 Publish BTC received on the funding address to the lock transaction. Need 1 confirmation on the blockchain");
  host.publish_lock().await.context("Couldn't publish the lock")?;
  
  println!("-----------------------------------------------------------------------------------------------");    
  // In order for the client to be able to now purchase from our lock, we need to prepare buy transaction for them
  // This is sent over with an encrypted signature so when they publish the decrypted version, we learn their key
  println!("HOST: #6 prepare_buy_for_client()");  
  let prepare_buy = host.prepare_buy_for_client().await.context("Couldn't prepare the buy")?;
  let prepare_buy_crc = State::<ARC>::calculate( &prepare_buy[..]);  
  println!("HOST: #6 write prepare_buy to client: len={}, CRC:{:02x?}", prepare_buy.len(), prepare_buy_crc);
  write(&mut stream, &prepare_buy).await?;

  println!("-----------------------------------------------------------------------------------------------");    
  // Now, we wait for the unscripted send to appear
  println!("HOST: #7 Scanning for client transaction on the Arrr blockchain");
  verifier.verify_and_wait_for_send().await.context("Couldn't verify and wait for the unscripted send")?;
  println!("HOST: #7 Both transactions locked on the blockchain.");
  
  println!("-----------------------------------------------------------------------------------------------");    
  // Now that we've verified both transactions are on their networks and confirmed, we transmit the swap secret    
  let secret_crc = State::<ARC>::calculate( &host.swap_secret()[..]);  
  println!("HOST: #8 Write secret to the client");
  println!("HOST: #8 write secret:{:02x?} crc={:02x?}",host.swap_secret(), secret_crc);  
  write(&mut stream, &host.swap_secret()).await?;

  // Finally, we watch for the client to buy from the lock
  // Then we can recover the key and claim the other coin
  println!("-----------------------------------------------------------------------------------------------");    
  println!("HOST: #9 Wait for client to buy the BTC from the lock transaction.");
  println!("         Recover key and clain our coins");
  verifier.finish(host).await.context("Couldn't finish buying the unscripted coin")?;
  */
  println!("Swap completed");
  Ok(())
}

static mut global_client_counter: i32 = 0;

async fn client(opts: Cli,
                mut stream: TcpStream,
                client: &mut AnyUnscriptedClient,
                verifier: &mut AnyScriptedVerifier)
                -> anyhow::Result<()> {
  // The majority of comments explaining this protocol and this implementation is in the host function
  // The comments here are meant to explain the client-specific side of things
  //let cmd = vec![0u8; 1];
  let mut response = vec![0u8; 1];

  println!("CLIENT enter");
  println!("-----------------------------------------------------------------------------------------------");
  
  
  loop {
    unsafe {
      println!("client() global counter: {}",global_client_counter)
    }
    tokio::time::delay_for(std::time::Duration::from_secs(10)).await;
  }
  
  
  let mut magic = [0u8; MAGIC.len()];
  stream.read_exact(&mut magic).await.context("Failed to read magic bytes")?;
  println!("CLIENT: Connected to host. Magic len={}\n{:02x?}\n",magic.len(), magic);
  anyhow::ensure!(magic == MAGIC, "Bad magic bytes - is the host an ASMR instance?");

  let (cmd, rx_data) = read(&mut stream).await;
  if cmd[0] != 0 // 0 = Handshake
  {
    error!("State error: Expected cmd=0, got {}", cmd[0]);
    panic!();
  }
  let remote_pair=rx_data;
  println!("CLIENT: HOST handshake len{}\n{:02x?}\n", remote_pair.len(), remote_pair);
  if remote_pair != opts.pair.to_string().as_bytes() {
    anyhow::bail!("The host is attempting to exchange a different pair");
  }
  
  println!("CLIENT: Send magic response. len={}\n{:02x?}\n", MAGIC_RESPONSE.len(), MAGIC_RESPONSE);  
  //stream.write_all(MAGIC_RESPONSE).await.context("Failed to write magic bytes")?;
  response[0] = 0;
  let _result = write(&mut stream, &response, MAGIC_RESPONSE).await;
  println!("CLIENT: Sent handshake response len{}\n{:02x?}\n", MAGIC_RESPONSE.len(), MAGIC_RESPONSE);
  println!("-----------------------------------------------------------------------------------------------");

  println!("CLIENT: #0 Generate|restore keys()");
  // Generate keys | Restore keys from session
  let client_keys = client.generate_keys(verifier).await;
  let client_keys_crc = State::<ARC>::calculate( &client_keys[..]);
  println!("CLIENT: #0 client_keys len={}, CRC={:02x?}",client_keys.len(), client_keys_crc);  

  loop {
    let (cmd, rx_data) = read(&mut stream).await;
    
    if cmd[0]!=255
    {
      println!("-----------------------------------------------------------------------------------------------");
      println!("Received command {}",cmd[0]);
    }
    
    if cmd[0]==1 //1=Exchange Host/Client keys.  Input data=host_keys, Response data=client_keys
    {
      let host_keys = rx_data;
      //host_keys
      let str_hex_host_keys = hex::encode( host_keys.clone() );      
      let host_keys_crc = State::<ARC>::calculate( &host_keys[..]);
      println!("CLIENT: #1 Host_keys: len={} CRC:{:02x?}",host_keys.len(),host_keys_crc);
      
      client.verify_keys(&host_keys, verifier).context("Couldn't verify host DlEq proof")?;
      println!("CLIENT: host keys verified\n");
      
      println!("CLIENT: #1 Transmit client_keys");
      let _result = write(&mut stream, &cmd, &client_keys).await;
      
      let str_hex_client_keys = hex::encode( client_keys.clone() );
      write_session_key(0, "state_host_keys_exchanged", "1");      
      write_session_key(0, "host_keys",   &str_hex_host_keys);
      write_session_key(0, "client_keys", &str_hex_client_keys);      
    }    
    else if cmd[0]==2 //2=Confirm Host/Client keys checksum. Input data=[host_key_crc][client_key_crc], 
                      //Response data=0 : Did not yet receive the host key 
                      //             =1 : Received host key crc doesn't match our host key in the session
                      //             =2 : Received client key crc doesn't match our client key 
                      //             =3 : Success, CRCs match
    {
      //host_keys
      let mut str_host_keys_exchanged = String::new();
      let mut str_hex_host_keys       = String::new();
      read_session_key(0, "state_host_keys_exchanged", &mut str_host_keys_exchanged);
      read_session_key(0, "host_keys",                 &mut str_hex_host_keys);
      
      if str_host_keys_exchanged != "1"
      {        
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 0; //Did not yet receive the host key
        let _result = write(&mut stream, &cmd, &tx_data).await;         
        error!("Host command=2: confirmation of host/client keys. Client doesn't have the host key in the session");        
      }
      
      let host_keys     = hex::decode( str_hex_host_keys ).unwrap();
      let host_keys_crc = State::<ARC>::calculate( &host_keys.clone()[..]);
      println!("CLIENT: #2 Session host_keys: len={} CRC:{:02x?}",host_keys.len(),host_keys_crc);

      let reconstructed_host_crc = ((rx_data[0] as u16) << 8) | rx_data[1] as u16;
      println!("CLIENT: #2 Received host_keys: CRC:{:02x?}", reconstructed_host_crc);
      
      if host_keys_crc != reconstructed_host_crc
      {
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 1; //host keys doesn't match
        let _result = write(&mut stream, &cmd, &tx_data).await;  
        error!("Host command=2: confirmation of host/client keys. CRC of session host_key doesn't match the checksum from the host");        
      }
      
      let reconstructed_host_crc = ((rx_data[2] as u16) << 8) | rx_data[3] as u16;
      if client_keys_crc != reconstructed_host_crc
      {
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 2; //client keys doesn't match
        let _result = write(&mut stream, &cmd, &tx_data).await;  
        error!("Host command=2: confirmation of host/client keys. CRC of session client_key doesn't match the checksum from the host");        
      }
            
      client.verify_keys(&host_keys, verifier).context("Couldn't verify host DlEq proof")?;
      println!("CLIENT: #2 Host keys verified. Transmit result.");
      let mut tx_data = vec![0u8; 1];
      tx_data[0] = 3; //CRCs match
      let _result = write(&mut stream, &cmd, &tx_data).await; 
      
      println!("CLIENT: #2 Waiting for host to confirm funding of the BTC account");
    }
    else if cmd[0]==4 //4=Exchange Host/Client signatures.  Input data=host_signature, Response data=client_signature
    {      
      //host_lock_and_refund_sig
      let host_lock_and_refund_sig = rx_data;
      
      let host_lock_and_refund_sig_crc = State::<ARC>::calculate( &host_lock_and_refund_sig.clone()[..]);
      println!("CLIENT: #4 Received host lock_and_refund_sig: len={} CRC:{:02x?}",host_lock_and_refund_sig.len(),host_lock_and_refund_sig_crc);

      let mut ca_encrypted_sign_r1 = [0u8; 32];      
      let mut ca_encrypted_sign_r2 = [0u8; 32];
      let mut str_hex_encrypted_sign_r1= String::new();
      let mut str_hex_encrypted_sign_r2= String::new();
      
      read_session_key(0, "encrypted_sign_r1", &mut str_hex_encrypted_sign_r1);
      read_session_key(0, "encrypted_sign_r2", &mut str_hex_encrypted_sign_r2);
      if str_hex_encrypted_sign_r1.len()==0 ||
         str_hex_encrypted_sign_r2.len()==0
      {
        //ca_encrypted_sign_r1 = OsRng; //Scalar::random(&mut OsRng);
        //ca_encrypted_sign_r2 = OsRng; //Scalar::random(&mut OsRng);
        getrandom::getrandom(&mut ca_encrypted_sign_r1)?;
        getrandom::getrandom(&mut ca_encrypted_sign_r2)?;
        
        str_hex_encrypted_sign_r1 = hex::encode(ca_encrypted_sign_r1);
        str_hex_encrypted_sign_r2 = hex::encode(ca_encrypted_sign_r2);
      
        write_session_key(0, "encrypted_sign_r1", &mut str_hex_encrypted_sign_r1);
        write_session_key(0, "encrypted_sign_r2", &mut str_hex_encrypted_sign_r2);
      }
      else
      {
        let ca_vec = hex::decode(str_hex_encrypted_sign_r1.clone()).unwrap();
        let ca_bytes:&[u8] = &ca_vec;
        let mut ca32_bytes : [u8;32] = Default::default();
        ca32_bytes.copy_from_slice(&ca_bytes[0..32]);   
        ca_encrypted_sign_r1 = ca32_bytes;
        
        let ca_vec = hex::decode(str_hex_encrypted_sign_r2.clone()).unwrap();
        let ca_bytes:&[u8] = &ca_vec;
        let mut ca32_bytes : [u8;32] = Default::default();
        ca32_bytes.copy_from_slice(&ca_bytes[0..32]);   
        ca_encrypted_sign_r2 = ca32_bytes;
        
      }
      
      // Also offer them a way to claim the refund transaction if our side cancels/errors
      let client_refund_and_spend_sig = verifier.complete_refund_and_prepare_spend(
                                        &host_lock_and_refund_sig,
                                        &ca_encrypted_sign_r1, 
                                        &ca_encrypted_sign_r2
                                        ).await.context("Couldn't complete the refund transaction")?;                                            
      let client_refund_and_spend_sig_crc = State::<ARC>::calculate( &client_refund_and_spend_sig.clone()[..]);
      println!("CLIENT: #4 Client refund_and_spend_signature: len={}, crc={:02x?}\n",client_refund_and_spend_sig.len(), client_refund_and_spend_sig_crc );
      
      println!("CLIENT: Transmit client refund_and_spend_signature");
      write(&mut stream, &cmd, &client_refund_and_spend_sig).await?; 
      
      //Write succeeded at this point. Log the data into the session:
      let mut str_signatures_exchanged = String::new();
      read_session_key(0, "state_signatures_exchanged", &mut str_signatures_exchanged);
      if str_signatures_exchanged != "1"
      {
        str_signatures_exchanged = "1".to_string();
        write_session_key(0, "state_signatures_exchanged", &mut str_signatures_exchanged);      
        
        let str_hex_host_lock_and_refund_sig = hex::encode( host_lock_and_refund_sig.clone() );
        write_session_key(0, "host_lock_and_refund_sig", &str_hex_host_lock_and_refund_sig);

        let str_hex_client_refund_and_spend_sig = hex::encode( client_refund_and_spend_sig.clone() );
        write_session_key(0, "client_refund_and_spend_sig", &str_hex_client_refund_and_spend_sig);            
      }
    }    
    else if cmd[0]==5 //5=Confirm Host/Client signature checksum. Input data=[host_signature_crc][client_signature_crc], 
                      //Response data=0 : Did not yet receive the host signature
                      //             =1 : Received host signature crc doesn't match our value in the session
                      //             =2 : Received client signature crc doesn't match our value in the session
                      //             =3 : Success, CRCs match
    {
      //host_signature
      let mut str_signatures_exchanged = String::new();
      let mut str_hex_host_lock_and_refund_sig = String::new();
      let mut str_hex_client_refund_and_spend_sig = String::new();
      read_session_key(0, "state_signatures_exchanged", &mut str_signatures_exchanged);
      read_session_key(0, "host_lock_and_refund_sig",   &mut str_hex_host_lock_and_refund_sig);
      read_session_key(0, "client_refund_and_spend_sig",&mut str_hex_client_refund_and_spend_sig);            
      
      if str_signatures_exchanged != "1"
      {
        error!("CLIENT: #5: Confirmation of host/client signatures. Client doesn't have the host_lock_and_refund_sig in the session");
        
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 0; //BTC locked funds not detected after 20 seconds
        let _result = write(&mut stream, &cmd, &tx_data).await;         
      }
      else
      {
        let host_lock_and_refund_sig     = hex::decode( str_hex_host_lock_and_refund_sig ).unwrap();
        let host_lock_and_refund_sig_crc = State::<ARC>::calculate( &host_lock_and_refund_sig.clone()[..]);
        println!("CLIENT: #5 Session host_keys: len={} CRC:{:02x?}",host_lock_and_refund_sig.len(),host_lock_and_refund_sig_crc);

        let reconstructed_host_lock_and_refund_sig_crc = ((rx_data[0] as u16) << 8) | rx_data[1] as u16;
        println!("CLIENT: #5 Received host_keys: CRC:{:02x?}", reconstructed_host_lock_and_refund_sig_crc);
        
        if host_lock_and_refund_sig_crc != reconstructed_host_lock_and_refund_sig_crc
        {
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 1; //Received host signature crc doesn't match our value in the session
          let _result = write(&mut stream, &cmd, &tx_data).await;  
          error!("CLIENT: #5: Confirmation of host/client signatures. CRC of host_lock_and_refund_sig mismatch");
          panic!();
        } 

        let reconstructed_client_refund_and_spend_sig_crc = ((rx_data[2] as u16) << 8) | rx_data[3] as u16;
        println!("CLIENT: #5 Received client_keys: CRC:{:02x?}", reconstructed_client_refund_and_spend_sig_crc);


        //Compare recalulcated signature to the stored signature:
        let decoded = hex::decode(str_hex_client_refund_and_spend_sig).unwrap();
        let crc     = State::<ARC>::calculate( &decoded.clone()[..]);
        if crc != reconstructed_client_refund_and_spend_sig_crc
        {
          println!("CLIENT #5 stored and recalculated CRCs doesn't match");
        }
        else
        {
          println!("CLIENT #5 stored and recalcualted CRCs match");
        }
        
        let mut ca_encrypted_sign_r1 : [u8;32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let mut str_hex_encrypted_sign_r1= String::new();
        let mut ca_encrypted_sign_r2 : [u8;32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let mut str_hex_encrypted_sign_r2= String::new();
        
        read_session_key(0, "encrypted_sign_r1", &mut str_hex_encrypted_sign_r1);
        read_session_key(0, "encrypted_sign_r2", &mut str_hex_encrypted_sign_r2);
        if str_hex_encrypted_sign_r1.len()==0 ||
           str_hex_encrypted_sign_r2.len()==0
        {
          getrandom::getrandom(&mut ca_encrypted_sign_r1)?;
          getrandom::getrandom(&mut ca_encrypted_sign_r2)?;
                  
          str_hex_encrypted_sign_r1 = hex::encode(ca_encrypted_sign_r1);
          str_hex_encrypted_sign_r2 = hex::encode(ca_encrypted_sign_r2);
                
          write_session_key(0, "encrypted_sign_r1", &mut str_hex_encrypted_sign_r1);
          write_session_key(0, "encrypted_sign_r2", &mut str_hex_encrypted_sign_r2);        
        }
        else
        {
          let ca_vec = hex::decode(str_hex_encrypted_sign_r1.clone()).unwrap();
          let ca_bytes:&[u8] = &ca_vec;
          let mut ca32_bytes : [u8;32] = Default::default();
          ca32_bytes.copy_from_slice(&ca_bytes[0..32]);   
          ca_encrypted_sign_r1 = ca32_bytes;
                  
          let ca_vec = hex::decode(str_hex_encrypted_sign_r2.clone()).unwrap();
          let ca_bytes:&[u8] = &ca_vec;
          let mut ca32_bytes : [u8;32] = Default::default();
          ca32_bytes.copy_from_slice(&ca_bytes[0..32]);   
          ca_encrypted_sign_r2 = ca32_bytes;
        }
        
        
        
        //Generate client refund signature, so that the verifier.complete_refund_and_prepare_spend() code gets executed.
        let client_refund_and_spend_sig = verifier.complete_refund_and_prepare_spend(
                                          &host_lock_and_refund_sig,
                                          &ca_encrypted_sign_r1,
                                          &ca_encrypted_sign_r2
                                          ).await.context("Couldn't complete the refund transaction")?;
        let client_refund_and_spend_sig_crc = State::<ARC>::calculate( &client_refund_and_spend_sig.clone()[..]);      
        
        
        
        if client_refund_and_spend_sig_crc != reconstructed_client_refund_and_spend_sig_crc
        {
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 2; //Received client signature crc doesn't match our value in the session
          let _result = write(&mut stream, &cmd, &tx_data).await;  
          error!("CLIENT: #5: Confirmation of host/client signatures. CRC of client_refund_and_spend_sig mismatch");
        }
                    
        println!("CLIENT: #5 Host/client signatures verified. Transmit result.");
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 3; //CRCs match
        let _result = write(&mut stream, &cmd, &tx_data).await; 
        
        println!("CLIENT: #5 Waiting for host to lock BTC funds");
      }
    }
    else if cmd[0]==7 //7=Client prepare_buy from BTC lock
    {       
      // Receive info about the buy transaction we will end up publishing
      // Namely, the host's signature, which we'll use to verify the buy and make sure we should continue
      //host_lock_and_refund_sig
      let prepared_buy = rx_data;
      
      let prepared_buy_crc = State::<ARC>::calculate( &prepared_buy[..]);
      println!("CLIENT: #7 Client prepare_buy from BTC lock len={} CRC:{:02x?}",prepared_buy.len(),prepared_buy_crc);
      
      let mut str_hex_buy_transaction = verifier.verify_prepared_buy(&prepared_buy)?; //FIXIT: Evaluate & report the failure
      println!("CLIENT: #7 Verified prepared_buy");
      
      let mut s_value=String::new();
      read_session_key(0, "prepared_buy_from_btc_lock", &mut s_value);
      if s_value.len() == 0
      {
        let mut str_hex_prepared_buy = hex::encode(prepared_buy);
        write_session_key(0, "prepared_buy_from_btc_lock", &mut str_hex_prepared_buy);
        
//        let ca_vec = serialize( &buy_transaction.clone() );
//        let ca_bytes:&[u8] = &ca_vec;
//        let str_hex_buy = hex::encode(ca_bytes);
        write_session_key(0, "buy_transaction", &mut str_hex_buy_transaction);
      }
      
      println!("CLIENT: #7 Client prepare_buy from BTC lock verified. Transmit result.");
      let mut tx_data = vec![0u8; 1];
      tx_data[0] = 1; //prepare_buy verified.
      let _result = write(&mut stream, &cmd, &tx_data).await;
    }
    else if cmd[0]==8 //8=Verify BTC locked; Prompt for ARRR to be deposited to funding address
    {
      println!("---------------------------------------------------------------");
      println!("Process cmd 8: Verify if BTC funds are locked");
      /*
      We now need to finally verify the lock, as well as start tracking it
      We can get the lock via two methods
      A) Checking the spendable outputs for the lock script's address (via P2WSH in the case of BTC)
      B) Being transmitted its TX ID
      The first is preferred due it lowering the amount of data transferred between the two parties
      */
      
      let mut s_value = String::new();
      let mut str_hex_lock_height = String::new();
      let mut _lock_height : isize = 0;
      
      read_session_key(0, "btc_locked", &mut s_value);
      
      if s_value != "1"
      {
        println!("CLIENT: #8 Verifying if BTC funds are locked on the blockchain (Expected after 1 confirmation)");
        _lock_height = verifier.verify_and_wait_for_lock(false).await?;
        if _lock_height==0
        {
          println!("CLIENT: #8 BTC funds not detected in lock address after 20 seconds");
          //Funds not yet in the lock
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 0; //BTC locked funds not detected after 20 seconds
          let _result = write(&mut stream, &cmd, &tx_data).await;        
        }
        else
        {
          println!("CLIENT: #8 BTC funds detected in the lock transaction: {}",_lock_height);
          
          write_session_key(0, "btc_locked", "1");
          let hex_str_lock_height = hex::encode( &_lock_height.to_string() );
          write_session_key(0, "lock_transaction_confirmation_height",&hex_str_lock_height);
          write_session_key(0, "arrr_address", &client.get_address() );
          
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 1; //BTC locked funds detected
          let _result = write(&mut stream, &cmd, &tx_data).await;                      
        }
      }
      else
      {
        read_session_key(0, "lock_transaction_confirmation_height", &mut str_hex_lock_height);
        let vec_value = hex::decode(str_hex_lock_height).unwrap();
        let str_value = String::from_utf8_lossy(&vec_value);
        _lock_height   = str_value.parse::<isize>().unwrap();      
        
        verifier.restore_lock_height(_lock_height);
        println!("Restored lock height from session: {}",_lock_height);
         
        println!("send back '1'");
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 1; //BTC locked funds detected
        let _result = write(&mut stream, &cmd, &tx_data).await; 
      }
    }
    else if cmd[0]==9 //Arrr account funded?
    {
      let mut s_value = String::new();
      read_session_key(0, "arrr_funded", &mut s_value);
      if s_value != "1"
      {
        // Now that the BTC is locked on-chain and we have everything we need to buy its funds,
        // we need to publish our Arrr transaction
        println!("Send your Arrr to {} for the swap to continue", client.get_address());
        
        let result = client.wait_for_deposit(false).await?;
        //let amount = result.unwrap();
        println!("Result contents: {}",result);
        
        if result==0
        {
          println!("CLIENT: #9 ARRR funds not detected after 20 seconds");
          //Funds not yet in the lock
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 0; //ARRR funds not detected after 20 seconds
          let _result = write(&mut stream, &cmd, &tx_data).await;        
        }
        else
        {
          println!("CLIENT: #9 ARRR funds detected");
          
          write_session_key(0, "arrr_funded", "1");
          
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 1; //ARRR funds detected
          let _result = write(&mut stream, &cmd, &tx_data).await;                      
        }
      }
      else
      {
        println!("CLIENT: #9 ARRR account already funded");
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 1; //Arrr account funded
        let _result = write(&mut stream, &cmd, &tx_data).await;       
      }
    }    
    else if cmd[0]==11 //Share secret
    {
      let vec_secret = rx_data;
      let str_hex_secret = hex::encode( vec_secret.clone() );
      let secret_crc = State::<ARC>::calculate( &vec_secret[..]);
      
      println!("CLIENT: #11 Received secret:{:02x?} crc={:02x?}",vec_secret, secret_crc);
      
      let mut s_value = String::new();
      read_session_key(0, "secret", &mut s_value);
      if s_value != "1"
      {
        write_session_key(0, "secret", &str_hex_secret);
          
        //Restore the buy transaction
        //FIXIT:this should be moved to stage 7:
        let mut str_hex_prepared_buy = String::new();
        read_session_key(0, "prepared_buy_from_btc_lock", &mut str_hex_prepared_buy);
        let vec_prepared_buy = hex::decode(&str_hex_prepared_buy).unwrap();                 
        let _str_hex_buy_transaction = verifier.verify_prepared_buy(&vec_prepared_buy)?;
      
        println!("CLIENT: #11 Finalise BTC buy");
        let (vec_buy_transaction,vec_buy_transaction_txid) = verifier.finish(&vec_secret).await.context("Couldn't finishing buying the scripted coin")?;
        println!("CLIENT: #11 Buy completed");
        
        let str_hex_buy = hex::encode(vec_buy_transaction);
        let str_hex_buy_txid = hex::encode(vec_buy_transaction_txid);
        
        println!("BTC buy transaction: {}",str_hex_buy);
        println!("BTC buy txid: {}", str_hex_buy_txid );        
        
        write_session_key(0,"buy_transaction",&str_hex_buy);
        write_session_key(0,"buy_transaction_txid",&str_hex_buy_txid);
      }
      let mut tx_data = vec![0u8; 1];
      tx_data[0] = 1; //Secret received. Buy transaction submitted
      let _result = write(&mut stream, &cmd, &tx_data).await;      
      
      break;
    }    

    tokio::time::delay_for(std::time::Duration::from_secs(1)).await;
  }
  
  println!("Swap completed");
  Ok(())
}
