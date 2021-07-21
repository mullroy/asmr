use std::ptr;
use libc::c_void;
use std::ffi::CString;
use std::ffi::CStr;
use std::sync::RwLock;
use futures::prelude::*;
use tokio::sync::oneshot;
use lazy_static::lazy_static;
use std::sync::Mutex;
use tokio::runtime::Runtime;
use std::{thread, time};
use std::slice;
use crc16::*;
use std::ffi;

use std::fs;
use std::fs::OpenOptions;
use std::io::prelude::*;

lazy_static! {
    static ref RUNTIME: Runtime = Runtime::new().unwrap();
    
    static ref ARRAY: Mutex<Vec<u8>> = Mutex::new(vec![]);
    static ref ARRAY2: Vec<u8> = vec![];
}

mod crypt_engines;
mod coins;
mod cli;
mod dl_eq;

use crate::{
  coins::{
    *,
    btc::{host::BtcHost, verifier::BtcVerifier},
    arrr::{client::ArrrClient, verifier::ArrrVerifier}
  },
  cli::{ScriptedCoin, UnscriptedCoin, Cli}
};

const MAGIC: &[u8]          = b"ASMR";
const MAGIC_RESPONSE: &[u8] = b"ConfirmASMR";
const MAX_ITEM_LENGTH: usize  = 512 * 1024; // 256 KB, but increase to 512kb for hex encoded string The largest transmitted data is the DL EQ Proof which is still less than this

static mut CMD_WRITE      : i8 = 0;
static mut CMD_READ       : i8 = 0;
static mut DATA_WRITE     : &'static mut [u8] = &mut [0; MAX_ITEM_LENGTH];
static mut DATA_READ      : &'static mut [u8] = &mut [0; MAX_ITEM_LENGTH];
static mut DATA_WRITE_LEN : i32 = 0;
static mut DATA_READ_LEN  : i32 = 0;

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
  
  //print!("session: {}:",s_key);
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
          //println!("len={}, crc={:02x?}",s_value.len(), crc);            
        }
        //else
        //{
        //  println!("{}",s_value);            
        //}
        return;
      }
    }
  }
  //println!("<Not in session>");
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



#[no_mangle]
pub unsafe extern "C"
fn asmr_spawn_host( ) -> i8 {
  
  RUNTIME.spawn( async move {
    let result = asmr_host_thread().await;
    });

  return 0;
}


async fn asmr_host_thread( ) -> i8 
{
  println!("asmr_host_thread() starting");
  let mut i_state : u16 = 0;
  
  let mut vec_rx_data : Vec<u8> = vec![0; MAX_ITEM_LENGTH];
  let mut i_rx_length : i32;

  let mut verifier_keys = Vec::new();
  let mut verifier_keys_crc : u16 = 0;  
  let mut client_keys;
  let mut address = String::new();
  
  let mut i_verify_lock_counter : u16 =0;
  
  unsafe {
    CMD_WRITE=-1;
    CMD_READ =-1;
  }

  //let cli::UnscriptedCoin
  //pub enum UnscriptedCoin {
  //  #[enumeration(alias = "arrr")]
  //  PirateChain,}
  let opts_pair_unscripted = UnscriptedCoin::PirateChain;

  let scripted_config="../config/bitcoin.json".to_string();
  let mut host = BtcHost::new(&scripted_config).unwrap();
  
  let unscripted_config="../config/piratechain.json".to_string();
  let mut verifier : AnyUnscriptedVerifier; // = ArrrVerifier::new(&unscripted_config);
  
  let mut unscripted_verifier: AnyUnscriptedVerifier = match opts_pair_unscripted {
      UnscriptedCoin::PirateChain => ArrrVerifier::new(&unscripted_config).await.map(Into::into)
  }.expect("Failed to create unscripted verifier");
 
  //println!("start loop. state={}",i_state);
  
  let mut _b_state_enter=true;
  let mut str_hex_verifier_keys = String::new();
  
  loop 
  {
    if i_state == 0      //Init
    {
      println!("#0 Init session()");
      println!("---------------------------------------------------");
      host.init_session();
      //Generate keys || restore keys from session
      verifier_keys = host.generate_keys(&mut unscripted_verifier).await;
      verifier_keys_crc = State::<ARC>::calculate( &verifier_keys[..]);
      str_hex_verifier_keys = hex::encode(verifier_keys.clone());
  
      //println!("verifier_keys: lenth={} crc={:02x?}", verifier_keys.len(), verifier_keys_crc);
      
      
      let mut str_value = String::new();
      read_session_key(1, "state_client_keys_exchanged", &mut str_value);   
      
      let mut str_hex_client_keys = String::new();      
      read_session_key(1, "client_keys",&mut str_hex_client_keys);
      
      if str_value.len()==0             || //Keys not yet exchanged
         str_value != "1"               || //Keys not yet exchanged
         str_hex_client_keys.len() == 0    //Error: state_client_keys_exchanged set, but client keys not
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
    else if i_state == 1 //Exchange keys
    {
      if _b_state_enter==true
      {
        println!("#1 Exchange keys");
        println!("---------------------------------------------------");
        _b_state_enter=false;
      }

      //println!("#1 Copy data, wait for it to get processed");
      unsafe 
      {
        DATA_READ_LEN = str_hex_verifier_keys.len() as i32;    
        for x in 0..DATA_READ_LEN
        {
          DATA_READ[x as usize] = str_hex_verifier_keys.as_bytes()[x as usize] as u8;
        }
        CMD_READ=1;
      
        loop
        {
          if CMD_READ==-1
          {
            break;
          }
          tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
        }
        //println!("#1 Data picked up by host main app. Waiting for the data to get processed by the client");
      
        //Wait for client to respond:
        loop
        {
          if CMD_WRITE != -1
          {
            break;
          }
          tokio::time::delay_for(std::time::Duration::from_millis(10)).await;  
        }        
        //println!("#1 Received response from the client.");

        if CMD_WRITE != 1
        {
          println!("#1 Expected incoming data to be for state=1. Received state: {}",CMD_WRITE);
          return -1;
        }
        
        
        vec_rx_data.clear();
        vec_rx_data.resize (DATA_WRITE_LEN as usize ,0);      
        for x in 0..DATA_WRITE_LEN
        { 
          vec_rx_data[x as usize] = DATA_WRITE[x as usize];
        }
        i_rx_length = DATA_WRITE_LEN;
        CMD_WRITE=-1;
        
      
        //println!("#1 Read: Client keys");          
        client_keys = hex::decode (vec_rx_data.clone()).unwrap();
        let str_hex_client_keys = hex::encode( client_keys.clone() );
        write_session_key(1, "client_keys", &str_hex_client_keys);

        let client_keys_crc = State::<ARC>::calculate( &client_keys[..]);
        //println!("#1 Client_keys: len={} CRC:{:02x?}",client_keys.len(),client_keys_crc);
        let _result = host.verify_keys(&client_keys, &mut unscripted_verifier);
        if !_result.is_ok()
        {
          println!("Couldn't verify client DlEq proof");
          return -1;
        }
        //println!("HOST: #1 DlEq proof verified");

        write_session_key(1, "state_client_keys_exchanged", "1");

        println!("HOST: State->3 : BTC account funded?");
        _b_state_enter=true;
        i_state=3;
      }
    }
    else if i_state == 2 //Exchange keys
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
        println!("HOST: #2 Send: Verify key checksums.");
        // host crc={:02x} client crc={:02x}",verifier_keys_crc, client_keys_crc);
      }
      
      let mut tx_data = vec![0u8; 4];
      let mut _tmp16 : u16 = 0;
      _tmp16 = verifier_keys_crc >> 8;      
      tx_data[0] = _tmp16 as u8;
      tx_data[1] = verifier_keys_crc as u8;
      
      _tmp16 = client_keys_crc >> 8;      
      tx_data[2] = _tmp16 as u8;
      tx_data[3] = client_keys_crc   as u8;


      //let _result = write(&mut stream, &cmd, &tx_data).await.context("Failed to verify host/client key checksums");
      unsafe 
      {
        let str_hex_crc = hex::encode(tx_data);
        DATA_READ_LEN = str_hex_crc.len() as i32;
        for x in 0..DATA_READ_LEN
        {
          DATA_READ[x as usize] = str_hex_crc.as_bytes()[x as usize] as u8;
        }
        CMD_READ=2; //2=Confirm Host/Client keys checksum
      
        loop
        {
          if CMD_READ==-1
          {
            break;
          }
          tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
        }
        //println!("#2 Data picked up by host main app.");
      
      
        //let (response_code, rx_data) = read(&mut stream).await;
        //Wait for client to respond:
        loop
        {
          if CMD_WRITE != -1
          {
            break;
          }
          tokio::time::delay_for(std::time::Duration::from_millis(10)).await;  
        }        
        //println!("#2 Received response from the client.");

        
        if CMD_WRITE != 2 //2=Confirm Host/Client keys checksum
        {
          println!("#2 Expected incoming data to be for state=2. Received state: {}",CMD_WRITE);
          return -1;
        }
        vec_rx_data.clear();
        vec_rx_data.resize (DATA_WRITE_LEN as usize ,0);      
        for x in 0..DATA_WRITE_LEN
        { 
          vec_rx_data[x as usize] = DATA_WRITE[x as usize];
        }
        i_rx_length = DATA_WRITE_LEN;
        CMD_WRITE=-1;        
      }
      
      let vec_data = hex::decode(vec_rx_data.clone()).unwrap();
      
      if vec_data[0] == 0      // Did not yet receive the host key 
      {
        println!("HOST: #2 Verify host/client key checksums: Client reported that it has not yet received the host key");
        return -1;
      }
      else if vec_data[0] == 1 // Received host key crc doesn't match our host key in the session
      {
        println!("HOST: #2 Verify host/client key checksums: Client reported that the host key checksum doesn't match its checksum");
        return -1;
      }
      else if vec_data[0] == 2 // Received client key crc doesn't match our client key 
      {
        println!("HOST: #2 Verify host/client key checksums: Client reported that the client key checksum doesn't match its checksum");
        return -1;
      }
      else if vec_data[0] == 3 // Success, CRCs match
      {
        println!("HOST: #2 Verify host/client key checksums: Success");
      }
      else                    // Unknown
      {
        println!("HOST: #2 Verify host/client key checksums: Result code unknown: {}",vec_rx_data[0]);
        return -1;
      }

      
      let result = host.verify_keys(&client_keys, &mut unscripted_verifier);
      if !result.is_ok()
      {
        println!("Couldn't verify client DlEq proof");
        return -1;
      }
      //println!("HOST: #2 DlEq proof verified");

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
        println!("HOST: #3 BTC funding");
                
        let mut s_value = String::new();
        read_session_key(1, "state_btc_funded",&mut s_value);
        if s_value.len() == 0 //Not funded
        {      
          println!("Send your BTC to the funding address. The swap transaction will proceed as soon as the funds are detected on the blockchain.");
          
          let str_response = format!("Fund BTC address {}", address);
          unsafe 
          {
            DATA_READ_LEN = str_response.len() as i32;    
            for x in 0..DATA_READ_LEN
            {
              DATA_READ[x as usize] = str_response.as_bytes()[x as usize] as u8;
            }
            CMD_READ=3;      
            loop
            {
              if CMD_READ==-1
              {
                break;
              }
              tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
            }
            //println!("#3 Data picked up by host main app.\n");
          }
        }
        else
        {
          //println!("HOST: #3 Account was already funded.");
          
          let str_response = format!("BTC address {} funded", address);          
          unsafe 
          {
            DATA_READ_LEN = str_response.len() as i32;    
            for x in 0..DATA_READ_LEN
            {
              DATA_READ[x as usize] = str_response.as_bytes()[x as usize] as u8;
            }
            CMD_READ=3;      
            loop
            {
              if CMD_READ==-1
              {
                break;
              }
              tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
            }
            //println!("#3 Data picked up by host main app.\n");
          }          
          
          
          println!("HOST: State->4 : Exchange signatures");
          _b_state_enter=true;
          i_state=4;
          continue;
        }
      }
      
      let b_value = host.get_if_funded( &address.clone() ).await;
      if b_value==true
      {
        //println!("HOST: #3 Detected BTC funding");
        
        let mut s_value = "1";
        write_session_key(1, "state_btc_funded",&mut s_value);
        
        //Generate and store the refund transaction
        let result=host.generate_funding_address_refund().await;
        if !result.is_ok()
        {
          println!("HOST: #3 Could't generate the unlock transaction");      
          return -1;
        }
          
        
        let str_response = format!("Detected transaction for address {}\nFollow processing of the transaction on the blockchain at:\nhttps://live.blockcypher.com/btc-testnet/address/{}", address, address);
        unsafe 
        {
          DATA_READ_LEN = str_response.len() as i32;    
          for x in 0..DATA_READ_LEN
          {
            DATA_READ[x as usize] = str_response.as_bytes()[x as usize] as u8;
          }
          CMD_READ=3;      
          loop
          {
            if CMD_READ==-1
            {
              break;
            }
            tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
          }
          //println!("#1 Data picked up by host main app.");
        }        

        
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
        println!("HOST: #4 Exchange signatures, require 1 BTC block confirmation to continue");
      }
      
      //Create signature | restore object data from session:
      let result = host.create_lock_and_prepare_refund().await;
      if !result.is_ok()
      {
        println!("Couldn't create the BTC lock");
        return -1;
      }
      let host_lock_and_refund_sig = result.unwrap();
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
        //println!("HOST: #4 Send: Lock & refund signature to client. crc={:02x}",host_lock_and_refund_sig_crc);

        //let _result = write(&mut stream, &cmd, &host_lock_and_refund_sig).await;
        unsafe 
        {
          let str_hex_host_lock_and_refund_sig = hex::encode( host_lock_and_refund_sig.clone() );
          DATA_READ_LEN = str_hex_host_lock_and_refund_sig.len() as i32;
          for x in 0..DATA_READ_LEN
          {
            DATA_READ[x as usize] = str_hex_host_lock_and_refund_sig.as_bytes()[x as usize] as u8;
          }
          CMD_READ=4; //4=Exchange signatures
      
          loop
          {
            if CMD_READ==-1
            {
              break;
            }
            tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
          }
          //println!("#4 Data picked up by host main app.");
       
          //println!("HOST: #4 Wait for response");
          loop
          {
            if CMD_WRITE != -1
            {
              break;
            }
            tokio::time::delay_for(std::time::Duration::from_millis(10)).await;              
          }
          //println!("HOST: #4 Received response");
          
          //let (response_code, rx_data) = read(&mut stream).await;
          if CMD_WRITE != 4 //2=Confirm Host/Client keys checksum
          {
            println!("#4 Expected incoming data to be for state=4. Received state: {}. Exit",CMD_WRITE);
            return -1;
          }
          vec_rx_data.clear();
          vec_rx_data.resize (DATA_WRITE_LEN as usize ,0);      
          for x in 0..DATA_WRITE_LEN
          { 
            vec_rx_data[x as usize] = DATA_WRITE[x as usize];
          }
          i_rx_length = DATA_WRITE_LEN;
          CMD_WRITE=-1;        
        }
        let vec_data = hex::decode(vec_rx_data.clone()).unwrap();
        
        client_refund_and_spend_sig = vec_data;
        //println!("HOST: #4 Received: client refund and spend sig");
        
        //Verify signatures:
        let result = host.verify_refund_and_spend(&client_refund_and_spend_sig);
        if !result.is_ok()
        {
          println!("HOST: #4 Refund and spend signature verification failed");
          return -1;
        }
        //println!("HOST: #4 Refund and spend signature verified");
        
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
        if str_hex_host_lock_and_refund_sig.len()    == 0 ||
           str_hex_client_refund_and_spend_sig.len() == 0
        {
          println!("HOST: #4 Session indicates signatures were exchanged, but the contents of the signatures are empty. Exit");
          return -1;
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
        println!("HOST: #5 Verify signature checksums: Session reported that the signatures was not exchanged. Exit");
        return -1;
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
        println!("HOST: #5 Verify signature checksums.");
        // host crc={:02x} client crc={:02x}",host_lock_and_refund_sig_crc, client_refund_and_spend_sig_crc);
      }
      
      let mut tx_data = vec![0u8; 4];
      let mut _tmp16 : u16 = 0;
      _tmp16 = host_lock_and_refund_sig_crc >> 8;      
      tx_data[0] = _tmp16 as u8;
      tx_data[1] = host_lock_and_refund_sig_crc as u8;
      
      _tmp16 = client_refund_and_spend_sig_crc >> 8;      
      tx_data[2] = _tmp16 as u8;
      tx_data[3] = client_refund_and_spend_sig_crc as u8;

      //let _result = write(&mut stream, &cmd, &tx_data).await.context("Failed to verify signature checksums");                    
      unsafe 
      {
        let str_hex_crc = hex::encode(tx_data);
        DATA_READ_LEN = str_hex_crc.len() as i32;
        for x in 0..DATA_READ_LEN
        {
          DATA_READ[x as usize] = str_hex_crc.as_bytes()[x as usize] as u8;
        }
        CMD_READ=5; //5=Verify signature checksums
      
        loop
        {
          if CMD_READ==-1
          {
            break;
          }
          tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
        }
        //println!("#5 Data picked up by host main app.");
      
      
        //println!("#5 Waiting for response from client.");
        //let (response_code, rx_data) = read(&mut stream).await;
        //Wait for client to respond:
        loop
        {
          if CMD_WRITE != -1
          {
            break;
          }
          tokio::time::delay_for(std::time::Duration::from_millis(10)).await;  
        }        
        //println!("#5 Received response from the client.");

        
        if CMD_WRITE != 5 //5=Confirm signature checksum
        {
          println!("#5 Expected incoming data to be for state=5. Received state: {}. Exit",CMD_WRITE);
          return -1;
        }
        vec_rx_data.clear();
        vec_rx_data.resize (DATA_WRITE_LEN as usize ,0);      
        for x in 0..DATA_WRITE_LEN
        { 
          vec_rx_data[x as usize] = DATA_WRITE[x as usize];
        }
        i_rx_length = DATA_WRITE_LEN;
        CMD_WRITE=-1;        
      }
      
      let vec_data = hex::decode(vec_rx_data.clone()).unwrap();

      if vec_data[0] == 0      // Did not yet receive the host signature
      {
        println!("HOST: #5 Verify signature checksums: Client reported that it has not yet received the host signature");
        return -1;
      }
      else if vec_data[0] == 1 // Received host signature mismatch
      {
        println!("HOST: #5 Verify signature checksums: Host signature mismatch");
        return -1;
      }
      else if vec_data[0] == 2 // Received client signature mismatch
      {
        println!("HOST: #5 Verify signature checksums: Client signature mismatch");
        return -1;
      }
      else if vec_data[0] == 3 // Success, CRCs match
      {
        println!("HOST: #5 Verify signature checksums: Success");          
      }
      else if vec_data[0] == 4 // Invalid data length
      {
        println!("HOST: #5 Verify signature checksums: Payload data invalid length");
        return -1;        
      }       
      else                    // Unknown
      {
        println!("HOST: #5 Verify signature checksums: Result code unknown: {}",vec_data[0]);
        return -1;
      }
      
      let result = host.verify_refund_and_spend(&client_refund_and_spend_sig);
      if !result.is_ok()
      {
        println!("HOST: #5 Refund and spend signature verification failed");
        return -1;
      }
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
        println!("HOST: #6 Lock BTC funds, require 1 BTC block confirmation to continue");        
        let result = host.publish_lock().await;
        if !result.is_ok()
        {         
          println!("Couldn't publish the lock transaction");
          return -1;
        }
        //FIXIT: Save engine.lock_script & engine.lock_script_bytes?
      }
      
      let mut str_value = String::new();
      read_session_key(1, "state_lock_transaction", &mut str_value);      
      if str_value != "1"
      {
        println!("HOST: #6 Could not publish the BTC funds to the lock transaction");
        return -1;  
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
        let result = getrandom::getrandom(&mut ca_encrypted_sign_r1);
        if !result.is_ok()
        {
          println!("getrandom() failed");
          continue;         
        }
        let result = getrandom::getrandom(&mut ca_encrypted_sign_r2);
        if !result.is_ok()
        {
          println!("getrandom() failed");
          continue;        
        }
        
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
      let result = host.prepare_buy_for_client(&ca_encrypted_sign_r1,&ca_encrypted_sign_r2).await;
      if !result.is_ok()
      {
        println!("Couldn't prepare the buy");
        return -1;
      }
      let client_buy_from_lock = result.unwrap();
      
      let client_buy_from_lock_crc = State::<ARC>::calculate( &client_buy_from_lock[..]);  
      //println!("HOST: #7 Client_buy_from_lock: len={}, CRC:{:02x?}", client_buy_from_lock.len(), client_buy_from_lock_crc);      
    
      let mut s_value = String::new();
      read_session_key(1, "state_client_buy-from-lock_exchanged", &mut s_value);
      if s_value != "1"
      {            
        //println!("HOST: #7 Send client buy-from-lock");
        //let _result = write(&mut stream, &cmd, &client_buy_from_lock).await;
        unsafe 
        {                                                 
          let str_hex_client_buy_from_lock = hex::encode( client_buy_from_lock.clone() );
          DATA_READ_LEN = str_hex_client_buy_from_lock.len() as i32;
          for x in 0..DATA_READ_LEN
          {
            DATA_READ[x as usize] = str_hex_client_buy_from_lock.as_bytes()[x as usize] as u8;
          }
          CMD_READ=7; //7=Client buy-from-lock transaction
      
          loop
          {
            if CMD_READ==-1
            {
              break;
            }
            tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
          }
          //println!("#7 Data picked up by host main app.");
       
          //println!("HOST: #7 Wait for response");
          loop
          {
            if CMD_WRITE != -1
            {
              break;
            }
            tokio::time::delay_for(std::time::Duration::from_millis(10)).await;              
          }
          //println!("HOST: #7 Received response");
          
          //let (response_code, rx_data) = read(&mut stream).await;
          if CMD_WRITE != 7
          {
            println!("#7 Expected incoming data to be for state=7. Received state: {}. Exit",CMD_WRITE);
            return -1;
          }
          vec_rx_data.clear();
          vec_rx_data.resize (DATA_WRITE_LEN as usize ,0);      
          for x in 0..DATA_WRITE_LEN
          { 
            vec_rx_data[x as usize] = DATA_WRITE[x as usize];
          }
          i_rx_length = DATA_WRITE_LEN;
          CMD_WRITE=-1;        
        }
        let vec_data = hex::decode(vec_rx_data.clone()).unwrap();        
        
        print!("HOST: #7 Read: Client respose:");
        if vec_data[0] != 1
        {
          println!("State error: Client could not verify the buy-from-lock transaction");
          return -1;
        }
        //println!(" buy-from-lock confirmed");
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
        //Note: No data to send. Pad data with one [u8]
        let mut tx_data = vec![0u8; 1];
        tx_data[0]=0;
        //let _result = write(&mut stream, &cmd, &tx_data).await.context("Failed to write 'BTC funds locked?'");
        //println!("wrote cmd 8, wait for response");
        
                
        unsafe 
        {                                                 
          let str_hex_tx_data = hex::encode( tx_data.clone() );
          DATA_READ_LEN = str_hex_tx_data.len() as i32;
          for x in 0..DATA_READ_LEN
          {
            DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize] as u8;
          }
          CMD_READ=8; //8=Client: See locked BTC funds?
      
          loop
          {
            if CMD_READ==-1
            {
              break;
            }
            tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
          }
          //println!("#8 Data picked up by host main app.");
       
          //println!("HOST: #8 Wait for response");
          loop
          {
            if CMD_WRITE != -1
            {
              break;
            }
            tokio::time::delay_for(std::time::Duration::from_millis(10)).await;              
          }
          //println!("HOST: #8 Received response");
          
          //let (response_code, rx_data) = read(&mut stream).await;
          if CMD_WRITE != 8
          {
            println!("#8 Expected incoming data to be for state=8. Received state: {}. Exit",CMD_WRITE);
            return -1;
          }
          vec_rx_data.clear();
          vec_rx_data.resize (DATA_WRITE_LEN as usize ,0);      
          for x in 0..DATA_WRITE_LEN
          { 
            vec_rx_data[x as usize] = DATA_WRITE[x as usize];
          }
          i_rx_length = DATA_WRITE_LEN;
          CMD_WRITE=-1;        
        }
        let vec_data = hex::decode(vec_rx_data.clone()).unwrap();                
        
                
        //let (response_code, rx_data) = read(&mut stream).await;                
        i_verify_lock_counter+=1; //20 second intervals
        //println!("HOST: #8 Read: Client respose");
        let response = vec_data.clone();
        if response.len()<=0  ||
           response[0] == 0       //BTC locked funds transaction not detected or # of confirmations < 1
        {
          println!("Verify if the BTC funds are locked. Require 1 confirmation.");
          
          //Don't use the timeout, since the blockchains sometimes take longer to process the transactions...
          //if i_verify_lock_counter>=12 //4:00
          //{
          //  println!("Timeout waiting for client to verify the locked BTC funds");
          //  return -1;
          //}
        }
        else if response[0]==1   //Client verified BTC funds is locked
        {
          //println!("Client verified BTC funds are locked. Waiting for client to verify that Arrr is funded");
          i_verify_lock_counter=0;
          
          write_session_key(1, "state_client_verified_btc_funds_locked", "1");

          println!("HOST: State->9 : Client: Arrr funds locked?");
          _b_state_enter=true;
          i_state=9;                          
        }
        else
        {
          println!("Invalid response from client: {}",response[1]);
          return -1;
        }
      }
      else
      {
        //Send cmd=8 so that the client can restore its session variables 
        //Note: No data to send. Pad data with one [u8]
        let mut tx_data = vec![0u8; 1];
        tx_data[0]=0;
        //let _result = write(&mut stream, &cmd, &tx_data).await.context("Failed to write 'BTC funds locked?'");
        //println!("wrote cmd 8, wait for response");
        
        
        unsafe 
        {                                                 
          let str_hex_tx_data = hex::encode( tx_data.clone() );
          DATA_READ_LEN = str_hex_tx_data.len() as i32;
          for x in 0..DATA_READ_LEN
          {
            DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize] as u8;
          }
          CMD_READ=8; //8=Client: See locked BTC funds?
      
          loop
          {
            if CMD_READ==-1
            {
              break;
            }
            tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
          }
          //println!("#8 Data picked up by host main app.");
       
          //println!("HOST: #8 Wait for response");
          loop
          {
            if CMD_WRITE != -1
            {
              break;
            }
            tokio::time::delay_for(std::time::Duration::from_millis(10)).await;              
          }
          //println!("HOST: #8 Received response");
          
          //let (response_code, rx_data) = read(&mut stream).await;
          if CMD_WRITE != 8
          {
            println!("#8 Expected incoming data to be for state=8. Received state: {}. Exit",CMD_WRITE);
            return -1;
          }
          vec_rx_data.clear();
          vec_rx_data.resize (DATA_WRITE_LEN as usize ,0);      
          for x in 0..DATA_WRITE_LEN
          { 
            vec_rx_data[x as usize] = DATA_WRITE[x as usize];
          }
          i_rx_length = DATA_WRITE_LEN;
          CMD_WRITE=-1;        
        }
        let vec_data = hex::decode(vec_rx_data.clone()).unwrap();                
        
        
        //let (response_code, rx_data) = read(&mut stream).await;
        if vec_data.len()>0 &&
           vec_data[0]==1      //Client verified BTC funds is locked
        {
          println!("HOST: State->9 : Client: Arrr funds locked?");
          _b_state_enter=true;
          i_state=9;
        }
        else
        {
          println!("Invalid response from client");
          return -1;          
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
        //let _result = write(&mut stream, &cmd, &cmd).await.context("Failed to write 'ARRR funds locked?'");
        
        
        let mut tx_data = vec![0u8; 1];
        tx_data[0]=0;
        //Note: No data to send. Pad data with one [u8]
        unsafe 
        {                                                 
          let str_hex_tx_data = hex::encode( tx_data.clone() );
          DATA_READ_LEN = str_hex_tx_data.len() as i32;
          for x in 0..DATA_READ_LEN
          {
            DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize] as u8;
          }
          CMD_READ=9; //9=Client: Arrr funds locked?
      
          loop
          {
            if CMD_READ==-1
            {
              break;
            }
            tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
          }
          //println!("#9 Data picked up by host main app.");
       
          //println!("HOST: #9 Wait for response");
          loop
          {
            if CMD_WRITE != -1
            {
              break;
            }
            tokio::time::delay_for(std::time::Duration::from_millis(10)).await;              
          }
          //println!("HOST: #9 Received response");
          
          //let (response_code, rx_data) = read(&mut stream).await;
          if CMD_WRITE != 9
          {
            println!("#9 Expected incoming data to be for state=9. Received state: {}. Exit",CMD_WRITE);
            return -1;
          }
          vec_rx_data.clear();
          vec_rx_data.resize (DATA_WRITE_LEN as usize ,0);      
          for x in 0..DATA_WRITE_LEN
          { 
            vec_rx_data[x as usize] = DATA_WRITE[x as usize];
          }
          i_rx_length = DATA_WRITE_LEN;
          CMD_WRITE=-1;        
        }
        let vec_data = hex::decode(vec_rx_data.clone()).unwrap();                        
        
        //let (response_code, rx_data) = read(&mut stream).await;
        i_verify_lock_counter+=1; //20 second intervals
        //println!("HOST: #9 Read: Client respose");
        let response = vec_data.clone();
        if response.len()<=0  ||
           response[0] == 0       //Arrr locked funds transaction not detected or # of confirmations < 1
        {
          println!("Verify if the ARRRR funds are locked. Need 8 confirmations");
          tokio::time::delay_for(std::time::Duration::from_secs(10)).await;
          
          //Don't use the timeout, since the blockchains sometimes take longer to process the transactions...
          //if i_verify_lock_counter>=30 //5:00
          //{
          //  println!("Timeout waiting for client to verify the locked ARRR funds");
          //  return -1;
          //}
        }
        else if response[0]==1   //Client verified ARRR funds are locked
        {
          //println!("Client verified ARRR funds are locked");
          i_verify_lock_counter=0;
          
          write_session_key(1, "state_client_verified_arrr_funds_locked", "1");
          println!("HOST: State->10 : Verify Arrr funds locked");
          _b_state_enter=true;
          i_state=10;
        }
        else
        {
          println!("Invalid response from client: {}",response[1]);
          return -1;
        }
      }
      else
      {
        println!("HOST: State->10 : Verify Arrr funds locked?");
        _b_state_enter=true;
        i_state=10;
      }
    }
    else if i_state==10 //Host: ARRR funds locked?
    {
      if _b_state_enter==true
      {
        println!("------------------------------------------------------------------------");
        println!("HOST : #10 Arrr funds deposited?");
        _b_state_enter=false;
      }
      
      //Have to run each time to have engine.host&engine.witness populated.
      //Alternatively, store vars in session and restore for future runs
      let result_wrapped = unscripted_verifier.verify_and_wait_for_send(false).await;
      if !result_wrapped.is_ok()
      {
        println!("Couldn't verify and wait for the unscripted send");
        return -1;
      }
      let result = result_wrapped.unwrap();
      //println!("result: {:02x?}",result);      
      if result==0
      {
        println!("HOST: ARRR funds not yet detected");
      }
      else
      {
        println!("HOST: ARRR funds detected");
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
        
        //println!("HOST: #11 write secret:{:02x?} crc={:02x?}",host.swap_secret(), secret_crc);  
        //cmd[0]=11;
        //write( &mut stream, &cmd, &host.swap_secret() ).await?;
        unsafe 
        {                                                 
          let str_hex_tx_data = hex::encode( host.swap_secret().clone() );
          DATA_READ_LEN = str_hex_tx_data.len() as i32;
          for x in 0..DATA_READ_LEN
          {
            DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize] as u8;
          }
          CMD_READ=11; //11=Share secret
      
          loop
          {
            if CMD_READ==-1
            {
              break;
            }
            tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
          }
          //println!("HOST: #11 Data picked up by host main app.");
          
          //println!("HOST: #11 Wait for response");
          loop
          {
            if CMD_WRITE != -1
            {
              break;
            }
            tokio::time::delay_for(std::time::Duration::from_millis(10)).await;              
          }
          //println!("HOST: #11 Received response");
          
          //let (response_code, rx_data) = read(&mut stream).await;
          if CMD_WRITE != 11
          {
            println!("HOST: #11 Expected incoming data to be for state=11. Received state: {}. Exit",CMD_WRITE);
            return -1;
          }
          vec_rx_data.clear();
          vec_rx_data.resize (DATA_WRITE_LEN as usize ,0);      
          for x in 0..DATA_WRITE_LEN
          { 
            vec_rx_data[x as usize] = DATA_WRITE[x as usize];
          }
          i_rx_length = DATA_WRITE_LEN;
          CMD_WRITE=-1;        
        }
        let vec_data = hex::decode(vec_rx_data.clone()).unwrap();         
        
        
        //let (response_code, rx_data) = read(&mut stream).await;                
        print!("HOST: #11 Read: Client respose:");
        let response = vec_data.clone();
        if response.len()<=0
        {
          println!("HOST: State error: Client did not receive the secret");
          return -1;
        }        
        if response[0]==1
        {
          //println!("Secret received, BTC funds claimed");
          write_session_key(1, "state_secret_shared", "1");
        }
        else if response[0]==2
        {
          println!("HOST: Secret received, but could not claim the BTC funds");
          return -1;
        }
        else
        {
          println!("HOST: Unknown resonse value: {:02x?}",response);
          return -1;
        }
      }
      else
      {
        //println!("Secret already shared");
        println!("HOST: State->12 : BTC redeemed?"); 
        _b_state_enter=true;
        i_state=12;              
      }
    }
    else if i_state==12
    {
      println!("------------------------------------------------------------------------");
      println!("HOST: #12 Redeem Arrr");
      let mut s_value=String::new();
      read_session_key(1,"state_arrr_redeemed", &mut s_value);
      if s_value.len() == 0
      {
        //println!("Redeem Arrr");
        let result = unscripted_verifier.finish(&host).await;
        if !result.is_ok()
        {
          println!("HOST: Couldn't finish buying the Arrr coins");
          return -1;
        }
        
        write_session_key(1,"state_arrr_redeemed","1");        
      }
      unsafe
      { 
      
        let mut tx_data = vec![0u8; 1];
        tx_data[0]=0; //Note: No data to send. Pad data with one [u8]
        let str_hex_tx_data = hex::encode( tx_data.clone() );
        DATA_READ_LEN = str_hex_tx_data.len() as i32;
        for x in 0..DATA_READ_LEN
        {
          DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize] as u8;
        }
        CMD_READ=13; //13 -- Transaction completed
      }
      break;
    }    
    tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
  }
      
      
  return 0;
}

#[no_mangle]
pub unsafe extern "C"
fn asmr_read (pc_cmd: *mut i8, pca_data: *mut c_void, pi_length: *mut i32) -> i8 
{
  if CMD_READ==-1 
  {
    //println!("asmr_read(-1)");
    return 0;
  }
 
  ptr::copy_nonoverlapping(DATA_READ.as_ptr(), pca_data as *mut u8, DATA_READ_LEN as usize);
  *pc_cmd    = CMD_READ;
  *pi_length = DATA_READ_LEN;
  
  //Indicate that the command was read by the external code:
  CMD_READ=-1;
  
  return 1;
}

#[no_mangle]
pub unsafe extern "C"
fn asmr_write (pc_cmd: *mut i8, pca_data: *mut c_void, pi_length: *mut i32) -> i8 
{
  if CMD_WRITE!=-1 
  {
    //println!("asmr_write() Previous command not yet processed");
    if CMD_WRITE==*pc_cmd
    {
      println!("asmr_write() Same command pending -- Wait for library to pick it up");
      return 1;
    }
    return 0;
  }

  unsafe
  {
    let cs_data = CStr::from_ptr( pca_data as *mut i8 );
    let ca_data = cs_data.to_bytes();
    //println!("asmr_write() cmd:{}, ca_data len={}, pi_length={}", *pc_cmd, ca_data.len(), *pi_length);
    for x in 0..*pi_length
    {
      DATA_WRITE[x as usize] = ca_data[x as usize] as u8;
    }
    DATA_WRITE_LEN = *pi_length;
    CMD_WRITE = *pc_cmd;
  }
  return 1;
}




#[no_mangle]
pub unsafe extern "C" 
fn asmr_spawn_client( ) -> i8 
{  
  RUNTIME.spawn( async move 
  {
    let result = asmr_client_thread().await;
  });

  return 0;
}

async fn asmr_client_thread( ) -> i8 {
  println!("asmr_client_thread() started");    
  let mut c_state : i8 = 0;
  let mut vec_rx_data : Vec<u8> = vec![0; MAX_ITEM_LENGTH];
  let mut i_rx_length : i32;
  
  unsafe {
    CMD_WRITE=-1;
    CMD_READ =-1;
  }

  let opts_pair_scripted   = ScriptedCoin::Bitcoin;
  let opts_pair_unscripted = UnscriptedCoin::PirateChain;

  let scripted_config="../config/bitcoin.json".to_string();
  let unscripted_config="../config/piratechain.json".to_string();


  let mut unscripted_client: AnyUnscriptedClient = match opts_pair_unscripted {
      UnscriptedCoin::PirateChain => ArrrClient::new(&unscripted_config).await.map(Into::into),
  }.expect("Failed to create unscripted client");
  let mut scripted_verifier: AnyScriptedVerifier = match opts_pair_scripted {
      ScriptedCoin::Bitcoin => BtcVerifier::new(&scripted_config).map(Into::into),
  }.expect("Failed to create scripted verifier");

  
  //println!("CLIENT enter");
  //println!("-----------------------------------------------------------------------------------------------");  
 
  //println!("Library: #0 Generate|restore keys()");
  // Generate keys | Restore keys from session
  let client_keys = unscripted_client.generate_keys( &mut scripted_verifier ).await;
  let client_keys_crc = State::<ARC>::calculate( &client_keys[..]);
  //println!("Library: #0 client_keys len={}, CRC={:02x?}",client_keys.len(), client_keys_crc);  

 
  loop 
  {
    unsafe
    {
      if (CMD_WRITE == -1)
      { 
        tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
        continue;
      }
      
      c_state = CMD_WRITE;
      vec_rx_data.clear();
      vec_rx_data.resize (DATA_WRITE_LEN as usize ,0);
        
      for x in 0..DATA_WRITE_LEN
      { 
        //ca_rx_data[x] = DATA_WRITE[x];
        vec_rx_data[x as usize] = DATA_WRITE[x as usize];
      }
      //let ca_rx_data : [i8; DATA_WRITE_LEN];
      i_rx_length = DATA_WRITE_LEN;
      CMD_WRITE=-1;      
    }
    
    
    if c_state==1 //1=Exchange Host/Client keys.  Input data=host_keys, Response data=client_keys
    {
      println!("Library #1 Exchange keys");
      let host_keys = hex::decode (vec_rx_data.clone()).unwrap();
   
      //host_keys
      let str_hex_host_keys = hex::encode( host_keys.clone() );      
      let host_keys_crc = State::<ARC>::calculate( &host_keys[..]);
      //println!("Library: #1 Host_keys: len={} CRC:{:02x?}",host_keys.len(),host_keys_crc);
      
      let result = unscripted_client.verify_keys(&host_keys, &mut scripted_verifier);
      if !result.is_ok()
      {
        println!("Library #1 Couldn't verify host DlEq proof");
        return -1;
      }      
      //println!("Library: #1 Host keys verified\n");
      let client_keys_crc = State::<ARC>::calculate( &client_keys[..]);
      let str_hex_client_keys = hex::encode( client_keys.clone() );
      //println!("library: #1 Client_keys: len={} CRC:{:02x?}",client_keys.len(), client_keys_crc);
      //println!("Library: #1 Transmit client_keys");      
      unsafe {
        DATA_READ_LEN = str_hex_client_keys.len() as i32;
        for x in 0..DATA_READ_LEN
        { 
          DATA_READ[x as usize] = str_hex_client_keys.as_bytes()[x as usize];
        }
        CMD_READ = 1;      
      }
      
      write_session_key(0, "state_host_keys_exchanged", "1");      
      write_session_key(0, "host_keys",   &str_hex_host_keys);
      write_session_key(0, "client_keys", &str_hex_client_keys);       
      
      c_state=-1;  
    }
 
 
    else if c_state==2 //2=Confirm Host/Client keys checksum. Input data=[host_key_crc][client_key_crc], 
                       //Response data=0 : Did not yet receive the host key 
                       //             =1 : Received host key crc doesn't match our host key in the session
                       //             =2 : Received client key crc doesn't match our client key 
                       //             =3 : Success, CRCs match
                       //             =4 : Key verification failed
                       //             =5 : Input data invalid length
    {
      println!("Library #2 Verify keys");
      
      if i_rx_length!=8
      {
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 5; //Input data invalid length
        //let _result = write(&mut stream, &cmd, &tx_data).await;  
        let str_hex_tx_data = hex::encode(tx_data);
        unsafe {
          DATA_READ_LEN = str_hex_tx_data.len() as i32;
          for x in 0..DATA_READ_LEN
          { 
            DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
          }
          CMD_READ = 2;      
        }        
        
        println!("Host command=2: Input data invalid length. Expected 8 bytes, got {}",i_rx_length);        
        continue;
      }
      
      let vec_data = hex::decode(vec_rx_data.clone()).unwrap();
      //println!("Library #2 Received {:02x?}",vec_data);
      
      
      //host_keys
      let mut str_host_keys_exchanged = String::new();
      let mut str_hex_host_keys       = String::new();
      read_session_key(0, "state_host_keys_exchanged", &mut str_host_keys_exchanged);
      read_session_key(0, "host_keys",                 &mut str_hex_host_keys);
      
      if str_host_keys_exchanged != "1"
      {        
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 0; //Did not yet receive the host key
        //let _result = write(&mut stream, &cmd, &tx_data).await;        
        let str_hex_tx_data = hex::encode(tx_data);
        unsafe {
          DATA_READ_LEN = str_hex_tx_data.len() as i32;
          for x in 0..DATA_READ_LEN
          { 
            DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
          }
          CMD_READ = 2;      
        }
        
        println!("Host command=2: confirmation of host/client keys. Client doesn't have the host key in the session");
        continue;
      }
      
      let host_keys     = hex::decode( str_hex_host_keys ).unwrap();
      let host_keys_crc = State::<ARC>::calculate( &host_keys.clone()[..]);
      //println!("Library: #2 Session host_keys: len={} CRC:{:02x?}",host_keys.len(),host_keys_crc);

      let reconstructed_host_crc = ((vec_data[0] as u16) << 8) | vec_data[1] as u16;
      //println!("Library: #2 Received host_keys: CRC:{:02x?}", reconstructed_host_crc);
      
      if host_keys_crc != reconstructed_host_crc
      {
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 1; //host keys doesn't match
        //let _result = write(&mut stream, &cmd, &tx_data).await;  
        let str_hex_tx_data = hex::encode(tx_data);
        unsafe {
          DATA_READ_LEN = str_hex_tx_data.len() as i32;
          for x in 0..DATA_READ_LEN
          { 
            DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
          }
          CMD_READ = 2;      
        }        
        
        println!("Host command=2: confirmation of host/client keys. CRC of session host_key doesn't match the checksum from the host");
        continue;
      }
      
      //println!("Library: #2 Session client_keys:  CRC:{:02x?}", client_keys_crc);
      let reconstructed_client_crc = ((vec_data[2] as u16) << 8) | vec_data[3] as u16;
      //println!("Library: #2 Received client_keys: CRC:{:02x?}", reconstructed_client_crc);
      
      if client_keys_crc != reconstructed_client_crc
      {
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 2; //client keys doesn't match
        //let _result = write(&mut stream, &cmd, &tx_data).await;  
        let str_hex_tx_data = hex::encode(tx_data);
        unsafe {
          DATA_READ_LEN = str_hex_tx_data.len() as i32;
          for x in 0..DATA_READ_LEN
          { 
            DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
          }
          CMD_READ = 2;      
        }        
        println!("Host command=2: confirmation of host/client keys. CRC of session client_key doesn't match the checksum from the host");        
        continue;
      }
            
      let mut tx_data = vec![0u8; 1];
      let result = unscripted_client.verify_keys(&host_keys, &mut scripted_verifier);
      if result.is_ok()
      {
        //println!("Library: #2 Host keys verified. Transmit result.");
        tx_data[0] = 3; //CRCs match
      }
      else
      {
        println!("Library: #2 Key verification failed");
        tx_data[0] = 4; //Could not verify the keys
      }
      
      //let _result = write(&mut stream, &cmd, &tx_data).await; 
      let str_hex_tx_data = hex::encode(tx_data);
      unsafe {
        DATA_READ_LEN = str_hex_tx_data.len() as i32;
        for x in 0..DATA_READ_LEN
        { 
          DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
        }
        CMD_READ = 2;      
      }      
      
      println!("Library: #2 Waiting for host to confirm funding of the BTC account");
      
      c_state=-1;
    }   
    else if c_state==4 //4=Exchange Host/Client signatures.  Input data=host_signature, Response data=client_signature
    {      
      //host_lock_and_refund_sig
      //let host_lock_and_refund_sig = rx_data;
      let host_lock_and_refund_sig     = hex::decode(vec_rx_data.clone()).unwrap();
      let host_lock_and_refund_sig_crc = State::<ARC>::calculate( &host_lock_and_refund_sig.clone()[..]);
      println!("Library: #4 Received host lock_and_refund_sig");
      //: len={} CRC:{:02x?}",host_lock_and_refund_sig.len(),host_lock_and_refund_sig_crc);

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
        let result = getrandom::getrandom(&mut ca_encrypted_sign_r1);
        if !result.is_ok()
        {
          println!("getrandom() failed");
          continue;
        }
        let result = getrandom::getrandom(&mut ca_encrypted_sign_r2);
        if !result.is_ok()
        {
          println!("getrandom() failed");
          continue;
        }        
        
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
      let result = scripted_verifier.complete_refund_and_prepare_spend(
                                        &host_lock_and_refund_sig,
                                        &ca_encrypted_sign_r1, 
                                        &ca_encrypted_sign_r2
                                        ).await;
      if !result.is_ok()
      {
        println!("Couldn't complete the refund transaction");
        continue;
      }
      let client_refund_and_spend_sig = result.unwrap();
      let client_refund_and_spend_sig_crc = State::<ARC>::calculate( &client_refund_and_spend_sig.clone()[..]);
      //println!("Library: #4 Client refund_and_spend_signature: len={}, crc={:02x?}\n",client_refund_and_spend_sig.len(), client_refund_and_spend_sig_crc );
      
      //println!("Library: Transmit client refund_and_spend_signature");
      //write(&mut stream, &cmd, &client_refund_and_spend_sig).await?; 
      let str_hex_tx_data = hex::encode( client_refund_and_spend_sig.clone() );
      unsafe {
        DATA_READ_LEN = str_hex_tx_data.len() as i32;
        for x in 0..DATA_READ_LEN
        { 
          DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
        }
        CMD_READ = c_state;      
      }      
      
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
      c_state=-1;
    }     
    else if c_state==5 //5=Confirm Host/Client signature checksum. Input data=[host_signature_crc][client_signature_crc], 
                       //Response data=0 : Did not yet receive the host signature
                       //             =1 : Received host signature crc doesn't match our value in the session
                       //             =2 : Received client signature crc doesn't match our value in the session
                       //             =3 : Success, CRCs match
    {
      println!("Library #5 Verify signatures");
      
      if i_rx_length!=8
      {
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 4; //Input data invalid length
        //let _result = write(&mut stream, &cmd, &tx_data).await;  
        let str_hex_tx_data = hex::encode(tx_data);
        unsafe {
          DATA_READ_LEN = str_hex_tx_data.len() as i32;
          for x in 0..DATA_READ_LEN
          { 
            DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
          }
          CMD_READ = 5;      
        }        
        
        println!("Host command=5: Input data invalid length. Expected 8 bytes, got {}",i_rx_length);        
        continue;
      }
      
      let vec_data = hex::decode(vec_rx_data.clone()).unwrap();
      //println!("Library #5 Received {:02x?}",vec_data);    
    
    
      //host_signature
      let mut str_signatures_exchanged = String::new();
      let mut str_hex_host_lock_and_refund_sig = String::new();
      let mut str_hex_client_refund_and_spend_sig = String::new();
      read_session_key(0, "state_signatures_exchanged", &mut str_signatures_exchanged);
      read_session_key(0, "host_lock_and_refund_sig",   &mut str_hex_host_lock_and_refund_sig);
      read_session_key(0, "client_refund_and_spend_sig",&mut str_hex_client_refund_and_spend_sig);            
      
      if str_signatures_exchanged != "1"
      {
        println!("Library: #5: Confirmation of host/client signatures. Client doesn't have the host_lock_and_refund_sig in the session");
        
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 0; //Doesn't have the host/client signatures
        //let _result = write(&mut stream, &cmd, &tx_data).await;         
        let str_hex_tx_data = hex::encode(tx_data);
        unsafe {
          DATA_READ_LEN = str_hex_tx_data.len() as i32;
          for x in 0..DATA_READ_LEN
          { 
            DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
          }
          CMD_READ = 5;      
        }
      }
      else
      {
        let host_lock_and_refund_sig     = hex::decode( str_hex_host_lock_and_refund_sig ).unwrap();
        let host_lock_and_refund_sig_crc = State::<ARC>::calculate( &host_lock_and_refund_sig.clone()[..]);
        //println!("Library: #5 Session host_keys: len={} CRC:{:02x?}",host_lock_and_refund_sig.len(),host_lock_and_refund_sig_crc);

        let reconstructed_host_lock_and_refund_sig_crc = ((vec_data[0] as u16) << 8) | vec_data[1] as u16;
        //println!("Library: #5 Received host signature CRC:{:02x?}", reconstructed_host_lock_and_refund_sig_crc);
        
        if host_lock_and_refund_sig_crc != reconstructed_host_lock_and_refund_sig_crc
        {
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 1; //Received host signature crc doesn't match our value in the session
          //let _result = write(&mut stream, &cmd, &tx_data).await;  
          let str_hex_tx_data = hex::encode(tx_data);
          unsafe {
            DATA_READ_LEN = str_hex_tx_data.len() as i32;
            for x in 0..DATA_READ_LEN
            { 
              DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
            }
            CMD_READ = 5;      
          }          
          println!("Library: #5: Confirmation of host/client signatures. CRC of host lock_and_refund_sig mismatch");
          continue
        } 

        let reconstructed_client_refund_and_spend_sig_crc = ((vec_data[2] as u16) << 8) | vec_data[3] as u16;
        //println!("Library: #5 Received client signature CRC:{:02x?}", reconstructed_client_refund_and_spend_sig_crc);


        //Compare recalulcated signature to the stored signature:
        let decoded = hex::decode(str_hex_client_refund_and_spend_sig).unwrap();
        let crc     = State::<ARC>::calculate( &decoded.clone()[..]);
        if crc != reconstructed_client_refund_and_spend_sig_crc
        {          
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 2; //Received client signature crc doesn't match our value in the session
          let str_hex_tx_data = hex::encode(tx_data);          
          unsafe {
            DATA_READ_LEN = str_hex_tx_data.len() as i32;
            for x in 0..DATA_READ_LEN
            { 
              DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
            }
            CMD_READ = 5;      
          }
          println!("CLIENT #5 stored and recalculated client CRCs doesn't match");  
          continue;
        }
        //println!("CLIENT #5 stored and recalcualted client CRCs match");
        
        let mut ca_encrypted_sign_r1 : [u8;32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let mut str_hex_encrypted_sign_r1= String::new();
        let mut ca_encrypted_sign_r2 : [u8;32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let mut str_hex_encrypted_sign_r2= String::new();
        
        read_session_key(0, "encrypted_sign_r1", &mut str_hex_encrypted_sign_r1);
        read_session_key(0, "encrypted_sign_r2", &mut str_hex_encrypted_sign_r2);
        if str_hex_encrypted_sign_r1.len()==0 ||
           str_hex_encrypted_sign_r2.len()==0
        {
          let result = getrandom::getrandom(&mut ca_encrypted_sign_r1);
          if !result.is_ok()
          {
            println!("getrandom() failed");
            continue;  
          }
          let result = getrandom::getrandom(&mut ca_encrypted_sign_r2);
          if !result.is_ok()
          {
            println!("getrandom() failed");
            continue;
          }
                  
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
        let result = scripted_verifier.complete_refund_and_prepare_spend(
                                          &host_lock_and_refund_sig,
                                          &ca_encrypted_sign_r1,
                                          &ca_encrypted_sign_r2
                                          ).await;                                          
        if !result.is_ok() 
        {                                         
          println!("Couldn't complete the refund transaction");
          continue;
        }
        let client_refund_and_spend_sig     = result.unwrap();
        let client_refund_and_spend_sig_crc = State::<ARC>::calculate( &client_refund_and_spend_sig.clone()[..]);      
        
        if client_refund_and_spend_sig_crc != reconstructed_client_refund_and_spend_sig_crc
        {
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 2; //Received client signature crc doesn't match our value in the session
          //let _result = write(&mut stream, &cmd, &tx_data).await;  
          
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 2; //Received client signature crc doesn't match our value in the session
          let str_hex_tx_data = hex::encode(tx_data);          
          unsafe {
            DATA_READ_LEN = str_hex_tx_data.len() as i32;
            for x in 0..DATA_READ_LEN
            { 
              DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
            }
            CMD_READ = 5;      
          }          
          println!("Library: #5: Confirmation of host/client signatures. CRC of client_refund_and_spend_sig mismatch");
          continue;
        }
                    
        //println!("Library: #5 Host/client signatures verified. Transmit result.");
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 3; //CRCs match
        //let _result = write(&mut stream, &cmd, &tx_data).await; 
        let str_hex_tx_data = hex::encode(tx_data);          
        unsafe {
          DATA_READ_LEN = str_hex_tx_data.len() as i32;
          for x in 0..DATA_READ_LEN
          { 
            DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
          }
          CMD_READ = 5;      
        }                
        println!("Library: #5 Waiting for host to lock BTC funds");
      }    
      c_state=-1;
    }
    else if c_state==7 //7=Client prepare_buy from BTC lock
    {       
      let vec_data = hex::decode(vec_rx_data.clone()).unwrap();
      println!("Library #7"); 
      
      // Receive info about the buy transaction we will end up publishing
      // Namely, the host's signature, which we'll use to verify the buy and make sure we should continue
      //host_lock_and_refund_sig
      let prepared_buy = vec_data;
      
      let prepared_buy_crc = State::<ARC>::calculate( &prepared_buy[..]);
      //println!("Library: #7 Client prepare_buy from BTC lock len={} CRC:{:02x?}",prepared_buy.len(),prepared_buy_crc);
      
      let result = scripted_verifier.verify_prepared_buy(&prepared_buy);
      if !result.is_ok()
      {
        println!("Library: #7 Could not verify the prepared BTC buy transaction");
        return -1;
      }
      let mut str_hex_buy_transaction = result.unwrap();
      //println!("Library: #7 Verified prepared_buy");
      
      let mut s_value=String::new();
      read_session_key(0, "prepared_buy_from_btc_lock", &mut s_value);
      if s_value.len() == 0
      {
        let mut str_hex_prepared_buy = hex::encode(prepared_buy);
        write_session_key(0, "prepared_buy_from_btc_lock", &mut str_hex_prepared_buy);
        write_session_key(0, "buy_transaction", &mut str_hex_buy_transaction);
      }
      
      //println!("Library: #7 Client prepare_buy from BTC lock verified. Transmit result.");
      let mut tx_data = vec![0u8; 1];
      tx_data[0] = 1; //prepare_buy verified.
      //let _result = write(&mut stream, &cmd, &tx_data).await;
      let str_hex_tx_data = hex::encode(tx_data);
      unsafe {
        DATA_READ_LEN = str_hex_tx_data.len() as i32;
        for x in 0..DATA_READ_LEN
        { 
          DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
        }
        CMD_READ = 7;      
      }
      c_state=-1;     
    }
    else if c_state==8 //8=Verify BTC locked; Prompt for ARRR to be deposited to funding address
    {
      println!("Library: #8 Verify if BTC funds are locked");
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
        //println!("Library: #8 Verifying if BTC funds are locked on the blockchain (Expected after 1 confirmation)");
        let result = scripted_verifier.verify_and_wait_for_lock(false).await;
        if !result.is_ok()
        {
          println!("Library: #8 Wait for lock failed");
        }
        let _lock_height = result.unwrap();
        if _lock_height==0
        {
          println!("Library: #8 BTC funds not detected in lock address after 20 seconds");
          //Funds not yet in the lock
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 0; //BTC locked funds not detected after 20 seconds
//        let _result = write(&mut stream, &cmd, &tx_data).await;        
          let str_hex_tx_data = hex::encode(tx_data);          
          unsafe {
            DATA_READ_LEN = str_hex_tx_data.len() as i32;
            for x in 0..DATA_READ_LEN
            { 
              DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
            }
            CMD_READ = 8;
          }    
        }
        else
        {
          println!("Library: #8 BTC funds detected in the lock transaction: {}\n",_lock_height);
          
          write_session_key(0, "btc_locked", "1");
          let hex_str_lock_height = hex::encode( &_lock_height.to_string() );
          write_session_key(0, "lock_transaction_confirmation_height",&hex_str_lock_height);
          write_session_key(0, "arrr_address", &unscripted_client.get_address() );
          
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 1; //BTC locked funds detected
          //let _result = write(&mut stream, &cmd, &tx_data).await;
          let str_hex_tx_data = hex::encode(tx_data);          
          unsafe {
            DATA_READ_LEN = str_hex_tx_data.len() as i32;
            for x in 0..DATA_READ_LEN
            { 
              DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
            }
            CMD_READ = 8;
          }              
        }
      }
      else
      {
        read_session_key(0, "lock_transaction_confirmation_height", &mut str_hex_lock_height);
        let vec_value = hex::decode(str_hex_lock_height).unwrap();
        let str_value = String::from_utf8_lossy(&vec_value);
        _lock_height   = str_value.parse::<isize>().unwrap();      
        
        scripted_verifier.restore_lock_height(_lock_height);
        //println!("Restored lock height from session: {}",_lock_height);
         
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 1; //BTC locked funds detected
        //let _result = write(&mut stream, &cmd, &tx_data).await; 
        let str_hex_tx_data = hex::encode(tx_data);
        unsafe {
          DATA_READ_LEN = str_hex_tx_data.len() as i32;
          for x in 0..DATA_READ_LEN
          { 
            DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
          }
          CMD_READ = 8;
        }            
      }
      c_state=-1;
    }
    else if c_state==9 //Arrr account funded?
    {
      println!("Library: #9 Arrr transaction funded?");
      let mut s_value = String::new();
      read_session_key(0, "arrr_funded", &mut s_value);
      if s_value != "1"
      {
        // Now that the BTC is locked on-chain and we have everything we need to buy its funds,
        // we need to publish our Arrr transaction
        println!("Send your Arrr to {}\nfor the swap to continue. Need 8 confirmations.", unscripted_client.get_address());
        
        let result_wrapped = unscripted_client.wait_for_deposit(false).await;
        if !result_wrapped.is_ok()
        {
          println!("unscripted_client.wait_for_deposit() failed");
          return -1;
        }
        let result = result_wrapped.unwrap();
        //println!("Result contents: {}",result);
        
        if result==0
        {
          //println!("Library: #9 ARRR funds not detected after 20 seconds");
          //Funds not yet in the lock
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 0; //ARRR funds not detected after 20 seconds
          //let _result = write(&mut stream, &cmd, &tx_data).await;
          let str_hex_tx_data = hex::encode(tx_data);
          unsafe {
            DATA_READ_LEN = str_hex_tx_data.len() as i32;
            for x in 0..DATA_READ_LEN
            { 
              DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
            }
            CMD_READ = 9;
          }          
        }
        else
        {
          //println!("Library: #9 ARRR funds detected");
          
          write_session_key(0, "arrr_funded", "1");
          
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 1; //ARRR funds detected
          //let _result = write(&mut stream, &cmd, &tx_data).await;
          let str_hex_tx_data = hex::encode(tx_data);
          unsafe {
            DATA_READ_LEN = str_hex_tx_data.len() as i32;
            for x in 0..DATA_READ_LEN
            { 
              DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
            }
            CMD_READ = 9;
          }          
        }
      }
      else
      {
        //println!("Library: #9 ARRR account already funded");
        let mut tx_data = vec![0u8; 1];
        tx_data[0] = 1; //Arrr account funded
        //let _result = write(&mut stream, &cmd, &tx_data).await;
        let str_hex_tx_data = hex::encode(tx_data);
        unsafe {
          DATA_READ_LEN = str_hex_tx_data.len() as i32;
          for x in 0..DATA_READ_LEN
          {
            DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
          }
          CMD_READ = 9;
        }
      }
      c_state=-1;
    }    
    else if c_state==11 //Share secret
    {
      let vec_data = hex::decode(vec_rx_data.clone()).unwrap();
      println!("Library: #11 Share secret");
      
      let vec_secret = vec_data;
      let str_hex_secret = hex::encode( vec_secret.clone() );
      let secret_crc = State::<ARC>::calculate( &vec_secret[..]);
      
      //println!("Library: #11 Received secret:{:02x?} crc={:02x?}",vec_secret, secret_crc);
      
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
        let result = scripted_verifier.verify_prepared_buy(&vec_prepared_buy);
        if !result.is_ok()
        {
          println!("Library: #11 Could not verify the prepared buy");
          return -1;
        }
        let _str_hex_buy_transaction = result.unwrap();
      
        //println!("Library: #11 Finalise BTC buy");
        let result = scripted_verifier.finish(&vec_secret).await;
        if !result.is_ok()
        {
          println!("Library: #11 Couldn't finish buying BTC");
          
          let mut tx_data = vec![0u8; 1];
          tx_data[0] = 2; //Secret received, but buy transaction failed
          let str_hex_tx_data = hex::encode(tx_data);
          unsafe {
            DATA_READ_LEN = str_hex_tx_data.len() as i32;
            for x in 0..DATA_READ_LEN
            { 
              DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
            }
            CMD_READ = 11;
          }
          return -1;
        }
        let (vec_buy_transaction,vec_buy_transaction_txid) = result.unwrap();
        //println!("Library: #11 Buy completed");
        
        let str_hex_buy = hex::encode(vec_buy_transaction);
        let str_hex_buy_txid = hex::encode(vec_buy_transaction_txid);
        
        //println!("BTC buy transaction: {}",str_hex_buy);
        //println!("BTC buy txid: {}", str_hex_buy_txid );        
        
        write_session_key(0,"buy_transaction",&str_hex_buy);
        write_session_key(0,"buy_transaction_txid",&str_hex_buy_txid);
      }
      let mut tx_data = vec![0u8; 1];
      tx_data[0] = 1; //Secret received. Buy transaction submitted
      //let _result = write(&mut stream, &cmd, &tx_data).await;      
      let str_hex_tx_data = hex::encode(tx_data);
      unsafe {
        DATA_READ_LEN = str_hex_tx_data.len() as i32;
        for x in 0..DATA_READ_LEN
        { 
          DATA_READ[x as usize] = str_hex_tx_data.as_bytes()[x as usize];
        }
        CMD_READ = 11;
      }      
      c_state=-1;
      break;
    }    
    tokio::time::delay_for(std::time::Duration::from_millis(10)).await;
  }
  
  return 0;
}