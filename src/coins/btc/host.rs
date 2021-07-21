use std::{
  marker::PhantomData,
  fmt::Debug,
  path::Path,
  fs::File
};
use std::fs;
use async_trait::async_trait;
use hex_literal::hex;
use rand::{rngs::OsRng, RngCore};
use digest::Digest;
use std::fs::OpenOptions;
use std::io::prelude::*;

use serde::Deserialize;
use crc16::*;
use bitcoin::{
  secp256k1,
  hashes::hex::FromHex, hash_types::Txid,
  blockdata::{script::Script, transaction::{OutPoint, TxIn, TxOut, Transaction}},
  util::{address::Address, bip143::SighashComponents},
  consensus::serialize
};

use crate::{
  crypt_engines::{KeyBundle, CryptEngine, secp256k1_engine::Secp256k1Engine},
  coins::{
    ScriptedHost, UnscriptedVerifier,
    btc::{engine::*, rpc::*}
  }
};

pub struct BtcHost {
  engine: BtcEngine,
  rpc: BtcRpc,
//  #[cfg(test)]
  refund_pubkey: Option<bitcoin::util::key::PublicKey>,
  refund_pubkey_script: Script,
  address: Option<(<Secp256k1Engine as CryptEngine>::PrivateKey, String, [u8; 20])>,

  swap_secret: [u8; 32],
  swap_hash: Vec<u8>,

  lock: Option<Transaction>,
  lock_height: Option<isize>,

  refund: Option<Transaction>,
  spend: Option<Transaction>,
  refund_script: Option<Script>,
  refund_message: Option<secp256k1::Message>,
  refund_signature: Option<Vec<u8>>,
  spend_message: Option<Vec<u8>>,
  encrypted_spend_signature: Option<<Secp256k1Engine as CryptEngine>::EncryptedSignature>,

  client: Option<Vec<u8>>,
  client_refund: Option<Vec<u8>>,
  client_destination_script: Option<Script>,

  encryption_key: Option<<Secp256k1Engine as CryptEngine>::PublicKey>,
  encrypted_signature: Option<<Secp256k1Engine as CryptEngine>::EncryptedSignature>,
  buy: Option<Txid>,
  
  
  //session
  //session_keybundle : Option<Vec<u8>>
}

impl BtcHost {
  pub fn new(config_path: &String) -> anyhow::Result<BtcHost> {
//    let s_path = "./config/bitcoin.json";
    let config = serde_json::from_reader(File::open(config_path)?)?;
//    let config = serde_json::from_reader(File::open(s_path)?)?;

    let mut swap_secret = [0; 32];
    OsRng.fill_bytes(&mut swap_secret);
    Ok(BtcHost {
      engine: BtcEngine::new(),
      rpc: BtcRpc::new(&config)?,
//      #[cfg(test)]
      refund_pubkey: None,
      refund_pubkey_script: BtcEngine::decode_address(&config.refund)?,
      address: None,

      swap_secret,
      swap_hash: sha2::Sha256::digest(&swap_secret).to_vec(),

      lock: None,
      lock_height: None,

      refund: None,
      spend: None,
      refund_script: None,
      refund_message: None,
      refund_signature: None,
      spend_message: None,
      encrypted_spend_signature: None,

      client: None,
      client_refund: None,
      client_destination_script: None,

      encryption_key: None,
      encrypted_signature: None,
      buy: None
      
//      session_keybundle : None
    })
  }
  


  async fn prepare_refund_and_spend(&mut self, lock_id: Txid, lock_value: u64) -> anyhow::Result<(u64, Vec<u8>)> {
    let fee_per_byte = self.rpc.get_fee_per_byte().await?;
    let (refund_script, refund, refund_message, sig) = self.engine.prepare_and_sign_refund(
      lock_id,
      true,
      self.client_refund.as_ref().expect("Creating refund before verifying keys"),
      self.client.as_ref().expect("Creating refund before verifying keys"),
      lock_value,
      fee_per_byte
    )?;

    let spend = BtcEngine::prepare_spend(
      refund.txid(),
      self.refund_pubkey_script.clone(),
      refund.output[0].value,
      fee_per_byte
    )?;
    let components = SighashComponents::new(&spend);
    self.spend_message = Some(
      components.sighash_all(
        &spend.input[0],
        &Script::from(self.engine.refund_script_bytes.clone().expect("Creating spend before refund script")),
        refund.output[0].value
      ).to_vec()
    );

    self.refund_script = Some(refund_script);
    self.refund = Some(refund);
    self.refund_message = Some(refund_message);
    self.refund_signature = Some(sig.clone());
    self.spend = Some(spend);

    Ok((fee_per_byte, sig))
  }
}

#[async_trait]
impl ScriptedHost for BtcHost {

  fn report_host_state(&mut self)
  {
    if self.refund_pubkey == None
    {
      //println!("refund_pubkey == None");
    }
    else
    {
      //println!("refund_pubkey: {:02x?}",self.refund_pubkey);
    }
    
    //println!("refund_pubkey_script: {:02x?}", self.refund_pubkey_script);

     
    if self.address == None
    {
      //println!("address == None");
    }
    else
    {
      //println!("address: {:02x?}",self.address);
    }
    
    //println!("swap_secret: {:02x?}",self.swap_secret);
    //println!("swap_hash: {:02x?}",self.swap_hash);

    if self.lock == None
    {
      //println!("lock == None");
    }
    else
    {
      //println!("lock: {:02x?}",self.lock);
    }
    if self.lock_height == None
    {
      //println!("lock_height == None");
    }
    else
    {
      //println!("lock_height: {:02x?}",self.lock_height);
    }

/*
      refund: None,
      spend: None,
      refund_script: None,
      refund_message: None,
      refund_signature: None,
      spend_message: None,
      encrypted_spend_signature: None,

      client: None,
      client_refund: None,
      client_destination_script: None,

      encryption_key: None,
      encrypted_signature: None,
      buy: None
*/      
  }
  
  fn read_session_key(&self, s_key: &str, s_value: &mut String)
  {
    let local_value;  //str
    
    let data = fs::read_to_string("./host_session");
   
    let data = match data {
        Ok(file) => file,
        Err(_error) => {
            //println!("No session file found. Assuming new session");
            return;
        },
    };
    
    let split_data = data.split("\n");    
    
    //print!("session {}:",s_key);
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
          else
          {
            //println!("{}",s_value);            
          }
          return;
        }
      }
    }
    //println!("<Not in session>");
  }
    
  fn write_session_key(&self, s_key: &str, s_value: &str)
  {    
   
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("./host_session")
        .unwrap();

    if let Err(e) = writeln!(file, "{}={}", s_key,s_value)
    {
      eprintln!("Couldn't write to file: {}", e);
    }
  }
  
  fn init_session(&mut self)
  {
    let mut s_value = String::new();
    self.read_session_key("swap_secret",&mut s_value);
    
    //0 : secret
    if s_value.is_empty()
    {
      //println!("SESSION: Generate new secret:");
      OsRng.fill_bytes(&mut self.swap_secret);      
      
      let str_hex_secret    = hex::encode(self.swap_secret.clone() );      
      //println!("str_hex_secret = { }", str_hex_secret);
     
      self.write_session_key("swap_secret", &str_hex_secret);
    }
    else if s_value.len() != 64
    {
      //println!("SESSION: Found swap_secret, but length!=64");
      return;
    }
    else    
    { 
      //println!("SESSION: Returned secret: {}",s_value);
      //String to [u8; 32]
      //Conver the 64 char hex array to 32 bytes [u8]
      let ca_vec = hex::decode( s_value.clone() ).unwrap();
      let ca_bytes:&[u8] = &ca_vec;
      //Convert the [u8] to fixed size [u8;32]
      let mut ca32_bytes : [u8;32] = Default::default();
      ca32_bytes.copy_from_slice(&ca_bytes[0..32]);

      
      self.swap_secret = ca32_bytes;
      //println!("SESSION: secret={:02x?}", self.swap_secret);
    }
    //Calculate the swap_hash
    self.swap_hash = sha2::Sha256::digest( &self.swap_secret.clone() ).to_vec();      
    let str_hex_swap_hash = hex::encode(self.swap_hash.clone()   );
    //println!("SESSION: swap_hash={:02x?}", str_hex_swap_hash);


    //1 : engine
    //let caB  = &self.engine.b;
    //let caBR = &self.engine.br;
    let mut str_hex_engine_b  = String::new();
    let mut str_hex_engine_br = String::new();
    self.read_session_key("btc_engine_b", &mut str_hex_engine_b);
    self.read_session_key("btc_engine_br",&mut str_hex_engine_br);
    
    //0 : secret
    if !str_hex_engine_b.is_empty() && !str_hex_engine_br.is_empty()
    {
      //Conver the 64 char hex array to 32 bytes [u8]
      let ca_vec = hex::decode( str_hex_engine_b.clone() ).unwrap();
      let ca_bytes:&[u8] = &ca_vec;
      //Convert the [u8] to fixed size [u8;32]
      let mut ca32_bytes : [u8;32] = Default::default();
      ca32_bytes.copy_from_slice(&ca_bytes[0..32]);
      //Assign the key    
      self.engine.b = Secp256k1Engine::bytes_to_private_key(ca32_bytes).unwrap();

      //Conver the 64 char hex array to 32 bytes [u8]
      let ca_vec = hex::decode( str_hex_engine_br.clone() ).unwrap();
      let ca_bytes:&[u8] = &ca_vec;
      //Convert the [u8] to fixed size [u8;32]
      let mut ca32_bytes : [u8;32] = Default::default();
      ca32_bytes.copy_from_slice(&ca_bytes[0..32]);
      //Assign the key    
      self.engine.br = Secp256k1Engine::bytes_to_private_key(ca32_bytes).unwrap();      
    }
    else
    {
      //println!("SESSION: Engine B&BR not stored. Write current values to session.");
      
      str_hex_engine_b  = hex::encode(self.engine.b.to_bytes()  );  //Scalar to [u8] to hex_str
      str_hex_engine_br = hex::encode(self.engine.br.to_bytes() );  //Scalar to [u8] to hex_str      
     
      self.write_session_key("btc_engine_b", &str_hex_engine_b);
      self.write_session_key("btc_engine_br", &str_hex_engine_br);
    }
    
    let ca_b                 = Secp256k1Engine::public_key_to_bytes(&Secp256k1Engine::to_public_key(&self.engine.b));
    let ca_engine_b_crc      = State::<ARC>::calculate( &ca_b[..]);
    let ca_br                = Secp256k1Engine::public_key_to_bytes(&Secp256k1Engine::to_public_key(&self.engine.br));
    let ca_engine_br_crc     = State::<ARC>::calculate( &ca_br[..]);   
    //println!("setup_engine()\nB:{ } crc={:02x?}\nBR={ } crc={:02x?}",str_hex_engine_b,ca_engine_b_crc,str_hex_engine_br,ca_engine_br_crc);
  }
  
  async fn generate_keys<Verifier: UnscriptedVerifier>(&mut self, verifier: &mut Verifier) -> Vec<u8> {
    //println!("btc/hosts generate_keys()");
    self.report_host_state();

    //Need to initialise blockchain height during engine startup from the session data:
    let mut str_hex_arrr_engine_height = String::new();
    
    //verifier.generate_keys_for_engine() set internal variables.
    //Need to initialise verifier key1 from the session data.
    let mut str_hex_verifier_dl_eq     = String::new();
    let mut str_hex_arrr_engine_height = String::new();
    let mut str_hex_arrr_engine_nsk    = String::new(); //nsk
    let mut str_hex_arrr_engine_ask    = String::new(); //key1
    let mut str_hex_btc_verifier_ak    = String::new(); //key2
    
    
    self.read_session_key("verifier_dl_eq",     &mut str_hex_verifier_dl_eq);
    self.read_session_key("arrr_engine_height", &mut str_hex_arrr_engine_height);    
    self.read_session_key("arrr_engine_nsk",    &mut str_hex_arrr_engine_nsk);
    self.read_session_key("arrr_engine_ask",    &mut str_hex_arrr_engine_ask);
    self.read_session_key("btc_verifier_ak",    &mut str_hex_btc_verifier_ak);
    
    let dl_eq;
    let ca_arrr_engine_nsk_crc;
    let ca_arrr_engine_ask_crc;  
    let ca_btc_verifier_ak_crc;


    if !str_hex_verifier_dl_eq.is_empty()     &&
       !str_hex_arrr_engine_height.is_empty() &&
       !str_hex_arrr_engine_nsk.is_empty()    &&
       !str_hex_arrr_engine_ask.is_empty()    &&
       !str_hex_btc_verifier_ak.is_empty()
       
    {
      //println!("generate_keys() - Read from session");       
      verifier.restore_private_variables(&str_hex_arrr_engine_nsk, &str_hex_arrr_engine_ask, &str_hex_arrr_engine_height).await;  //ARRR engine variables
      dl_eq = hex::decode( str_hex_verifier_dl_eq.clone() ).unwrap();
      
      //Restore ak
      let ca_vec = hex::decode(str_hex_btc_verifier_ak).unwrap();
      let ca_bytes:&[u8] = &ca_vec;
      let mut ca32_bytes : [u8;32] = Default::default();
      ca32_bytes.copy_from_slice(&ca_bytes[0..32]);   
      ca_btc_verifier_ak_crc  = State::<ARC>::calculate( &ca_bytes[..]);
      let key_ak = Secp256k1Engine::bytes_to_private_key(ca32_bytes).unwrap();
      self.engine.bs = Some(key_ak); //BTC engine
            
      let ca_vec = hex::decode(str_hex_arrr_engine_nsk).unwrap();
      let ca_bytes:&[u8] = &ca_vec;
      ca_arrr_engine_nsk_crc  = State::<ARC>::calculate( &ca_bytes[..]);
      
      let ca_vec = hex::decode(str_hex_arrr_engine_ask).unwrap();
      let ca_bytes:&[u8] = &ca_vec;
      ca_arrr_engine_ask_crc  = State::<ARC>::calculate( &ca_bytes[..]);                 
    }
    else
    {      
      let (dl_eq2, ca_key_nsk, key_ak2, ca_key_ask, i_height) = verifier.generate_keys_for_engine::<Secp256k1Engine>(PhantomData);
      dl_eq = dl_eq2.clone();
      let key_ak = key_ak2.clone();      
      self.engine.bs = Some( key_ak.clone() ); //BTC engine
      
      //println!("generate_keys() - Generate new & store to session");
      str_hex_verifier_dl_eq = hex::encode( dl_eq.clone() );
      self.write_session_key("verifier_dl_eq", &str_hex_verifier_dl_eq);
                   
      str_hex_arrr_engine_height = hex::encode( i_height.to_string() ); // int to str to hex_str
      self.write_session_key("arrr_engine_height", &str_hex_arrr_engine_height);                          
                     
      str_hex_arrr_engine_nsk = hex::encode( ca_key_nsk );//[u8] to hex_str
      self.write_session_key("arrr_engine_nsk", &str_hex_arrr_engine_nsk);                     
      
      str_hex_arrr_engine_ask = hex::encode( ca_key_ask );// [u8] to hex_str
      self.write_session_key("arrr_engine_ask", &str_hex_arrr_engine_ask);
                     
      str_hex_btc_verifier_ak = hex::encode( key_ak.to_bytes() );//Scalar to [u8] to hex_str
      self.write_session_key("btc_verifier_ak", &str_hex_btc_verifier_ak);
      
      
      ca_arrr_engine_nsk_crc = State::<ARC>::calculate( &ca_key_nsk[..]);
      ca_arrr_engine_ask_crc = State::<ARC>::calculate( &ca_key_ask[..]);
      ca_btc_verifier_ak_crc = State::<ARC>::calculate( &key_ak.to_bytes()[..]);
      
    }    
    
    let ca_dleq_crc          = State::<ARC>::calculate( &dl_eq.clone()[..]);    
    let ca_btc_engine_b      = Secp256k1Engine::public_key_to_bytes(&Secp256k1Engine::to_public_key(&self.engine.b));
    let ca_btc_engine_b_crc  = State::<ARC>::calculate( &ca_btc_engine_b[..]);
    let ca_btc_engine_br     = Secp256k1Engine::public_key_to_bytes(&Secp256k1Engine::to_public_key(&self.engine.br));
    let ca_btc_engine_br_crc = State::<ARC>::calculate( &ca_btc_engine_br[..]);    
    let ca_refund_pubkey     = self.refund_pubkey_script.to_bytes();
    let ca_refund_pubkey_crc = State::<ARC>::calculate( &ca_refund_pubkey[..]);
        
    //println!("generate_keys(done)");
    //println!("  dleq crc=0x{:02x?}"            , ca_dleq_crc);
    //println!("  arrr_engine_nsk crc=0x{:02x?}" , ca_arrr_engine_nsk_crc);
    //println!("  arrr_engine_ask crc=0x{:02x?}" , ca_arrr_engine_ask_crc);
                                                     
    //println!("  btc_engine_b crc=0x{:02x?}"    , ca_btc_engine_b_crc);
    //println!("  btc_engine_br crc=0x{:02x?}"   , ca_btc_engine_br_crc); 
    //println!("  btc_verifier_ak crc=0x{:02x?}" , ca_btc_verifier_ak_crc);
                                                 
    //println!("  refund_pubkey crc=0x{:02x?}"   , ca_refund_pubkey_crc);
    
    KeyBundle {
      dl_eq,
      B: Secp256k1Engine::public_key_to_bytes(&Secp256k1Engine::to_public_key(&self.engine.b)),
      BR: Secp256k1Engine::public_key_to_bytes(&Secp256k1Engine::to_public_key(&self.engine.br)),
      scripted_destination: self.refund_pubkey_script.to_bytes()
    }.serialize()
  }

  fn verify_keys<Verifier: UnscriptedVerifier>(&mut self, keys: &[u8], verifier: &mut Verifier) -> anyhow::Result<()> {
    let keys = KeyBundle::deserialize(keys)?;
    let key = verifier.verify_dleq_for_engine::<Secp256k1Engine>(&keys.dl_eq, PhantomData)?;
    if (keys.B.len() != 33) || (keys.BR.len() != 33) {
      anyhow::bail!("Keys have an invalid length");
    }
    self.client = Some(keys.B);
    self.client_refund = Some(keys.BR);
    self.encryption_key = Some(key);
    self.client_destination_script = Some(Script::from(keys.scripted_destination));
    
    //println!("verify_keys()\n  client={:02x?}\n  client_refund={:02x?}\n  encryption_key={:02x?}\n  client_destination_script={:02x?}",
    //  self.client, self.client_refund, self.encryption_key, self.client_destination_script);
    
    Ok(())
  }

  fn swap_secret(&self) -> [u8; 32] {
    self.swap_secret
  }

  fn generate_deposit_address(&mut self) -> String {
    //println!("btc/host.rs generate_deposit_address()");
    
    let mut str_hex_deposit_address_secret     = String::new();
    let mut str_hex_deposit_address_public     = String::new();
    let mut str_hex_deposit_address_pubkeyhash = String::new();    
    self.read_session_key("deposit_address_secret"    ,&mut str_hex_deposit_address_secret);
    self.read_session_key("deposit_address_public"    ,&mut str_hex_deposit_address_public);
    self.read_session_key("deposit_address_pubkeyhash",&mut str_hex_deposit_address_pubkeyhash);
    
    let address;
    if str_hex_deposit_address_secret.len()     == 0 ||
       str_hex_deposit_address_public.len()     == 0 ||
       str_hex_deposit_address_pubkeyhash.len() == 0
    {
      address = BtcEngine::generate_deposit_address();
      
      //Address is a 3 part result:
      //(
      //  key,                                                < Scalar<Secret,NonZero>
      //  Address::p2wpkh(public_key, NETWORK).to_string(),   < String
      //  WPubkeyHash::from_engine(hash_engine).as_ref().try_into().expect("Couldn't convert a twenty-byte hash to a twenty-byte array")  < [u8; 20]
      //)
      //println!("  new address: key={:02x?}\n,  address={},\n  WPubkeyHash={:02x?}",address.0, address.1.to_string(), address.2);
    
      str_hex_deposit_address_secret     = hex::encode( address.0.to_bytes().clone() );
      str_hex_deposit_address_public     = hex::encode( address.1.clone() );
      str_hex_deposit_address_pubkeyhash = hex::encode( address.2.clone() );
    
      self.write_session_key("deposit_address_secret"    ,&str_hex_deposit_address_secret);
      self.write_session_key("deposit_address_public"    ,&str_hex_deposit_address_public);
      self.write_session_key("deposit_address_pubkeyhash",&str_hex_deposit_address_pubkeyhash);
    }
    else
    {
      //Process the session variables:
      let ca_vec = hex::decode( str_hex_deposit_address_secret.clone() ).unwrap();
      let ca_bytes:&[u8] = &ca_vec;
      //Convert the [u8] to fixed size [u8;32]
      let mut ca32_bytes : [u8;32] = Default::default();
      ca32_bytes.copy_from_slice(&ca_bytes[0..32]);
      let deposit_address_secret = Secp256k1Engine::bytes_to_private_key(ca32_bytes).unwrap();
      
      let vec_deposit_address_public = hex::decode( str_hex_deposit_address_public.clone() ).unwrap();
      let deposit_address_public     = String::from_utf8(vec_deposit_address_public).expect("Found invalid UTF-8");

      let ca_vec = hex::decode( str_hex_deposit_address_pubkeyhash.clone() ).unwrap();
      let ca_bytes:&[u8] = &ca_vec;
      //Convert the [u8] to fixed size [u8;20]
      let mut deposit_address_pubkeyhash : [u8;20] = Default::default();
      deposit_address_pubkeyhash.copy_from_slice(&ca_bytes[0..20]);
      
      //println!("  Address from session: key={:02x?}\n,  address={}\n  WPubkeyHash={:02x?}",deposit_address_secret.clone(), deposit_address_public.clone(), deposit_address_pubkeyhash.clone());
    
      address = (deposit_address_secret,deposit_address_public, deposit_address_pubkeyhash);
    }
    
    self.address = Some(address.clone());
    
    address.1.to_string()
  }
  
  async fn create_lock_and_prepare_refund(
    &mut self
  ) -> anyhow::Result<Vec<u8>> {
    #[derive(Deserialize, Debug)]
    struct UnspentInputResponse {
      height: u32,
      tx_hash: String,
      tx_pos: u32,
      value: u64
    }
    
    //println!("host/create_lock_and_prepare_refund()");    
    let mut inputs_to_use = Vec::new();    
    let mut s_value = String::new();
    self.read_session_key("spendable_funds_recorded", &mut s_value); 
    
    
    let client = self.client.as_ref().expect("Creating lock before verifying keys");
    let client_refund = self.client_refund.as_ref().expect("Creating lock before verifying keys");
    
    
    let address = self.address.clone().expect("Creating lock before creating address");
    if s_value != "1"
    {
      println!("Library: Scanning BTC blockchain for incoming funds -- Need 1 confirmation");
      inputs_to_use = self.rpc.get_spendable(&address.1).await?;
      //let mut icount : u8;
      //Height is 0 as long as the input has 0 confirmations:
      while inputs_to_use.len() == 0 || inputs_to_use[0].height == 0
      {
        tokio::time::delay_for(std::time::Duration::from_secs(10)).await;
        inputs_to_use = self.rpc.get_spendable(&address.1).await?;
      }
      
      self.write_session_key("spendable_funds_recorded", "1");
      
      let str_hex_height=hex::encode( inputs_to_use[0].height.to_string() );
      self.write_session_key("spendable_funds_height", &str_hex_height);
      
      let str_hex_tx_hash= inputs_to_use[0].tx_hash.clone();
      self.write_session_key("spendable_funds_tx_hash", &str_hex_tx_hash);

      let str_hex_tx_pos=hex::encode( inputs_to_use[0].tx_pos.to_string() );
      self.write_session_key("spendable_funds_tx_pos", &str_hex_tx_pos);
      
      let str_hex_value=hex::encode( inputs_to_use[0].value.to_string() );      
      self.write_session_key("spendable_funds_value", &str_hex_value);
      
      
      //println!("inputs to use: {:02x?},{},{:02x?},{:02x?}",inputs_to_use[0].height,
      //                                      inputs_to_use[0].tx_hash,
      //                                      inputs_to_use[0].tx_pos,
      //                                      inputs_to_use[0].value
      //        );
      
      println!("BTC input to use: TxId={}",inputs_to_use[0].tx_hash);
    }
    else
    {
      //println!("  Restore data of the BTC funds from session variables");
      let mut my_input = self.rpc.get_empty_input_response().unwrap();
      
      let mut str_hex_height = String::new();
      self.read_session_key("spendable_funds_height", &mut str_hex_height);
      let vec_height = hex::decode( str_hex_height ).unwrap();
      let str_height = String::from_utf8_lossy(&vec_height);
      my_input.height = str_height.parse::<u32>().unwrap();
      
      let mut str_hex_tx_hash = String::new();
      self.read_session_key("spendable_funds_tx_hash", &mut str_hex_tx_hash);
      my_input.tx_hash = str_hex_tx_hash;      

      let mut str_hex_tx_pos = String::new();
      self.read_session_key("spendable_funds_tx_pos", &mut str_hex_tx_pos);
      let vec_tx_pos = hex::decode(str_hex_tx_pos).unwrap();
      let str_tx_pos = String::from_utf8_lossy(&vec_tx_pos);
      my_input.tx_pos = str_tx_pos.parse::<u32>().unwrap();      
      
      let mut str_hex_value = String::new();
      self.read_session_key("spendable_funds_value", &mut str_hex_value);
      let vec_value = hex::decode(str_hex_value).unwrap();
      let str_value = String::from_utf8_lossy(&vec_value);
      my_input.value = str_value.parse::<u64>().unwrap();            
      
      inputs_to_use.push(my_input);  
    }

    if inputs_to_use.len() != 1
    {
      println!("Current implemenation expects only one input to fund the transaction. Counted {} inputs",inputs_to_use.len());
      panic!(" ");
    }
      
    let mut value = 0;
    let inputs = inputs_to_use.iter().map(|input| {
      value += input.value;
      Ok(TxIn {
        previous_output: OutPoint{txid: Txid::from_hex(&input.tx_hash)?, vout: input.tx_pos},
        script_sig: Script::new(),
        sequence: 0xFFFFFFFF,
        witness: Vec::new()
      })
    }).collect::<anyhow::Result<_>>()?;
    //println!("  inputs={:02x?}",inputs);

    self.engine.create_lock_script(&self.swap_hash, true, client, client_refund);
    let mut lock_script_hash = hex!("0020").to_vec();
    lock_script_hash.extend(sha2::Sha256::digest(self.engine.lock_script_bytes()));
    //println!("  lock_script_hash: {:02x?}",lock_script_hash);

    let mut lock = Transaction {
      version: 2,
      lock_time: 0,
      input: inputs,
      output: vec![TxOut {
        value,
        script_pubkey: Script::from(lock_script_hash)
      }]
    };
    
    let fee = ((lock.get_weight() / 4) as u64) * self.rpc.get_fee_per_byte().await?;
    lock.output[0].value = lock.output[0].value.checked_sub(fee)
      .ok_or_else(|| anyhow::anyhow!("Not enough Bitcoin to pay for {} sats of fees", fee))?;

    let private_key = secp256k1::SecretKey::from_slice(
      &Secp256k1Engine::private_key_to_bytes(&address.0)
    ).expect("Secp256k1Engine generated an invalid secp256k1 key, yet we already used it earlier");
    
    //println!("private_key={:02x?}",private_key);

    let key_bytes = Secp256k1Engine::public_key_to_bytes(
      &Secp256k1Engine::to_public_key(&address.0)
    );
    //println!("  key_bytes={:02x?}",key_bytes);

    let mut segwit_script_code = hex!("76a914").to_vec();
    segwit_script_code.extend(&address.2);
    segwit_script_code.extend(hex!("88ac").to_vec());
    let segwit_script_code = Script::from(segwit_script_code);

    let components = SighashComponents::new(&lock);
    for i in 0 .. lock.input.len() {
      let signature = SECP.sign(
        &secp256k1::Message::from_slice(&components.sighash_all(&lock.input[i], &segwit_script_code, value))?,
        &private_key
      ).serialize_der();

      let mut signature = signature.to_vec();
      signature.push(1);
      lock.input[i].witness = vec![signature, key_bytes.clone()];
    }

    self.lock = Some( lock.clone() );
    let fee_per_byte_and_sig = self.prepare_refund_and_spend(lock.txid(), lock.output[0].value).await?;
    let result = Ok(
      bincode::serialize(
        &LockAndRefundInfo {
          swap_hash: self.swap_hash.clone(),
          lock_id: serialize(&lock.txid()),
          host_refund_signature: fee_per_byte_and_sig.1,
          value: lock.output[0].value,
          fee_per_byte: fee_per_byte_and_sig.0
        }
      ).expect("Couldn't serialize the lock and refund info")
    );
    
    result
  }

  fn verify_refund_and_spend(&mut self, refund_and_spend_sigs: &[u8]) -> anyhow::Result<()> {
    //println!("btc/hosts.rs verify_refund_and_spend()");
    let sigs: ClientRefundAndSpendSignatures = bincode::deserialize(refund_and_spend_sigs)?;
    let refund_signature = sigs.refund_signature;
    let encrypted_spend_signature = Secp256k1Engine::bytes_to_encrypted_signature(&sigs.encrypted_spend_signature)?;
    
    let sigs_crc                      = State::<ARC>::calculate( &refund_and_spend_sigs[..]);
    let refund_signature_crc          = State::<ARC>::calculate( &refund_signature[..]);
    let encrypted_spend_signature_crc = State::<ARC>::calculate( &sigs.encrypted_spend_signature[..]);
    //println!("  sigs crc={:02x?}",sigs_crc);
    //println!("  refund_signature={:02x?}",refund_signature_crc);
    //println!("  encrypted_spend_signature={:02x?}",encrypted_spend_signature_crc);
        
    
    
    let refund_message_length    = self.refund_message.clone().unwrap().len();    
    let refund_message_ptr       = self.refund_message.clone().unwrap().as_mut_ptr();
    unsafe {
      let buf: &mut [u8]           = core::slice::from_raw_parts_mut(refund_message_ptr, refund_message_length as usize);
      let refund_message_crc       = State::<ARC>::calculate( &buf );
      //println!("  refund_message_crc={:02x?}",refund_message_crc);
    }
    
    
    let ca_bytes:&[u8]    = &self.client_refund.as_ref().unwrap(); //as_ref():Get the contents out of Option ; .unwrap():Remove Option to reach the Scalar inside
    let client_refund_crc = State::<ARC>::calculate( &ca_bytes[..] );
    
    let engine_bs_unwrapped = self.engine.bs.clone().unwrap();   //Clone contents & Unwrap Option
    let ca_bytes2           = engine_bs_unwrapped.to_bytes();   //Scalar to [u8]
    let engine_bs_crc     = State::<ARC>::calculate( &ca_bytes2[..] );
    
    
    //println!("  client_refund_crc ={:02x?}",client_refund_crc);
    //println!("  engine_bs_crc     ={:02x?}",engine_bs_crc);
    

    SECP.verify(
      self.refund_message.as_ref().expect("Couldn't grab the refund's message despite attempting to verify the refund"),
      &secp256k1::Signature::from_der(&refund_signature)?,
      &secp256k1::PublicKey::from_slice(self.client_refund.as_ref().expect("Couldn't grab the client's refund public key despite attempting to verify the refund"))?
    )?;

    Secp256k1Engine::encrypted_verify(
      &Secp256k1Engine::bytes_to_public_key(self.client_refund.as_ref().expect("Trying to verify the spend signature before exchanging keys"))?,
      &Secp256k1Engine::to_public_key(self.engine.bs.as_ref().expect("Verifying spend before generating keys")),
      &encrypted_spend_signature,
      self.spend_message.as_ref().expect("Trying to verify the spend before knowing its message")
    )?;

    // Complete the refund transaction
    let mut refund = self.refund.take().expect("Verifying and completing the refund before creating it");
    refund.input[0].witness = vec![
      Vec::new(),
      refund_signature,
      self.refund_signature.clone().expect("Verifying the refund yet we never signed it"),
      Vec::new(),
      self.engine.lock_script_bytes.clone().expect("Finishing despite not knowing the lock script")
    ];
    refund.input[0].witness[1].push(1);
    refund.input[0].witness[2].push(1);
    self.refund = Some(refund);

    self.encrypted_spend_signature = Some(encrypted_spend_signature);

    Ok(())
  }

  async fn publish_lock( &mut self ) -> anyhow::Result<()> 
  {    
    let mut s_value = String::new();
    self.read_session_key("state_lock_transaction", &mut s_value);
    if s_value.len() == 0
    {
      let lock = self.lock.clone().unwrap();
      let lock_clone1 = lock.clone();
      let lock_clone2 = lock.clone();
      
      let mut lock_id = lock_clone1.txid().to_vec();
      lock_id.reverse();
      
      //println!("  Publish BTC lock transaction. Need 1 confirmation on the blockchain to continue");
      let ca_vec = serialize(&lock_clone2);
      let ca_bytes:&[u8] = &ca_vec;
      self.write_session_key("lock_transaction", &hex::encode(ca_bytes) );
      let txid = hex::encode(&lock_id.clone());
      self.write_session_key("lock_transaction_txid", &txid.clone() );
      //println!("  TxID: { }",txid.clone());
      
      self.rpc.publish(&serialize(&lock)).await?;
      let address = Address::p2wsh(self.engine.lock_script(), NETWORK).to_string();
      //FIXIT: Save engine.lock_script & engine.lock_script_bytes?
      
      let str_hex_address = hex::encode(address.clone() );
      self.write_session_key("lock_transaction_script_address", &str_hex_address );   
      self.write_session_key("state_lock_transaction", "1");
      
      
      let mut history = self.rpc.get_address_history(&address).await;
      while (history.len() == 0) || (history[0].confirmations < CONFIRMATIONS) {
        #[cfg(test)]
        self.rpc.mine_block().await?;

        tokio::time::delay_for(std::time::Duration::from_secs(20)).await;
        history = self.rpc.get_address_history(&address).await;
      }
      self.lock_height = Some(self.rpc.get_height().await);
      self.write_session_key("lock_transaction_confirmation_height", &self.lock_height.unwrap().to_string() );
      
      
      //println!("  BTC lock transaction accepted by the network.");
      
      let refund = self.refund.clone().expect("Refund transaction doesn't exist despite having published the lock");
      let refund_id = refund.txid();
      //    let _ = self.rpc.publish(&serialize(&refund)).await;
      let refund_address = Address::p2wsh(
          self.refund_script.as_ref().expect("Calling refund after publishing the lock but before knowinng the refund script"),
          NETWORK
      ).to_string();
      
      let ca_vec = serialize( &refund.clone() );
      let ca_bytes:&[u8] = &ca_vec;
      let hex_str_refund = hex::encode(ca_bytes);
      
      //println!("refund {}\n  txid {}\n  refund_addresss {}",hex_str_refund, refund_id, refund_address); 
      self.write_session_key("lock_refund_transaction",&hex_str_refund);
     // self.write_session_key("lock_refund_txid",&refund_id);
      self.write_session_key("refund_address",&refund_address);
      
    }
    else
    {
      self.read_session_key("lock_transaction_txid", &mut s_value);
      //println!("  The BTC funds are already submitted to the lock address.\n  TxID:{}",s_value);
    }
    Ok(())
  }
  
  async fn generate_funding_address_refund(&mut self) -> anyhow::Result<()> 
  { 
    //println!("generate_funding_address_refund()");
    let address = self.address.clone().unwrap();
    let utxos = self.rpc.get_spendable(&address.1).await?;
  
    let mut value = 0;
    let inputs = utxos.iter().map(|input| {
      value += input.value;
      Ok(TxIn {
        previous_output: OutPoint{txid: Txid::from_hex(&input.tx_hash)?, vout: input.tx_pos},
        script_sig: Script::new(),
        sequence: 0xFFFFFFFF,
        witness: Vec::new()
      })
    }).collect::<anyhow::Result<_>>()?;

    let mut return_tx = Transaction {
      version: 2,
      lock_time: 0,
      input: inputs,
      output: vec![
        TxOut {
          script_pubkey: self.refund_pubkey_script.clone(),
          value
        }
      ]
    };
    let mut fee = ((return_tx.get_weight() / 4) as u64) * self.rpc.get_fee_per_byte().await?;             //FIXIT Already have the fee/byte. Just reuse it
    //Bitcoin core wallet rejected transaction with fee less than 110.00
    if fee<11100
    {
      fee=11100; //111.00 sats
    }
    //println!("  value:{}, fee:{}",value,fee);
    //return_tx.output[0].value = return_tx.output[0].value.checked_sub(fee);
    //  .ok_or_else(|| anyhow::anyhow!("Not enough Bitcoin to pay for {} sats of fees", fee))?;       //FIXIT: Check fees before starting swap
    
    return_tx.output[0].value = return_tx.output[0].value.checked_sub( fee/100 )
       .ok_or_else(|| anyhow::anyhow!("Not enough Bitcoin to pay for {} sats of fees", fee))?;        //FIXIT: Restore correct fee calculation


    let private_key = secp256k1::SecretKey::from_slice(
      &Secp256k1Engine::private_key_to_bytes(&address.0)
    ).expect("Secp256k1Engine generated an invalid secp256k1 key");

    let key_bytes = Secp256k1Engine::public_key_to_bytes(
      &Secp256k1Engine::to_public_key(&address.0)
    );

    let mut segwit_script_code = hex!("76a914").to_vec();
    segwit_script_code.extend(&address.2);
    segwit_script_code.extend(hex!("88ac").to_vec());
    let segwit_script_code = Script::from(segwit_script_code);

    let components = SighashComponents::new(&return_tx);
    for i in 0 .. return_tx.input.len() {
      let signature = SECP.sign(
        &secp256k1::Message::from_slice(&components.sighash_all(&return_tx.input[i], &segwit_script_code, value))?,
        &private_key
      ).serialize_der();

      let mut signature = signature.to_vec();
      signature.push(1);
      return_tx.input[i].witness = vec![signature, key_bytes.clone()];
    }
    
    let mut lock_id = return_tx.clone().txid().to_vec();
    lock_id.reverse();
    
    let ca_vec = serialize( &return_tx.clone() );
    let ca_bytes:&[u8] = &ca_vec;
    self.write_session_key("funding_adres_refund_transaction", &hex::encode(ca_bytes) );
    self.write_session_key("funding_adres_refund_transaction_txid", &hex::encode(&lock_id) );
    
    //self.rpc.publish(&serialize(&return_tx)).await?;
    //println!("The lock refund transaction: {}", &hex::encode(ca_bytes) );

    Ok(())
  }

/*
  async fn refund_btc_lock<Verifier: UnscriptedVerifier>(mut self, mut verifier: Verifier) -> anyhow::Result<()>{
  
    // If we published the lock, we need to publish the refund transaction
    // First, we need to wait for T0 to expire

    let current_height = self.rpc.get_height().await;
    //println!("Current height: {}, self.lock_height: {}",current_height, self.lock_height);
    
    //while self.rpc.get_height().await < (self.lock_height.expect("Never set lock height despite published lock") + (T0 as isize)) {
    //   #[cfg(test)]
    //      for _ in 0 .. T0 {
    //        self.rpc.mine_block().await?;
    //      }
    //      tokio::time::delay_for(std::time::Duration::from_secs(20)).await;
    //}

    let refund = self.refund.clone().expect("Refund transaction doesn't exist despite having published the lock");
    let refund_id = refund.txid();
    //    let _ = self.rpc.publish(&serialize(&refund)).await;
    let refund_address = Address::p2wsh(
          self.refund_script.as_ref().expect("Calling refund after publishing the lock but before knowinng the refund script"),
          NETWORK
    ).to_string();

        // Wait for the refund to confirm
        'outer: loop {
          #[cfg(test)]
          self.rpc.mine_block().await?;

          let history = self.rpc.get_address_history(&refund_address).await;
          let mut found = false;
          for tx in history {
            if (tx.tx.txid()) == (refund_id.clone()) {
              found = true;
              if (tx.confirmations) >= CONFIRMATIONS {
                break 'outer;
              }
            }
          }

          // Transaction was beat
          // Path D/forced success
          if !found {
            return verifier.finish(&mut self).await;
          }

          tokio::time::delay_for(std::time::Duration::from_secs(20)).await;
        }    
  }
*/

  async fn refund<Verifier: UnscriptedVerifier>(mut self, mut verifier: Verifier) -> anyhow::Result<()> {
    /*
      There are four states to be aware of:
      A) Never even created an address
      B) Created address but didn't fund
      C) Created address and did fund but didn't publish lock
      D) Published lock
      In the last case, if we fail to publish the refund, it may be because the client already claimed the BTC
      In that case, all we can do is finish purchasing the unscripted coin
    */

    // Path A
    if self.address.is_none() {
      Ok(())
    } else {
      // If the lock exists, confirm it was published
      let mut lock_exists = false;
      if let Some(lock) = self.lock.clone() {
        let mut lock_id = lock.txid().to_vec();
        lock_id.reverse();
        lock_exists = self.rpc.get_transaction(&hex::encode(&lock_id)).await.is_ok();
      }

      // Path B or C
      if !lock_exists {
        let address = self.address.expect("Address is some yet couldn't get its value");
        let utxos = self.rpc.get_spendable(&address.1).await?;
        // Path B
        if utxos.len() == 0 {
          Ok(())
        // Path C
        } else {
          let mut value = 0;
          let inputs = utxos.iter().map(|input| {
            value += input.value;
            Ok(TxIn {
              previous_output: OutPoint{txid: Txid::from_hex(&input.tx_hash)?, vout: input.tx_pos},
              script_sig: Script::new(),
              sequence: 0xFFFFFFFF,
              witness: Vec::new()
            })
          }).collect::<anyhow::Result<_>>()?;

          let mut return_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: inputs,
            output: vec![
              TxOut {
                script_pubkey: self.refund_pubkey_script,
                value
              }
            ]
          };
          let fee = ((return_tx.get_weight() / 4) as u64) * self.rpc.get_fee_per_byte().await?;
          return_tx.output[0].value = return_tx.output[0].value.checked_sub(fee)
            .ok_or_else(|| anyhow::anyhow!("Not enough Bitcoin to pay for {} sats of fees", fee))?;

          let private_key = secp256k1::SecretKey::from_slice(
            &Secp256k1Engine::private_key_to_bytes(&address.0)
          ).expect("Secp256k1Engine generated an invalid secp256k1 key");

          let key_bytes = Secp256k1Engine::public_key_to_bytes(
            &Secp256k1Engine::to_public_key(&address.0)
          );

          let mut segwit_script_code = hex!("76a914").to_vec();
          segwit_script_code.extend(&address.2);
          segwit_script_code.extend(hex!("88ac").to_vec());
          let segwit_script_code = Script::from(segwit_script_code);

          let components = SighashComponents::new(&return_tx);
          for i in 0 .. return_tx.input.len() {
            let signature = SECP.sign(
              &secp256k1::Message::from_slice(&components.sighash_all(&return_tx.input[i], &segwit_script_code, value))?,
              &private_key
            ).serialize_der();

            let mut signature = signature.to_vec();
            signature.push(1);
            return_tx.input[i].witness = vec![signature, key_bytes.clone()];
          }

          self.rpc.publish(&serialize(&return_tx)).await?;
          Ok(())
        }
      } else {
        // If we published the lock, we need to publish the refund transaction
        // First, we need to wait for T0 to expire

        while self.rpc.get_height().await < (self.lock_height.expect("Never set lock height despite published lock") + (T0 as isize)) {
          #[cfg(test)]
          for _ in 0 .. T0 {
            self.rpc.mine_block().await?;
          }
          tokio::time::delay_for(std::time::Duration::from_secs(20)).await;
        }

        let refund = self.refund.clone().expect("Refund transaction doesn't exist despite having published the lock");
        let refund_id = refund.txid();
        let _ = self.rpc.publish(&serialize(&refund)).await;
        let refund_address = Address::p2wsh(
          self.refund_script.as_ref().expect("Calling refund after publishing the lock but before knowinng the refund script"),
          NETWORK
        ).to_string();

        // Wait for the refund to confirm
        'outer: loop {
          #[cfg(test)]
          self.rpc.mine_block().await?;

          let history = self.rpc.get_address_history(&refund_address).await;
          let mut found = false;
          for tx in history {
            if (tx.tx.txid()) == (refund_id.clone()) {
              found = true;
              if (tx.confirmations) >= CONFIRMATIONS {
                break 'outer;
              }
            }
          }

          // Transaction was beat
          // Path D/forced success
          if !found {
            return verifier.finish(&mut self).await;
          }

          tokio::time::delay_for(std::time::Duration::from_secs(20)).await;
        }

        // Complete and publish the spend transaction.
        let mut spend = self.spend.expect("Spend transaction doesn't exist despite having published the lock");
        spend.input[0].witness = vec![
          Vec::new(),
          secp256k1::Signature::from_compact(
            &Secp256k1Engine::signature_to_bytes(
              &Secp256k1Engine::decrypt_signature(
                &self.encrypted_spend_signature.expect("Spend signature doesn't exist despite having published the lock"),
                &self.engine.bs.expect("Never generated keys despite having published the lock")
              )?
            )
          )?.serialize_der().to_vec(),
          SECP.sign(
            &secp256k1::Message::from_slice(
              &self.spend_message.expect("Spend message doesn't exist despite having published the lock")
            )?,
            &secp256k1::SecretKey::from_slice(&Secp256k1Engine::private_key_to_bytes(&self.engine.br))?
          ).serialize_der().to_vec(),
          vec![1],
          self.engine.refund_script_bytes.expect("Finishing despite not knowing the lock script")
        ];
        spend.input[0].witness[1].push(1);
        spend.input[0].witness[2].push(1);
        self.rpc.publish(&serialize(&spend)).await?;

        Ok(())
      }
    }
  }

  async fn prepare_buy_for_client(&mut self,
                                  pca_encrypted_sign_r1 : &[u8;32],                    //Must already be initialised with random data / swap
                                  pca_encrypted_sign_r2 : &[u8;32]                     //Must already be initialised with random data / swap
                                 ) -> anyhow::Result<Vec<u8>> {
    //println!("btc/hosts.rs prepare_buy_for_client()");
    let lock = self.lock.as_ref().expect("Preparing a buy transaction for the client despite not having created the lock");

    //External dependencies: 
    //  self.engine.b,                       << Restored from session in init_session()    
    //  self.client_destination_script       << Set in verify_keys()    
    //  self.encryption_key                  << Set in verify_keys()
    //  self.engine.lock_script()            << Set in create_lock_and_prepare_refund() -> engine::create_lock_script()
    
    //Created here:
    //  self.buy = Some(buy.txid());
    //  self.encrypted_signature
    
    let mut buy = Transaction {
      version: 2,
      lock_time: 0,
      input: vec![
        TxIn {
          previous_output: OutPoint {
            txid: lock.txid(),
            vout: 0
          },
          script_sig: Script::new(),
          sequence: 0xFFFFFFFF,
          witness: Vec::new()
        }
      ],
      output: vec![
        TxOut {
          script_pubkey: self.client_destination_script.clone().expect("Preparing buy for client before knowing their destination"),
          value: lock.output[0].value
        }
      ]
    };
    let fee = ((buy.get_weight() as u64) / 4) * self.rpc.get_fee_per_byte().await?;            //Fixit - Only lookup from network once
    buy.output[0].value = buy.output[0].value.checked_sub(fee)
      .ok_or_else(|| anyhow::anyhow!("Not enough Bitcoin to pay for {} sats of fees", fee))?;

    
    let mut struct_secp256k1_engine = Secp256k1Engine { ca_encrypted_sign_r1 : *pca_encrypted_sign_r1, ca_encrypted_sign_r2 : *pca_encrypted_sign_r2 };
    
    let components = SighashComponents::new(&buy);
    let encrypted_signature = Secp256k1Engine::encrypted_sign(&mut struct_secp256k1_engine,
      &self.engine.b,
      self.encryption_key.as_ref().expect("Attempted to generate encrypted sign before verifying dleq proof"),
      &components.sighash_all(
        &buy.input[0],
        self.engine.lock_script(),
        lock.output[0].value
      )
    )?;

    self.buy = Some(buy.txid());

    
    let serialized = bincode::serialize(&BuyInfo {
        value: buy.output[0].value,
        encrypted_signature: Secp256k1Engine::encrypted_signature_to_bytes(&encrypted_signature)
      })?;
    
    let result = Ok(
      bincode::serialize(&BuyInfo {
        value: buy.output[0].value,
        encrypted_signature: Secp256k1Engine::encrypted_signature_to_bytes(&encrypted_signature)
      })?
    );
    self.encrypted_signature = Some(encrypted_signature.clone());
    

    //Store the created communication block: prepare_buy in the session
    //let ca_vec = serialize( &serialized.clone() );
    //let ca_bytes:&[u8] = &ca_vec;
    //self.write_session_key("prepare_buy_for_client", &hex::encode(ca_bytes) );    
    
    //Store in session the items that were created here:
    //  self.buy                 = Some(buy.txid());
    //  self.encrypted_signature = Some(encrypted_signature.clone);
    
    let lock_id = buy.clone().txid().to_vec();
    let mut s_value = String::new();
    self.read_session_key("prepare_buy_for_client_txid", &mut s_value);    
    if s_value.len()==0    
    {
      self.write_session_key("prepare_buy_for_client_txid", &hex::encode(&lock_id));    
    }
    //self.write_session_key("prepare_buy_for_client_encrypted_signature", &hex::encode(   &Secp256k1Engine::encrypted_signature_to_bytes(&encrypted_signature)   ));
              
    let prepare_buy_crc = State::<ARC>::calculate( &serialized.clone()[..] );    
    //println!("  crc={:02x?}  txid={}",prepare_buy_crc, hex::encode(&lock_id));
       
    result
  }

  async fn recover_final_key(&self) -> anyhow::Result<[u8; 32]> {
    let encrypted_signature = self.encrypted_signature.as_ref().expect("Trying to recover the final key before preparing the encrypted signature");

    let mut buy_hash = self.buy.expect("Trying to recover the final key before creating the buy").to_vec();
    buy_hash.reverse();
    let buy_hash = hex::encode(buy_hash);
    let mut buy = Err(anyhow::anyhow!(""));
    while buy.is_err() {
      buy = self.rpc.get_transaction(&buy_hash).await;
      if buy.is_err() {
        tokio::time::delay_for(std::time::Duration::from_secs(3)).await;
      }
    }

    let their_signature = &buy?.input[0].witness[2];
    let signature = secp256k1::Signature::from_der(
      &their_signature[.. their_signature.len() - 1]
    ).expect("Signature included in the buy transaction wasn't valid despite getting on chain").serialize_compact();

    Ok(Secp256k1Engine::private_key_to_little_endian_bytes(
      &Secp256k1Engine::recover_key(
        self.encryption_key.as_ref().expect("Attempted to recover final key before verifying dleq proof"),
        encrypted_signature,
        &Secp256k1Engine::bytes_to_signature(&signature).expect("Failed to deserialize decrypted signature")
      ).expect("Failed to recover key from decrypted signature")
    ))
  }

  #[cfg(test)]
  fn override_refund_with_random_address(&mut self) {
    let pubkey = bitcoin::util::key::PublicKey::from_private_key(
      &SECP,
      &bitcoin::util::key::PrivateKey {
        compressed: true,
        network: NETWORK,
        key: secp256k1::SecretKey::from_slice(
          &Secp256k1Engine::private_key_to_bytes(
            &Secp256k1Engine::new_private_key()
          )
        ).expect("Secp256k1Engine generated invalid key")
      }
    );

    self.refund_pubkey_script = BtcEngine::decode_address(
      &Address::p2pkh(
        &pubkey,
        NETWORK
      ).to_string()
    ).expect("Generated an invalid random address");

    self.refund_pubkey = Some(pubkey);
  }
  #[cfg(test)]
  async fn send_from_node(&self) -> anyhow::Result<()> {
    self.rpc.send_from_electrum(&self.address.as_ref().unwrap().1.to_string()).await
  }
  #[cfg(test)]
  async fn advance_consensus(&self) -> anyhow::Result<()> {
    for _ in 0 .. CONFIRMATIONS {
      self.rpc.mine_block().await?
    }
    Ok(())
  }
  #[cfg(test)]
  fn get_refund_address(&self) -> String {
    Address::p2pkh(&self.refund_pubkey.expect("Calling test get_refund_address despite not overriding it"), NETWORK).to_string()
  }
  //#[cfg(test)]
  async fn get_if_funded(&mut self, address: &str) -> bool {
    self.rpc.get_spendable(address).await.expect("Couldn't get the UTXOs for an address").len() != 0
  }
}
