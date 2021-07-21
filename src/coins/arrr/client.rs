#[allow(unused_imports)]
use std::{
  marker::PhantomData,
  convert::TryInto,
  path::Path,
  fs::File
};

use async_trait::async_trait;

use std::fs;
use std::fs::OpenOptions;
use std::io::prelude::*;
use crc16::*;

#[allow(unused_imports)]
use rand::{rngs::OsRng, RngCore};

#[allow(unused_imports)]
use zcash_primitives::{
  primitives::Note,
  zip32::{ExtendedSpendingKey, ExtendedFullViewingKey}
};

#[cfg(test)]
use zcash_client_backend::encoding::encode_payment_address;

use crate::{
  crypt_engines::{KeyBundle, CryptEngine, jubjub_engine::JubjubEngine},
  coins::{UnscriptedClient, ScriptedVerifier, arrr::engine::*}
};

pub struct ArrrClient {
  engine: ArrrEngine,
  deposited: bool,
  #[cfg(test)]
  refund_seed: [u8; 32]
}

impl ArrrClient {
  pub async fn new(config_path: &String) -> anyhow::Result<ArrrClient> {
    //println!("src/coins/arrr/client.rs new()");
    Ok(ArrrClient{
      engine: ArrrEngine::new(serde_json::from_reader(File::open(config_path)?)?).await?,
      deposited: false,
      #[cfg(test)]
      refund_seed: [0; 32]
    })
  }
}



#[async_trait]
impl UnscriptedClient for ArrrClient {

  //TBD: put in its own class
  fn read_session_key(&mut self, s_key: &str, s_value: &mut String)
  {
    let local_value;  //str
    
    let data = fs::read_to_string("./client_session");
    
    let data = match data {
        Ok(file) => file,
        Err(_error) => {
            //println!("No session file found. Assuming new session");
            return;
        },
    };
    
    let split_data = data.split("\n");    
    
    //print!("Session {}:",s_key);
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

  fn write_session_key(&mut self, s_key: &str, s_value: &str)
  {  
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("./client_session")
        .unwrap();

    if let Err(e) = writeln!(file, "{}={}", s_key,s_value)
    {
      eprintln!("Couldn't write to file: {}", e);
    }
  }

  async fn generate_keys<Verifier: ScriptedVerifier>(&mut self, verifier: &mut Verifier) -> Vec<u8> {
    //println!("arrr/generate_keys()");
    
    //verifier.generate_keys_for_engine() set internal variables.
    
    //Need to initialise blockchain height during engine startup from the session data:
    let mut str_hex_arrr_engine_height = String::new();
    
    //Need to initialise verifier key1 from the session data.
    let mut str_hex_arrr_engine_nsk = String::new(); 
    let mut str_hex_arrr_engine_ask = String::new(); 
    let mut str_hex_btc_engine_b    = String::new(); 
    let mut str_hex_btc_engine_br   = String::new(); 
    
    let mut str_hex_verifier_dl_eq  = String::new();
    let mut str_hex_verifier_decryption_key = String::new();
    let mut str_hex_verifier_encryption_key = String::new();
    
    self.read_session_key("arrr_engine_height",       &mut str_hex_arrr_engine_height);
    self.read_session_key("arrr_engine_nsk",          &mut str_hex_arrr_engine_nsk);
    self.read_session_key("arrr_engine_ask",          &mut str_hex_arrr_engine_ask);
    self.read_session_key("btc_engine_b",            &mut str_hex_btc_engine_b);
    self.read_session_key("btc_engine_br",           &mut str_hex_btc_engine_br);    
    
    self.read_session_key("verifier_dl_eq",          &mut str_hex_verifier_dl_eq);    
    self.read_session_key("verifier_decryption_key", &mut str_hex_verifier_decryption_key);
    self.read_session_key("verifier_encryption_key", &mut str_hex_verifier_encryption_key);
    
    let ca_arrr_engine_nsk_crc;
    let ca_arrr_engine_ask_crc;
    let ca_btc_engine_b_crc;
    let ca_btc_engine_br_crc;
    let ca_verifier_dl_eq_crc;
    
    let dl_eq;
    
    if !str_hex_arrr_engine_height.is_empty()
    {
      let vec_value = hex::decode(str_hex_arrr_engine_height).unwrap();
      let str_value = String::from_utf8_lossy(&vec_value);
      let height  = str_value.parse::<isize>().unwrap();       
      let _result = self.engine.set_height_at_start(height).await;
    }
    else
    {
      let height : isize = self.engine.get_height_at_start();      
      let str_hex_arrr_engine_height = hex::encode( height.to_string() );      
      self.write_session_key("arrr_engine_height", &str_hex_arrr_engine_height);
    }
    
    //Arrr:
    if !str_hex_arrr_engine_nsk.is_empty()         &&
       !str_hex_verifier_dl_eq.is_empty()          &&
       !str_hex_verifier_decryption_key.is_empty() &&
       !str_hex_verifier_encryption_key.is_empty()
    {
      //println!("generate_keys() - Read from session");
     
      let ca_vec = hex::decode( str_hex_arrr_engine_nsk.clone() ).unwrap();
      let ca_bytes:&[u8] = &ca_vec;
      //Convert the [u8] to fixed size [u8;32]
      let mut ca32_bytes : [u8;32] = Default::default();
      ca32_bytes.copy_from_slice(&ca_bytes[0..32]);
      self.engine.nsk = JubjubEngine::bytes_to_private_key(ca32_bytes).unwrap(); 
      ca_arrr_engine_nsk_crc = State::<ARC>::calculate( &ca32_bytes[..]);
      //println!("session: arrr_engine.nsk");
      
      let ca_vec = hex::decode( str_hex_arrr_engine_ask.clone() ).unwrap();
      let ca_bytes:&[u8] = &ca_vec;
      //Convert the [u8] to fixed size [u8;32]
      let mut ca32_bytes : [u8;32] = Default::default();
      ca32_bytes.copy_from_slice(&ca_bytes[0..32]);
      let encrypption_key = JubjubEngine::bytes_to_private_key(ca32_bytes).unwrap(); 
      self.engine.ask = Some(encrypption_key);
      
      ca_arrr_engine_ask_crc = State::<ARC>::calculate( &ca32_bytes[..]);
      //println!("session: arrr_engine.ask");           
      
      dl_eq = hex::decode( str_hex_verifier_dl_eq.clone() ).unwrap();
      ca_verifier_dl_eq_crc  = State::<ARC>::calculate( &dl_eq[..]);
      //println!("session: verifier_dl_eq");            
      
      verifier.restore_private_variables(&str_hex_verifier_decryption_key, &str_hex_btc_engine_b, &str_hex_btc_engine_br);
      

      //BTC engine.b
      let ca_btc_engine_b       = verifier.Bpr();
      ca_btc_engine_b_crc   = State::<ARC>::calculate( &ca_btc_engine_b[..]);
                                
      //BTC engine.br           
      let ca_btc_engine_br      = verifier.BRpr();    
      ca_btc_engine_br_crc  = State::<ARC>::calculate( &ca_btc_engine_br[..]);            
    }
    else
    {
      //ARRR: engine.nsk
      self.engine.nsk = JubjubEngine::new_private_key();                                 //Generate a new key, regardless of object initialisation      
      let ca_engine_nsk = JubjubEngine::private_key_to_bytes(&self.engine.nsk.clone() ); //nsk      
      ca_arrr_engine_nsk_crc = State::<ARC>::calculate( &ca_engine_nsk[..]);
      str_hex_arrr_engine_nsk = hex::encode( ca_engine_nsk );//[u8] to hex_str
      self.write_session_key("arrr_engine_nsk", &str_hex_arrr_engine_nsk);        
    
      let (dl_eq2, encryption_key, decryption_key) = verifier.generate_keys_for_engine::<JubjubEngine>(PhantomData); 
      dl_eq = dl_eq2.clone();    
    
      //dl_eq
      str_hex_verifier_dl_eq = hex::encode( dl_eq.clone() );
      ca_verifier_dl_eq_crc  = State::<ARC>::calculate( &dl_eq[..]);
      self.write_session_key("verifier_dl_eq", &mut str_hex_verifier_dl_eq);

      //decryption_key
      str_hex_verifier_decryption_key = hex::encode( decryption_key.clone() );
      let ca_verifier_decryption_key_crc  = State::<ARC>::calculate( &decryption_key[..]);
      //println!("verifier decryption_key crc={:02x?}", ca_verifier_decryption_key_crc);
      self.write_session_key("verifier_decryption_key", &mut str_hex_verifier_decryption_key);
                    
      //encryption_key
      let ca32_bytes = JubjubEngine::get_scalar( &encryption_key ).to_bytes();
      str_hex_verifier_encryption_key = hex::encode( ca32_bytes ); //Scalar to [u8] to hex_str
      let ca_verifier_encryption_key_crc  = State::<ARC>::calculate( &ca32_bytes[..]);
      //println!("verifier encryption_key (engine.ask) crc={:02x?}", ca_verifier_encryption_key_crc);
      self.write_session_key("verifier_encryption_key", &str_hex_verifier_encryption_key);    
      self.engine.ask = Some(encryption_key);
      
      
      //ARRR: engine.ask
      let ca_arrr_engine_ask = JubjubEngine::private_key_to_bytes(&self.engine.ask.clone().unwrap() ); //ask      
      str_hex_arrr_engine_ask = hex::encode( ca_arrr_engine_ask );//[u8] to hex_str
      self.write_session_key("arrr_engine_ask", &str_hex_arrr_engine_ask); 
      ca_arrr_engine_ask_crc = State::<ARC>::calculate( &ca_arrr_engine_ask[..]);
      
      //BTC engine.b
      let ca_btc_engine_b       = verifier.Bpr();
      let str_hex_btc_engine_b  = hex::encode( ca_btc_engine_b );//[u8] to hex_str
      self.write_session_key("btc_engine_b", &str_hex_btc_engine_b);
      ca_btc_engine_b_crc       = State::<ARC>::calculate( &ca_btc_engine_b[..]);
                                
      //BTC engine.br           
      let ca_btc_engine_br      = verifier.BRpr();    
      let str_hex_btc_engine_br = hex::encode( ca_btc_engine_br );//[u8] to hex_str
      self.write_session_key("btc_engine_br", &str_hex_btc_engine_br);
      ca_btc_engine_br_crc      = State::<ARC>::calculate( &ca_btc_engine_br[..]);
    }
       
    let ca_destination_script= verifier.destination_script();
    let ca_destination_script_crc = State::<ARC>::calculate( &ca_destination_script[..]);    
    
    //println!("generate_keys(done)");
    //println!("  dleq crc=0x{:02x?}"              ,ca_verifier_dl_eq_crc);
    //println!("  arrr engine.nsk crc=0x{:02x?}"   ,ca_arrr_engine_nsk_crc);
    //println!("  arrr engine.ask crc=0x{:02x?}"   ,ca_arrr_engine_ask_crc);
    //println!("  btc engine_b  crc=0x{:02x?}"     ,ca_btc_engine_b_crc);
    //println!("  btc engine_br crc=0x{:02x?}"     ,ca_btc_engine_br_crc); 
    //println!("  destination_script crc=0x{:02x?}",ca_destination_script_crc);
    
    KeyBundle {
      dl_eq: bincode::serialize(
        &ZecKeys {
          dl_eq,
          nsk: JubjubEngine::private_key_to_bytes(&self.engine.nsk)
        }
      ).unwrap(),
      B: verifier.B(),
      BR: verifier.BR(),
      scripted_destination: verifier.destination_script()
    }.serialize()
  }

  fn verify_keys<Verifier: ScriptedVerifier>(&mut self, keys: &[u8], verifier: &mut Verifier) -> anyhow::Result<()> {
    let mut bundle: KeyBundle = bincode::deserialize(keys)?;
    let zec_keys: ZecKeys = bincode::deserialize(&bundle.dl_eq)?;
    bundle.dl_eq = zec_keys.dl_eq;
    self.engine.set_ak_nsk(
      &verifier.verify_keys_for_engine::<JubjubEngine>(&bincode::serialize(&bundle).unwrap(), PhantomData)?,
      &JubjubEngine::bytes_to_private_key(zec_keys.nsk)?
    );
    Ok(())
  }

  fn get_address(&mut self) -> String {
    self.engine.get_deposit_address()
  }

  async fn wait_for_deposit(&mut self, wait: bool) -> anyhow::Result<u8> {
    //println!("client.rs: 1 wait_for_deposit()");
    let vk = self.engine.vk.clone().expect("Getting the deposit before sharing keys");
    //println!("client.rs: 2 wait_for_deposit()");
    let result = self.engine.get_deposit(&vk, wait).await?;
    //println!("client.rs: 3 wait_for_deposit() amount: {}",result);
    
    if result == 0
    {
      self.deposited=false;
      Ok(0)
    }
    else
    {
      self.deposited=true;
      Ok(1)
    }    
  }

  async fn refund<Verifier: ScriptedVerifier>(self, verifier: Verifier) -> anyhow::Result<()> {
    if !self.deposited {
      Ok(())
    } else {
      if let Some(recovered_key) = verifier.claim_refund_or_recover_key().await? {
        self.engine.claim(
          JubjubEngine::little_endian_bytes_to_private_key(recovered_key)?,
          &self.engine.config.refund
        ).await?;
      }
      Ok(())
    }
  }

  #[cfg(test)]
  fn override_refund_with_random_address(&mut self) {
    let mut seed = [0; 32];
    OsRng.fill_bytes(&mut seed);
    self.refund_seed = seed;
    self.engine.config.refund = encode_payment_address(
      SAPLING_HRP,
      &ExtendedSpendingKey::master(&seed).default_address().expect("Couldn't get default address").1
    );
  }

  #[cfg(test)]
  async fn send_from_node(&mut self) -> anyhow::Result<()> {
    self.engine.send_from_wallet().await?;
    Ok(())
  }

  #[cfg(test)]
  async fn advance_consensus(&self) -> anyhow::Result<()> {
    self.engine.mine_block().await
  }

  #[cfg(test)]
  fn get_refund_address(&self) -> String {
    hex::encode(&self.refund_seed)
  }

  #[cfg(test)]
  async fn get_if_funded(mut self, address: &str) -> bool {
    let efvk: ExtendedFullViewingKey = (&ExtendedSpendingKey::master(hex::decode(address).unwrap()[..32].try_into().unwrap())).into();
    self.engine.get_deposit(&efvk.fvk.vk, false).await.expect("Couldn't get if a Transaction to a ViewKey exists").is_some()
  }
}
