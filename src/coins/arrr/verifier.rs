use std::{
  marker::PhantomData,
  path::Path,
  fs::File
};

use crc16::*;
use async_trait::async_trait;

use crate::{
  crypt_engines::{CryptEngine, jubjub_engine::JubjubEngine},
  dl_eq::DlEqProof,
  coins::{
    UnscriptedVerifier, ScriptedHost,
    arrr::engine::*
  }
};

pub struct ArrrVerifier(ArrrEngine);

impl ArrrVerifier {
  pub async fn new(config_path: &String) -> anyhow::Result<ArrrVerifier> {
    //println!("coins/arrr/verifier.rs new()");
    Ok(ArrrVerifier(ArrrEngine::new(serde_json::from_reader(File::open(config_path)?)?).await?))
  }
}

#[async_trait]
impl UnscriptedVerifier for ArrrVerifier {

  //This function used when restoring the object variables from a stored session
  async fn restore_private_variables(&mut self, str_hex_engine_nsk: &String, str_hex_engine_ask: &String, str_hex_engine_height: &String)
  {
    //From scripted (BTC), to reach the unscripted engine (Arrr), we need a bridge function here:
    if str_hex_engine_nsk.len() == 0 ||
       str_hex_engine_ask.len() == 0 ||
       str_hex_engine_height.len() == 0
    {
      //println!("arrr/verifiers.rs One of the inputs are empty");
      return;
    }

    //Restore engine nsk
    let ca_vec = hex::decode(str_hex_engine_nsk).unwrap();
    let ca_bytes:&[u8] = &ca_vec;
    let mut ca32_bytes : [u8;32] = Default::default();
    ca32_bytes.copy_from_slice(&ca_bytes[0..32]);   
    self.0.nsk = JubjubEngine::bytes_to_private_key(ca32_bytes).unwrap();
    
    //Restore engine ask   
    //Conver the 64 char hex array to 32 bytes [u8]
    let ca_vec = hex::decode( str_hex_engine_ask.clone() ).unwrap();
    let ca_bytes:&[u8] = &ca_vec;
    //Convert the [u8] to fixed size [u8;32]
    let mut ca32_bytes : [u8;32] = Default::default();
    ca32_bytes.copy_from_slice(&ca_bytes[0..32]);
    //Assign the key    
    self.0.ask = Some(JubjubEngine::bytes_to_private_key(ca32_bytes).unwrap());
    
    //Restore engine height
    let ca_vec = hex::decode(str_hex_engine_height).unwrap();
    let str_value = String::from_utf8_lossy(&ca_vec);
    let height  = str_value.parse::<isize>().unwrap(); 
    let _result = self.0.set_height_at_start(height).await;
   
    //println!("restore_private_variables:\n  ARR: nsk={:02x?}\n  ask={:02x?}\n  height={}", self.0.nsk, self.0.ask, height);
  }
  
  fn generate_keys_for_engine<OtherCrypt: CryptEngine>(&mut self, _: PhantomData<&OtherCrypt>) -> 
                                                      (Vec<u8>, [u8;32], OtherCrypt::PrivateKey, [u8;32], isize) {
    //println!("arrr/verifier.rs generate_keys_for_engine()");
    let (proof, key1, key2) = DlEqProof::<JubjubEngine, OtherCrypt>::new();
    self.0.ask = Some(key1);                                       //For session restore, set ask in verify_dleq_for_engine()   
    
    let proof_crc = State::<ARC>::calculate( &proof.serialize()[..]);
    let ca_ask =  JubjubEngine::private_key_to_bytes(&self.0.ask.as_ref().unwrap() );
    
    let i_height = self.0.get_height_at_start();
    
    //println!("  nsk={:02x?}\n  ask(key1)={:02x?}\n  proof len={}, crc={:02x?}", self.0.nsk, ca_ask, proof.serialize().len(), proof_crc);    
    (
      bincode::serialize(
        &ZecKeys {
          dl_eq: proof.serialize(),
          nsk: JubjubEngine::private_key_to_bytes(&self.0.nsk)     //nsk
        }
      ).unwrap(),
      JubjubEngine::private_key_to_bytes(&self.0.nsk),              //nsk
      key2,                                                         //ak
      ca_ask,                                                       //ask
      i_height                                                      //Arrr blockchain height at startup
    )
  }

  fn verify_dleq_for_engine<OtherCrypt: CryptEngine>(&mut self, dleq: &[u8], _: PhantomData<&OtherCrypt>) -> anyhow::Result<OtherCrypt::PublicKey> {
    let keys: ZecKeys = bincode::deserialize(dleq)?;
    let dleq = DlEqProof::<OtherCrypt, JubjubEngine>::deserialize(&keys.dl_eq)?;
    let (key1, key2) = dleq.verify()?;
    
    self.0.set_ak_nsk( 
      &key2,
      &JubjubEngine::bytes_to_private_key(keys.nsk)?
    );        
    Ok(key1)
  }

  async fn verify_and_wait_for_send(&mut self, wait: bool) -> anyhow::Result<u8> {  
    //println!("verify_and_wait_for_send()");
    
    let vk = self.0.vk.clone().expect("Getting the deposit before sharing keys");

    //  ak: JubjubEngine::add_public_key
    //  nk: JubjubEngine::mul_by_proof_generation_generator(&self.nsk)
    let _vk_ak = vk.clone().ak;
    let _vk_nk = vk.clone().nk;
    
    let result = self.0.get_deposit(&vk, wait).await?;  //Fixit : Cant we replace this with the transaction ID?
                                                        //If the block is missed on the blockchain then the transaction is missed?
    if result == 0
    {
      return Ok(0);
    }
    if !cfg!(test) {
      println!("You will receive {} atomic units of ARRR. Continue (yes/no)? ", result);  //FIXIT: The amounts must be exchanged beforehand and automatically evaluated
      //std::io::stdout().flush().expect("Failed to flush stdout");
      //let mut line = String::new();
      //std::io::stdin().read_line(&mut line).expect("Couldn't read from stdin");
      //if !line.to_lowercase().starts_with("y") {
      //  anyhow::bail!("User didn't confirm ARRR amount");
      //}
    }

    Ok(1)
  }

  async fn finish<Host: ScriptedHost>(&mut self, host: &Host) -> anyhow::Result<()> {
    // Called to set the diversifier
    let address = self.0.get_deposit_address();
    
    //println!("Deposit address: {}", address );
    let final_key= host.recover_final_key().await?;
    //println!("Final key: {:02x?}",final_key.clone());
    //println!("Destination:{}",self.0.config.destination.clone());
    
    self.0.claim(
      JubjubEngine::little_endian_bytes_to_private_key(final_key)?,
      &self.0.config.destination
    ).await
  }
}
