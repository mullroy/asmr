use std::{
  marker::PhantomData,
  convert::{TryInto, TryFrom},
  path::Path,
  fs::File
};

use async_trait::async_trait;
use crc16::*;
use sha2::Digest;

use bitcoin::{
  secp256k1,
  hash_types::Txid,
  blockdata::{script::Script, transaction::{OutPoint, TxIn, TxOut, Transaction}},
  util::{address::Address, bip143::SighashComponents},
  consensus::{serialize, deserialize}
};

use crate::{
  crypt_engines::{KeyBundle, CryptEngine, secp256k1_engine::Secp256k1Engine},
  dl_eq::DlEqProof,
  coins::{
    ScriptedVerifier,
    btc::{engine::*, rpc::BtcRpc}
  }
};

pub struct BtcVerifier {
  engine: BtcEngine,
  rpc: BtcRpc,
  destination: String,
  destination_script: Script,

  host: Option<Vec<u8>>,
  host_refund: Option<Vec<u8>>,
  host_refund_script: Option<Script>,

  swap_hash: Option<Vec<u8>>,

  pub decryption_key: Option<<Secp256k1Engine as CryptEngine>::PrivateKey>,          //Make pub to initialise direclty from client Implementing a wrapper function is probably better
  pub encryption_key: Option<<Secp256k1Engine as CryptEngine>::PublicKey>,           //Make pub to initialise direclty from client. Implementing a wrapper function is probably better
  encrypted_spend_sig: Option<<Secp256k1Engine as CryptEngine>::EncryptedSignature>,

  lock_id: Option<Txid>,
  lock_value: Option<u64>,
  lock_height: Option<isize>,

  refund_script: Option<Script>,
  refund: Option<Transaction>,
  buy: Option<Transaction>
}

impl BtcVerifier {
  pub fn new(config_path: &String) -> anyhow::Result<BtcVerifier> {
    let config = serde_json::from_reader(File::open(config_path)?)?;

    Ok(BtcVerifier {
      engine: BtcEngine::new(),
      rpc: BtcRpc::new(&config)?,
      destination: config.destination.clone(),
      destination_script: BtcEngine::decode_address(&config.destination)?,

      host: None,
      host_refund: None,
      host_refund_script: None,

      swap_hash: None,

      decryption_key: None,
      encryption_key: None,
      encrypted_spend_sig: None,

      lock_id: None,
      lock_value: None,
      lock_height: None,

      refund_script: None,
      refund: None,
      buy: None
    })
  }

  async fn attempt_key_recovery(&self, refund_address: &str) -> Option<[u8; 32]> {
    let mut history = self.rpc.get_address_history(refund_address).await;
    // This hopefully has deterministic ordering, and should only ever have a quantity of 1 or 2
    // Therefore, this algorithm is a bit overkill
    if history.len() != 1 {
      let mut refund_spend = history.remove(0).tx;
      while refund_spend.txid() == self.refund.as_ref().expect("Trying to recover key from the refund claim despite not knowing the refund").txid() {
        refund_spend = history.remove(0).tx;
      }
      let decrypted = secp256k1::Signature::from_der(
        &refund_spend.input[0].witness[1][0 .. refund_spend.input[0].witness[1].len() - 1]
      ).expect("Published BTC transaction has an invalid signature").serialize_compact().to_vec();

      Some(
        Secp256k1Engine::private_key_to_little_endian_bytes(
          &Secp256k1Engine::recover_key(
            self.encryption_key.as_ref().expect("Recovering key despite not having stored the encryption key"),
            self.encrypted_spend_sig.as_ref().expect("Recovering key despite not having encrypted a signature"),
            &Secp256k1Engine::bytes_to_signature(&decrypted).expect("Published BTC transaction has an invalid signature")
          ).expect("Couldn't recover the private key")
        )
      )
    } else {
      None
    }
  }
}

#[async_trait]
impl ScriptedVerifier for BtcVerifier {
  fn destination_script(&self) -> Vec<u8> {
    self.destination_script.to_bytes()
  }

  //This function used when restoring the object variables from a stored session
  fn restore_private_variables(&mut self, str_hex_decryption_key: &String, str_hex_btc_engine_b: &String, str_hex_btc_engine_br: &String )
  {
    //From scripted (BTC), to reach the unscripted engine (Arrr), we need a bridge function here:
    if str_hex_decryption_key.len() == 0 ||
       str_hex_btc_engine_b.len() == 0   ||
       str_hex_btc_engine_br.len() == 0
    {
      //println!("btc/verifiers.rs restore_private_variables() The input is empty");
      return;
    }

    //println!("restore_private_variables\n  str_hex_decryption_key {}\n  str_hex_btc_engine_b {}\n  str_hex_btc_engine_br {}", str_hex_decryption_key, str_hex_btc_engine_b, str_hex_btc_engine_br);
    //Restore decryption_key
    let ca_vec = hex::decode(str_hex_decryption_key).unwrap();
    let ca_bytes:&[u8] = &ca_vec;
    let mut ca32_bytes : [u8;32] = Default::default();
    ca32_bytes.copy_from_slice(&ca_bytes[0..32]);      
    self.decryption_key =  Some(Secp256k1Engine::bytes_to_private_key(ca32_bytes).unwrap());
    let ca_decrypt_key_crc = State::<ARC>::calculate( &ca32_bytes[..]);
    
    //BTC engine: b
    let ca_vec = hex::decode(str_hex_btc_engine_b).unwrap();
    let ca_bytes:&[u8] = &ca_vec;
    let mut ca32_bytes : [u8;32] = Default::default();
    ca32_bytes.copy_from_slice(&ca_bytes[0..32]);      
    self.engine.b =  Secp256k1Engine::bytes_to_private_key(ca32_bytes).unwrap();
    //let ca_btc_engine_b_crc = State::<ARC>::calculate( &ca32_bytes[..]);
    
    //BTC engine: br    
    let ca_vec = hex::decode(str_hex_btc_engine_br).unwrap();
    let ca_bytes:&[u8] = &ca_vec;
    let mut ca32_bytes : [u8;32] = Default::default();
    ca32_bytes.copy_from_slice(&ca_bytes[0..32]);      
    self.engine.br =  Secp256k1Engine::bytes_to_private_key(ca32_bytes).unwrap();
    //let ca_btc_engine_br_crc = State::<ARC>::calculate( &ca32_bytes[..]);    
    
    //println!("restore_private_variables():\n  decryption_key crc={:02x?}", ca_decrypt_key_crc );
  }  
  
  fn generate_keys_for_engine<OtherCrypt: CryptEngine>(&mut self, _: PhantomData<&OtherCrypt>) -> (Vec<u8>, OtherCrypt::PrivateKey, [u8;32]) {
    //println!("btc/verifier.rs generate_keys_for_engine()");
    let (proof, key1, key2) = DlEqProof::<Secp256k1Engine, OtherCrypt>::new();
    self.decryption_key = Some(key1.clone() );
    
    let ca_decrypt_key =  Secp256k1Engine::private_key_to_bytes(&self.decryption_key.as_ref().unwrap() );
    let ca_decrypt_key_crc = State::<ARC>::calculate( &ca_decrypt_key[..]);
    let ca_key2        =  OtherCrypt::private_key_to_bytes( &key2 );
    let proof_crc = State::<ARC>::calculate( &proof.serialize()[..]);
    //println!("  proof len={}, crc={:02x?}\n  decryption_key crc={:02x?}\n  encryption_key(key2)={:02x?}", proof.serialize().len(), proof_crc, ca_decrypt_key_crc, ca_key2);
    
    (proof.serialize(), key2, ca_decrypt_key)
  }

  fn verify_keys_for_engine<OtherCrypt: CryptEngine>(&mut self, keys: &[u8], _: PhantomData<&OtherCrypt>) -> anyhow::Result<OtherCrypt::PublicKey> {
    let bundle = KeyBundle::deserialize(keys)?;
    let dleq = DlEqProof::<OtherCrypt, Secp256k1Engine>::deserialize(&bundle.dl_eq)?;
    let (key1, key2) = dleq.verify()?;
    self.host = Some(bundle.B);
    self.host_refund = Some(bundle.BR);
    self.host_refund_script = Some(Script::from(bundle.scripted_destination));
    self.encryption_key = Some(key2);
    Ok(key1)
  }

  fn B(&self) -> Vec<u8> {
    Secp256k1Engine::public_key_to_bytes(&Secp256k1Engine::to_public_key(&self.engine.b))
  }

  fn BR(&self) -> Vec<u8> {
    Secp256k1Engine::public_key_to_bytes(&Secp256k1Engine::to_public_key(&self.engine.br))
  }
  
  fn Bpr(&self) -> [u8;32] {
    Secp256k1Engine::private_key_to_bytes(&self.engine.b)
  }

  fn BRpr(&self) -> [u8;32] {
    Secp256k1Engine::private_key_to_bytes(&self.engine.br)
  }

  async fn complete_refund_and_prepare_spend(
    &mut self,
    lock_and_host_signed_refund: &[u8],    
    pca_encrypted_sign_r1 : &[u8;32],                    //Random data / swap. Generate with r = Scalar::random(&mut OsRng);
    pca_encrypted_sign_r2 : &[u8;32]                     //Random data / swap. Generate with r = Scalar::random(&mut OsRng);
  ) -> anyhow::Result<Vec<u8>> {
    //println!("btc/verifiers.rs complete_refund_and_prepare_spend()");
    let host_refund = self.host_refund.as_ref().expect("Completing refund before verifying keys");
    let lock_and_refund: LockAndRefundInfo = bincode::deserialize(lock_and_host_signed_refund)?;

    let our_fee_per_byte: i64 = self.rpc.get_fee_per_byte().await?.try_into().expect("Fee per byte is greater than 2^63");
    let variance = our_fee_per_byte / 10; // 10% variance
    if (our_fee_per_byte - i64::try_from(lock_and_refund.fee_per_byte)?).abs() > variance {
      anyhow::bail!("Used fee per byte outside of acceptable variance.");
    }

    self.engine.create_lock_script(
      &lock_and_refund.swap_hash,
      false,
      self.host.as_ref().expect("Completing refund before verifying keys"),
      host_refund
    );
    self.swap_hash = Some(lock_and_refund.swap_hash);    

    let lock_id = deserialize(&lock_and_refund.lock_id)?;
    let (refund_script, mut refund, refund_msg, refund_sig) = self.engine.prepare_and_sign_refund(
      lock_id,
      false,
      host_refund,
      &self.B(),
      lock_and_refund.value,
      lock_and_refund.fee_per_byte
    )?;
    self.lock_id = Some(lock_id);
    self.lock_value = Some(lock_and_refund.value);
    self.refund_script = Some(refund_script);
    
    let swap_hash_crc     = State::<ARC>::calculate( &self.swap_hash.clone().unwrap()[..]);      
    let lock_id_crc       = State::<ARC>::calculate( &self.lock_id .clone().unwrap()[..]);         
    let refund_script_crc = State::<ARC>::calculate( &self.refund_script.clone().unwrap()[..]);                          

    let ca_bytes   = serialize( &refund.clone() ); //bitcoin::Transaction
    let mut refund_crc = State::<ARC>::calculate( &ca_bytes[..]); 
    
    let refund_msg_crc    = State::<ARC>::calculate( &refund_msg[..]); 
    let refund_sig_crc    = State::<ARC>::calculate( &refund_sig[..]); 
    
    //println!("swap_hash_crc={:02x?},lock_id_crc={:02x?},lock_value={:02x?},refund_script_crc={:02x?}, refund_crc={:02x?} (#1), refund_msg_crc={:02x?}, refund_sig_crc={:02x?}",
    //          swap_hash_crc,        lock_id_crc,        self.lock_value.clone().unwrap(), refund_script_crc, refund_crc, refund_msg_crc, refund_sig_crc);   

    SECP.verify(
      &refund_msg,
      &secp256k1::Signature::from_der(&lock_and_refund.host_refund_signature)?,
      &secp256k1::PublicKey::from_slice(self.host_refund.as_ref().expect("Completing refund despite not knowing the host's refund key"))?
    )?;

    let spend = BtcEngine::prepare_spend(
      refund.txid(),
      self.host_refund_script.clone().expect("Preparing spend despite not knowing the host's refund script"),
      refund.output[0].value,
      lock_and_refund.fee_per_byte
    )?;
    let components = SighashComponents::new(&spend);
    
   
    let mut ca_bytes  = serialize( &spend.clone() );                  //bitcoin::Transaction
    let spend_crc     = State::<ARC>::calculate( &ca_bytes[..]); 
    //println!("spend crc={:02x?}",spend_crc);

    let mut struct_secp256k1_engine = Secp256k1Engine { ca_encrypted_sign_r1 : *pca_encrypted_sign_r1, 
                                                        ca_encrypted_sign_r2 : *pca_encrypted_sign_r2 };

    let encrypted_spend_sig_typed = Secp256k1Engine::encrypted_sign(&mut struct_secp256k1_engine,
      &self.engine.br,
      self.encryption_key.as_ref().expect("Attempted to generate encrypted sign before verifying dleq proof"),
      &components.sighash_all(
        &spend.input[0],
        &Script::from(self.engine.refund_script_bytes.clone().expect("Preparing spend before knowing refund script")),
        refund.output[0].value
      )
    )?;    
    let encrypted_spend_sig = Secp256k1Engine::encrypted_signature_to_bytes(&encrypted_spend_sig_typed);
    self.encrypted_spend_sig = Some(encrypted_spend_sig_typed);
    
    let encrypted_spend_sig_crc = State::<ARC>::calculate( &encrypted_spend_sig.clone()[..]);
    //println!("encrypted_spend_sig crc={:02x?}",encrypted_spend_sig_crc);
    
    refund.input[0].witness = vec![
      Vec::new(),
      refund_sig.clone(),
      lock_and_refund.host_refund_signature,
      Vec::new(),
      self.engine.lock_script_bytes.clone().expect("Completing refund despite not knowing the lock script")
    ];
    refund.input[0].witness[1].push(1);
    refund.input[0].witness[2].push(1);
    self.refund = Some( refund.clone() );
    
    ca_bytes = serialize( &refund.clone() );                  //bitcoin::Transaction
    refund_crc     = State::<ARC>::calculate( &ca_bytes[..]); 
    //println!("refund crc={:02x?} #2",refund_crc);
    

    Ok(bincode::serialize(&ClientRefundAndSpendSignatures {
      refund_signature: refund_sig,
      encrypted_spend_signature: encrypted_spend_sig
    }).expect("Couldn't serialize the client's refund and spend signatures"))
  }

  fn verify_prepared_buy(&mut self, buy_info: &[u8]) -> anyhow::Result<String> {
    //println!("verify_prepared_buy()");
    let host_bytes = self.host.as_ref().expect("Verifying and waiting for lock before verifying their keys");
    let lock_id = self.lock_id.expect("Finishing our buy before knowing the lock's ID");

    let buy_info: BuyInfo = bincode::deserialize(buy_info)?;
    if !cfg!(test) {
      print!("You will receive {} satoshis. Continue (yes/no)? ", buy_info.value);
      //std::io::stdout().flush().expect("Failed to flush stdout");
      //let mut line = String::new();
      //std::io::stdin().read_line(&mut line).expect("Couldn't read from stdin");
      //if !line.to_lowercase().starts_with("y") {
      //  anyhow::bail!("User didn't confirm BTC amount");
      //}
    }

    let mut buy: Transaction = Transaction {
      version: 2,
      lock_time: 0,
      input: vec![
        TxIn {
          previous_output: OutPoint {
            txid: lock_id,
            vout: 0
          },
          script_sig: Script::new(),
          sequence: 0xFFFFFFFF,
          witness: Vec::new()
        }
      ],
      output: vec![
        TxOut {
          script_pubkey: self.destination_script.clone(),
          value: buy_info.value
        }
      ]
    };

    let components = SighashComponents::new(&buy);
    let buy_message = secp256k1::Message::from_slice(
      &components.sighash_all(
        &buy.input[0],
        self.engine.lock_script(),
        self.lock_value.expect("Finishing our buy before knowing the lock's value")
      )
    )?;

    let decrypted_signature = secp256k1::Signature::from_compact(
      &Secp256k1Engine::signature_to_bytes(
        &Secp256k1Engine::decrypt_signature(
          &Secp256k1Engine::bytes_to_encrypted_signature(&buy_info.encrypted_signature)?,
          self.decryption_key.as_ref().expect("Attempted to finish verifier before generate_keys called")
        )?
      )
    )?;
    SECP.verify(
      &buy_message,
      &decrypted_signature,
      &secp256k1::PublicKey::from_slice(&host_bytes)?
    )?;

    let signature = SECP.sign(
      &buy_message,
      &secp256k1::SecretKey::from_slice(
        &Secp256k1Engine::private_key_to_bytes(&self.engine.b)
      ).expect("Secp256k1Engine generated an invalid secp256k1 key")
    ).serialize_der();

    buy.input[0].witness = vec![
      Vec::new(),
      signature.to_vec(),
      decrypted_signature.serialize_der().to_vec(),
      Vec::new(),
      vec![1],
      self.engine.lock_script_bytes.clone().expect("Finishing despite not knowing the lock script")
    ];
    buy.input[0].witness[1].push(1);
    buy.input[0].witness[2].push(1);
    self.buy = Some( buy.clone() );

    let ca_vec = serialize( &buy.clone() );
    let ca_bytes:&[u8] = &ca_vec;
    let str_hex_buy = hex::encode(ca_bytes.clone() );
    
    let ca_buy_crc = State::<ARC>::calculate( &ca_bytes[..]);
    //println!("Buy crc:{:02x?}",ca_buy_crc);
    
    Ok( str_hex_buy )
  }

  async fn verify_and_wait_for_lock(
    &mut self,
    wait: bool    
  ) -> anyhow::Result<isize> {    
    //println!("btc/verifier.rs verify_and_wait_for_lock()");
    
    self.lock_height=Some(0);
    
    let lock_address = Address::p2wsh(self.engine.lock_script(), NETWORK).to_string();

    let mut history = self.rpc.get_address_history(&lock_address).await;
    
    let mut i_counter = 0;
    while history.len() == 0 {
      history = self.rpc.get_address_history(&lock_address).await;
      tokio::time::delay_for(std::time::Duration::from_secs(10)).await;
      
      //If wait==true, block until the lock is detected.
      //If wait==false, poll for 20 seconds and return with lock_height==0
      if !wait
      {
        i_counter+=1;
        if (i_counter>=2) //20 seconds
        {
          break;
        }
      }
    }
    if history.len() != 1 {
      anyhow::bail!("Lock and refund doesn't exist");
    }

    // Verify the lock. Simply getting it by the script hash verifies the lock script is used
    // We mainly need to check metadata, verify the TX uses SegWit, and find out what vout we're using
    let lock = history.remove(0).tx;
    if lock.txid() != self.lock_id.expect("Waiting for lock despite not knowing its ID") {
      anyhow::bail!("Only one transaction to this address exists but it isn't the lock.");
    }
    BtcEngine::verify_meta_and_inputs(lock.clone())?;
    // Workaround for the fact we don't track vouts
    // Given the way this PoC operates, this is acceptable behavior
    // Turning into a longer term app, or one seeking interop with other implementations, would benefit from removing this limitation
    if lock.output.len() != 1 {
      anyhow::bail!("Lock didn't have the expected output set.");
    }

    // Wait for the lock to confirm
    if cfg!(feature = "no_confs") {
      self.lock_height = Some(self.rpc.get_height().await);
    } else {
      let mut confirmations = -1;
      while confirmations < CONFIRMATIONS {
        tokio::time::delay_for(std::time::Duration::from_secs(20)).await;

        history = self.rpc.get_address_history(&lock_address).await;
        // Verify the refund still hasn't been broadcasted in this time period
        if history.len() != 1 {
          anyhow::bail!("Refund was broadcasted");
        }
        // Update the amount of confirmations.
        confirmations = history[0].confirmations;
      }
      self.lock_height = Some(history[0].height);
    }

    Ok( self.lock_height.unwrap() )
  }

  fn restore_lock_height (&mut self, i_height : isize) {
    self.lock_height = Some(i_height);
  }

  async fn claim_refund_or_recover_key(mut self) -> anyhow::Result<Option<[u8; 32]>> {
    let lock_height = self.lock_height.expect("Trying to publish refund despite no lock on chain");
    //println!("claim_refund_or_recover_key: height={}",lock_height.clone());
    while self.rpc.get_height().await < (lock_height + (T0 as isize)) {
      tokio::time::delay_for(std::time::Duration::from_secs(20)).await;
    }
    //println!("claim_refund_or_recover_key: rpc height confirmed");

    let refund = self.refund.as_ref().expect("Trying to get the refund despite not having a refund transaction");

    // Ignore this result
    // Publishing an existing transaction can cause an error
    let _ = self.rpc.publish(&serialize(refund)).await;

    let refund_script = self.refund_script.as_ref().expect("Trying to recover key despite not having a refund transaction");
    let refund_address = Address::p2wsh(refund_script, NETWORK).to_string();
    loop {
      #[cfg(test)]
      for _ in 0 .. T0 {
        self.rpc.mine_block().await?;
      }

      let history = self.rpc.get_address_history(&refund_address).await;
      if (history.len() > 0) && ((history[0].confirmations) >= CONFIRMATIONS) {
        break;
      }
      tokio::time::delay_for(std::time::Duration::from_secs(20)).await;
    }
    let refund_height = self.rpc.get_height().await;

    while self.rpc.get_height().await < (refund_height + (T1 as isize)) {
      #[cfg(test)]
      for _ in 0 .. T1 {
        self.rpc.mine_block().await?;
      }

      // Check if host spent refund
      if let Some(recovered_key) = self.attempt_key_recovery(&refund_address).await {
        return Ok(Some(recovered_key));
      }
    }

    let mut claim = Transaction {
      version: 2,
      lock_time: 0,
      input: vec![
        TxIn {
          previous_output: OutPoint {
            txid: refund.txid(),
            vout: 0
          },
          script_sig: Script::new(),
          sequence: T1 as u32,
          witness: vec![
            vec![0; 65],
            Vec::new(),
            refund_script.to_bytes()
          ]
        }
      ],
      output: vec![
        TxOut {
          script_pubkey: self.destination_script.clone(),
          value: refund.output[0].value
        }
      ]
    };
    let fee = ((claim.get_weight() as u64) / 4) * self.rpc.get_fee_per_byte().await?;
    claim.output[0].value = claim.output[0].value.checked_sub(fee)
      .ok_or_else(|| anyhow::anyhow!("Not enough Bitcoin to pay for {} sats of fees", fee))?;

    let components = SighashComponents::new(&claim);
    claim.input[0].witness[0] = SECP.sign(
      &secp256k1::Message::from_slice(
        &components.sighash_all(
          &claim.input[0],
          &refund_script,
          refund.output[0].value
        )
      )?,
      &secp256k1::SecretKey::from_slice(
        &Secp256k1Engine::private_key_to_bytes(&self.engine.b)
      ).expect("Secp256k1Engine generated an invalid secp256k1 key")
    ).serialize_der().to_vec();
    claim.input[0].witness[0].push(1);

    let _ = self.rpc.publish(&serialize(&claim)).await;
    let claim_id = claim.txid();

    // Wait for a confirmation
    loop {
      #[cfg(test)]
      self.rpc.mine_block().await?;

      let destination_history = self.rpc.get_address_history(&self.destination).await;
      let mut found = false;
      for tx in destination_history {
        if (tx.tx.txid()) == (claim_id.clone()) {
          found = true;
          if (tx.confirmations) >= CONFIRMATIONS {
            return Ok(None);
          }
        }
      }

      // Transaction was beat
      if !found {
        if let Some(recovered_key) = self.attempt_key_recovery(&refund_address).await {
          return Ok(Some(recovered_key));
        } else {
          anyhow::bail!("Transaction was beat/disappeared and we failed to recover the key");
        }
      }
    }
  }

  async fn finish(&self, swap_secret: &[u8] ) -> anyhow::Result<(Vec<u8>,Vec<u8>)> {
    // Verify the received swap secret
    if sha2::Sha256::digest(swap_secret).to_vec() != self.swap_hash.clone().expect("Trying to finish our buy before knowing the swap hash") {
      anyhow::bail!("Received an invalid swap secret");
    }
    // Check that we aren't nearing the end of the timelock
    let lock_height = self.lock_height.expect("Attempted to finish swap before verifying lock confirmation");
    if self.rpc.get_height().await - lock_height >= SWAP_CUTOFF_BLOCKS {
      //anyhow::bail!("Attempted to finish swap, but we're nearing the end of the timelock");
      //println!("Attempted to finish swap, but we're nearing the end of the timelock. More than {} blocks have elapsed", SWAP_CUTOFF_BLOCKS);
    }
    
    let mut buy = self.buy.clone().expect("Finishing before verifying buy");
    buy.input[0].witness[3] = swap_secret.to_vec();
    self.rpc.publish(&serialize(&buy.clone() )).await?;
    
    let ca_buy = serialize(&buy.clone() );
    let ca_buy_txid = buy.txid();
    
//    //println!("txid: {}",buy.txid() );

    Ok( (ca_buy,ca_buy_txid.to_vec() ) )
  }
}
