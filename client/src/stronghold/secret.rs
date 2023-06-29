// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The [SecretManage] implementation for [StrongholdAdapter].

use std::ops::Range;

use async_trait::async_trait;
use crypto::{
    ciphers::{traits::Aead, aes_gcm::Aes256Gcm},
    hashes::{blake2b::Blake2b256, Digest},
    keys::x25519,
};
use iota_stronghold::{
    procedures::{self, AeadCipher, Chain, KeyType, Sha2Hash, Slip10DeriveInput},
    Location,
};
use iota_types::block::{
    address::{Address, Ed25519Address},
    signature::{Ed25519Signature, Signature},
    unlock::{SignatureUnlock, Unlock},
};
use zeroize::Zeroize;

use super::{
    common::{DERIVE_OUTPUT_RECORD_PATH, PRIVATE_DATA_CLIENT_PATH, SECRET_VAULT_PATH, SEED_RECORD_PATH},
    StrongholdAdapter,
};
use crate::{
    api::{EncryptedData, RemainderData},
    secret::{types::InputSigningData, GenerateAddressOptions, SecretManage},
    stronghold::common::{AEAD_SALT, DIFFIE_HELLMAN_OUTPUT_PATH, DIFFIE_HELLMAN_SHARED_KEY_PATH},
    Error, Result,
};

#[async_trait]
impl SecretManage for StrongholdAdapter {
    async fn generate_addresses(
        &self,
        coin_type: u32,
        account_index: u32,
        address_indexes: Range<u32>,
        internal: bool,
        _options: Option<GenerateAddressOptions>,
    ) -> Result<Vec<Address>> {
        // Prevent the method from being invoked when the key has been cleared from the memory. Do note that Stronghold
        // only asks for a key for reading / writing a snapshot, so without our cached key this method is invocable, but
        // it doesn't make sense when it comes to our user (signing transactions / generating addresses without a key).
        // Thus, we put an extra guard here to prevent this methods from being invoked when our cached key has
        // been cleared.
        if !self.is_key_available().await {
            return Err(Error::StrongholdKeyCleared);
        }

        // Stronghold arguments.
        let seed_location = Slip10DeriveInput::Seed(Location::generic(SECRET_VAULT_PATH, SEED_RECORD_PATH));
        let derive_location = Location::generic(SECRET_VAULT_PATH, DERIVE_OUTPUT_RECORD_PATH);

        // Addresses to return.
        let mut addresses = Vec::new();

        for address_index in address_indexes {
            let chain = Chain::from_u32_hardened(vec![44u32, coin_type, account_index, internal as u32, address_index]);

            // Derive a SLIP-10 private key in the vault.
            self.slip10_derive(chain, seed_location.clone(), derive_location.clone())
                .await?;

            // Get the Ed25519 public key from the derived SLIP-10 private key in the vault.
            let public_key = self.ed25519_public_key(derive_location.clone()).await?;

            // Hash the public key to get the address.
            let hash = Blake2b256::digest(public_key);

            // Convert the hash into [Address].
            let address = Address::Ed25519(Ed25519Address::new(hash.into()));

            // Collect it.
            addresses.push(address);
        }

        Ok(addresses)
    }

    async fn signature_unlock(
        &self,
        input: &InputSigningData,
        essence_hash: &[u8; 32],
        _: &Option<RemainderData>,
    ) -> Result<Unlock> {
        let chain = input.chain.as_ref().unwrap();
        let ed25519_sig = self.sign_ed25519(essence_hash, chain).await?;

        // Convert the raw bytes into [Unlock].
        let unlock = Unlock::Signature(SignatureUnlock::new(Signature::Ed25519(ed25519_sig)));

        Ok(unlock)
    }

    async fn sign_ed25519(&self, msg: &[u8], chain: &Chain) -> Result<Ed25519Signature> {
        // Prevent the method from being invoked when the key has been cleared from the memory. Do note that Stronghold
        // only asks for a key for reading / writing a snapshot, so without our cached key this method is invocable, but
        // it doesn't make sense when it comes to our user (signing transactions / generating addresses without a key).
        // Thus, we put an extra guard here to prevent this methods from being invoked when our cached key has
        // been cleared.
        if !self.is_key_available().await {
            return Err(Error::StrongholdKeyCleared);
        }

        // Stronghold arguments.
        let seed_location = Slip10DeriveInput::Seed(Location::generic(SECRET_VAULT_PATH, SEED_RECORD_PATH));
        let derive_location = Location::generic(SECRET_VAULT_PATH, DERIVE_OUTPUT_RECORD_PATH);

        // Stronghold asks for an older version of [Chain], so we have to perform a conversion here.
        let chain = {
            let raw: Vec<u32> = chain
                .segments()
                .iter()
                // XXX: "ser32(i)". RTFSC: [crypto::keys::slip10::Segment::from_u32()]
                .map(|seg| u32::from_be_bytes(seg.bs()))
                .collect();

            Chain::from_u32_hardened(raw)
        };

        // Derive a SLIP-10 private key in the vault.
        self.slip10_derive(chain, seed_location, derive_location.clone())
            .await?;

        // Get the Ed25519 public key from the derived SLIP-10 private key in the vault.
        let public_key = self.ed25519_public_key(derive_location.clone()).await?;
        let signature = self.ed25519_sign(derive_location, msg).await?;

        Ok(Ed25519Signature::new(public_key, signature))
    }
}

/// Private methods for the secret manager implementation.
impl StrongholdAdapter {
    /// Execute [Procedure::BIP39Recover] in Stronghold to put a mnemonic into the Stronghold vault.
    async fn bip39_recover(&self, mnemonic: String, passphrase: Option<String>, output: Location) -> Result<()> {
        self.stronghold
            .lock()
            .await
            .get_client(PRIVATE_DATA_CLIENT_PATH)?
            .execute_procedure(procedures::BIP39Recover {
                mnemonic,
                passphrase,
                output,
            })?;

        Ok(())
    }

    /// Execute [Procedure::SLIP10Derive] in Stronghold to derive a SLIP-10 private key in the Stronghold vault.
    async fn slip10_derive(&self, chain: Chain, input: Slip10DeriveInput, output: Location) -> Result<()> {
        if let Err(err) = self
            .stronghold
            .lock()
            .await
            .get_client(PRIVATE_DATA_CLIENT_PATH)?
            .execute_procedure(procedures::Slip10Derive { chain, input, output })
        {
            match err {
                iota_stronghold::procedures::ProcedureError::Engine(ref e) => {
                    // Custom error for missing vault error: https://github.com/iotaledger/stronghold.rs/blob/7f0a2e0637394595e953f9071fa74b1d160f51ec/client/src/types/error.rs#L170
                    if e.to_string().contains("does not exist") {
                        // Actually the seed, derived from the mnemonic, is not stored.
                        return Err(Error::StrongholdMnemonicMissing);
                    } else {
                        return Err(err.into());
                    }
                }
                _ => {
                    return Err(err.into());
                }
            }
        };

        Ok(())
    }

    /// Execute [Procedure::Ed25519PublicKey] in Stronghold to get an Ed25519 public key from the SLIP-10 private key
    /// located in `private_key`.
    pub async fn ed25519_public_key(&self, private_key: Location) -> Result<[u8; 32]> {
        Ok(self
            .stronghold
            .lock()
            .await
            .get_client(PRIVATE_DATA_CLIENT_PATH)?
            .execute_procedure(procedures::PublicKey {
                ty: KeyType::Ed25519,
                private_key,
            })?)
    }

    /// Execute [Procedure::Ed25519Sign] in Stronghold to sign `msg` with `private_key` stored in the Stronghold vault.
    pub async fn ed25519_sign(&self, private_key: Location, msg: &[u8]) -> Result<[u8; 64]> {
        Ok(self
            .stronghold
            .lock()
            .await
            .get_client(PRIVATE_DATA_CLIENT_PATH)?
            .execute_procedure(procedures::Ed25519Sign {
                private_key,
                msg: msg.to_vec(),
            })?)
    }

    /// Store a mnemonic into the Stronghold vault.
    pub async fn store_mnemonic(&mut self, mut mnemonic: String) -> Result<()> {
        // The key needs to be supplied first.
        if self.key_provider.lock().await.is_none() {
            return Err(Error::StrongholdKeyCleared);
        };

        // Stronghold arguments.
        let output = Location::generic(SECRET_VAULT_PATH, SEED_RECORD_PATH);

        // Trim the mnemonic, in case it hasn't been, as otherwise the restored seed would be wrong.
        let trimmed_mnemonic = mnemonic.trim().to_string();
        mnemonic.zeroize();

        // Check if the mnemonic is valid.
        crypto::keys::bip39::wordlist::verify(&trimmed_mnemonic, &crypto::keys::bip39::wordlist::ENGLISH)
            .map_err(|e| crate::Error::InvalidMnemonic(format!("{e:?}")))?;

        // We need to check if there has been a mnemonic stored in Stronghold or not to prevent overwriting it.
        if self
            .stronghold
            .lock()
            .await
            .get_client(PRIVATE_DATA_CLIENT_PATH)?
            .record_exists(&output)?
        {
            return Err(crate::Error::StrongholdMnemonicAlreadyStored);
        }

        // Execute the BIP-39 recovery procedure to put it into the vault (in memory).
        self.bip39_recover(trimmed_mnemonic, None, output).await?;

        // Persist Stronghold to the disk
        self.write_stronghold_snapshot(None).await?;

        Ok(())
    }

    /// Encrypt a data packet
    pub async fn x25519_encrypt(&mut self, public_key: x25519::PublicKey, private_key: Location, msg: Vec<u8>) -> Result<EncryptedData> {
        let client = self
            .stronghold
            .lock()
            .await
            .get_client(PRIVATE_DATA_CLIENT_PATH)?;

        let shared_key_path = Location::generic(DIFFIE_HELLMAN_SHARED_KEY_PATH, DIFFIE_HELLMAN_SHARED_KEY_PATH);
        let shared_output_path = Location::generic(DIFFIE_HELLMAN_OUTPUT_PATH, DIFFIE_HELLMAN_OUTPUT_PATH);

        // Retrieve the sender public key for inclusion in EncryptedData
        let pub_key_proc = procedures::PublicKey {
            ty: KeyType::X25519,
            private_key: private_key.clone(),
        };

        let sender_pub_key = client.execute_procedure(pub_key_proc)?;

        // Create a diffie hellman shared key exchange
        let dh_proc = procedures::X25519DiffieHellman {
            public_key: public_key.to_bytes(),
            private_key: private_key.clone(),
            shared_key: shared_key_path.clone(),
        };

        // Complete a KDF Concat procedure and encrypt the output with AEAD to make
        // pass to recipient in serialized form
        let kdf_proc = procedures::ConcatKdf {
            hash: Sha2Hash::Sha256,
            algorithm_id: "ECDH-ES".to_string(),
            shared_secret: shared_key_path,
            key_len: 32,
            apu: vec![],
            apv: vec![],
            pub_info: vec![],
            priv_info: vec![],
            output: shared_output_path.clone(),
        };

        let mut nonce = [0_u8; 12];
        crypto::utils::rand::fill(&mut nonce)?;

        let aed_encrypt = procedures::AeadEncrypt {
            cipher: AeadCipher::Aes256Gcm,
            associated_data: AEAD_SALT.to_vec(),
            plaintext: msg,
            nonce: nonce.to_vec(),
            key: shared_output_path,
        };

        client.execute_procedure_chained(vec![dh_proc.into(), kdf_proc.into()])?;
        let mut resp = client.execute_procedure(aed_encrypt)?;

        let mut tag = [0u8; 16];
        let mut data = [0u8; 32];
        tag.clone_from_slice(&resp.drain(..Aes256Gcm::TAG_LENGTH).collect::<Vec<u8>>());
        data.clone_from_slice(resp.as_slice());

        Ok(EncryptedData::new(
            sender_pub_key,
            nonce,
            tag,
            data,
        ))
    }

    /// Decrypt a data packet
    pub async fn x25519_decrypt(&mut self, private_key: Location, msg: EncryptedData) -> Result<Vec<u8>> {
        let client = self
            .stronghold
            .lock()
            .await
            .get_client(PRIVATE_DATA_CLIENT_PATH)?;

        let shared_key_path = Location::generic(DIFFIE_HELLMAN_SHARED_KEY_PATH, DIFFIE_HELLMAN_SHARED_KEY_PATH);
        let shared_output_path = Location::generic(DIFFIE_HELLMAN_OUTPUT_PATH, DIFFIE_HELLMAN_OUTPUT_PATH);

        // Create a diffie hellman shared key exchange
        let dh_proc = procedures::X25519DiffieHellman {
            public_key: msg.public_key,
            private_key: private_key.clone(),
            shared_key: shared_key_path.clone(),
        };

        // Complete a KDF Concat procedure
        let kdf_proc = procedures::ConcatKdf {
            hash: Sha2Hash::Sha256,
            algorithm_id: "ECDH-ES".to_string(),
            shared_secret: shared_key_path,
            key_len: 32,
            apu: vec![],
            apv: vec![],
            pub_info: vec![],
            priv_info: vec![],
            output: shared_output_path.clone(),
        };

        client.execute_procedure_chained(vec![dh_proc.into(), kdf_proc.into()])?;

        // Decrypt AEAD Encrypted Data packet and return the message within
        let aed_decrypt = procedures::AeadDecrypt {
            cipher: AeadCipher::Aes256Gcm,
            associated_data: AEAD_SALT.as_ref().to_vec(),
            ciphertext: msg.ciphertext.to_vec(),
            tag: msg.tag.to_vec(),
            nonce: msg.nonce.to_vec(),
            key: shared_output_path,
        };

        Ok(client.execute_procedure(aed_decrypt)?)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::constants::IOTA_COIN_TYPE;

    #[tokio::test]
    async fn test_address_generation() {
        let stronghold_path = "test_address_generation.stronghold";
        // Remove potential old stronghold file
        std::fs::remove_file(stronghold_path).unwrap_or(());
        let mnemonic = String::from(
            "giant dynamic museum toddler six deny defense ostrich bomb access mercy blood explain muscle shoot shallow glad autumn author calm heavy hawk abuse rally",
        );
        let mut stronghold_adapter = StrongholdAdapter::builder()
            .password("drowssap")
            .build(stronghold_path)
            .unwrap();

        stronghold_adapter.store_mnemonic(mnemonic).await.unwrap();

        // The snapshot should have been on the disk now.
        assert!(Path::new(stronghold_path).exists());

        let addresses = stronghold_adapter
            .generate_addresses(IOTA_COIN_TYPE, 0, 0..1, false, None)
            .await
            .unwrap();

        assert_eq!(
            addresses[0].to_bech32("atoi"),
            "atoi1qpszqzadsym6wpppd6z037dvlejmjuke7s24hm95s9fg9vpua7vluehe53e".to_string()
        );

        // Remove garbage after test, but don't care about the result
        std::fs::remove_file(stronghold_path).unwrap_or(());
    }

    #[tokio::test]
    async fn test_key_cleared() {
        let stronghold_path = "test_key_cleared.stronghold";
        // Remove potential old stronghold file
        std::fs::remove_file(stronghold_path).unwrap_or(());
        let mnemonic = String::from(
            "giant dynamic museum toddler six deny defense ostrich bomb access mercy blood explain muscle shoot shallow glad autumn author calm heavy hawk abuse rally",
        );
        let mut stronghold_adapter = StrongholdAdapter::builder()
            .password("drowssap")
            .build(stronghold_path)
            .unwrap();

        stronghold_adapter.store_mnemonic(mnemonic).await.unwrap();

        // The snapshot should have been on the disk now.
        assert!(Path::new(stronghold_path).exists());

        stronghold_adapter.clear_key().await;

        // Address generation returns an error when the key is cleared.
        assert!(
            stronghold_adapter
                .generate_addresses(IOTA_COIN_TYPE, 0, 0..1, false, None,)
                .await
                .is_err()
        );

        stronghold_adapter.set_password("drowssap").await.unwrap();

        // After setting the correct password it works again.
        let addresses = stronghold_adapter
            .generate_addresses(IOTA_COIN_TYPE, 0, 0..1, false, None)
            .await
            .unwrap();

        assert_eq!(
            addresses[0].to_bech32("atoi"),
            "atoi1qpszqzadsym6wpppd6z037dvlejmjuke7s24hm95s9fg9vpua7vluehe53e".to_string()
        );

        // Remove garbage after test, but don't care about the result
        std::fs::remove_file(stronghold_path).unwrap_or(());
    }
}
