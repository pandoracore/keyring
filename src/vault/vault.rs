// Keyring: private/public key managing service
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the AGPL License
// along with this software.
// If not, see <https://www.gnu.org/licenses/agpl-3.0-standalone.html>.

use std::collections::HashSet;

use lnpbp::bitcoin::hash_types::XpubIdentifier;
use lnpbp::bitcoin::hashes::{sha256, Hash};
use lnpbp::bitcoin::secp256k1::{PublicKey, SecretKey, Signature};
use lnpbp::bitcoin::util::bip32::{
    DerivationPath, ExtendedPrivKey, ExtendedPubKey,
};
use lnpbp::bitcoin::util::psbt::PartiallySignedTransaction;
use lnpbp::bp::bip32::KeyApplication;
use lnpbp::bp::chain::{AssetId, Chain};

use super::{driver, keymgm::Error, Driver, FileDriver, Keyring, KeysAccount};
use crate::error::{BootstrapError, RuntimeError};
use crate::rpc::types::AccountInfo;

pub struct Vault {
    driver: Box<dyn Driver>,
    keyrings: Vec<Keyring>,
}

impl Vault {
    pub fn with(config: &driver::Config) -> Result<Self, BootstrapError> {
        let mut driver = match config {
            driver::Config::File(fdc) => FileDriver::init(fdc)?,
        };
        let keyrings = driver.load()?;
        Ok(Self {
            driver: Box::new(driver),
            //keyrings: vec![],
            keyrings,
        })
    }

    pub fn keyring_by_id(&self, key_id: XpubIdentifier) -> Option<&Keyring> {
        self.keyrings.iter().find(|kr| kr.identifier() == key_id)
    }

    pub fn keyring_by_id_mut(
        &mut self,
        key_id: XpubIdentifier,
    ) -> Option<&mut Keyring> {
        self.keyrings
            .iter_mut()
            .find(|kr| kr.identifier() == key_id)
    }

    pub fn account_by_id(
        &self,
        key_id: XpubIdentifier,
    ) -> Option<&KeysAccount> {
        self.keyrings.iter().find_map(|kr| kr.account_by_id(key_id))
    }
}

// API implementation
impl Vault {
    pub fn list(&self) -> Result<Vec<AccountInfo>, RuntimeError> {
        let mut list: Vec<_> =
            self.keyrings.iter().map(AccountInfo::from).collect();
        list.extend(self.keyrings.iter().flat_map(|keyring| {
            keyring
                .sub_accounts()
                .iter()
                .map(|(path, account)| {
                    let mut info = AccountInfo::from(account);
                    info.key_source =
                        Some((keyring.fingerprint(), path.clone()));
                    info
                })
                .collect::<Vec<_>>()
        }));
        Ok(list)
    }

    pub fn seed(
        &mut self,
        name: impl ToString,
        description: Option<impl ToString>,
        chain: &Chain,
        application: KeyApplication,
        encryption_key: PublicKey,
    ) -> Result<(), RuntimeError> {
        let description =
            description.map(|s| s.to_string()).unwrap_or_default();
        let keyring = Keyring::with(
            name.to_string(),
            description.clone(),
            chain,
            application,
            None,
            encryption_key,
        )?;
        self.keyrings.push(keyring);
        trace!(
            "New keyring created from a seed; total number of keyring is {}",
            self.keyrings.len()
        );
        self.driver.store(&self.keyrings)?;
        Ok(())
    }

    pub fn derive(
        &mut self,
        root: XpubIdentifier,
        path: DerivationPath,
        name: impl ToString,
        details: Option<impl ToString>,
        assets: HashSet<AssetId>,
        decryption_key: &mut SecretKey,
    ) -> Result<AccountInfo, RuntimeError> {
        let keyring = self.keyring_by_id_mut(root).ok_or(Error::NotFound)?;
        let account = keyring.create_account(
            path,
            name,
            details,
            assets,
            decryption_key,
        )?;
        let info = AccountInfo::from(account);
        self.driver.store(&self.keyrings)?;
        Ok(info)
    }

    pub fn xpub(
        &self,
        id: XpubIdentifier,
    ) -> Result<ExtendedPubKey, RuntimeError> {
        Ok(*self.account_by_id(id).ok_or(Error::NotFound)?.xpubkey())
    }

    pub fn xpriv(
        &self,
        id: XpubIdentifier,
        mut decryption_key: &mut SecretKey,
    ) -> Result<ExtendedPrivKey, RuntimeError> {
        Ok(self
            .account_by_id(id)
            .ok_or(Error::NotFound)?
            .xprivkey(&mut decryption_key)?)
    }

    pub fn sign_psbt(
        &self,
        _psbt: PartiallySignedTransaction,
        _decryption_key: &mut SecretKey,
    ) -> Result<PartiallySignedTransaction, RuntimeError> {
        /* TODO: Implement
        debug!("Signing PSBT using all private keys from account {}", id);
        let account = self.account_by_id(id).ok_or(Error::NotFound)?;
        trace!("Keys account for key id is found: {}", account);
        let pubkey = account.xpubkey().public_key;
        trace!("Public key used for signing: {}", pubkey);
        let digest = sha256::Hash::hash(&pubkey.key.serialize());
        trace!("Signing key digest {}", digest);
        Ok(account.sign_psbt(digest, decryption_key)?) */
        unimplemented!()
    }

    pub fn sign_key(
        &self,
        id: XpubIdentifier,
        mut decryption_key: &mut SecretKey,
    ) -> Result<Signature, RuntimeError> {
        debug!(
            "Signing public key with id {} using corresponding private key",
            id
        );
        let account = self.account_by_id(id).ok_or(Error::NotFound)?;
        trace!("Keys account for key id is found: {}", account);
        let pubkey = account.xpubkey().public_key;
        trace!("Public key used for signing: {}", pubkey);
        let digest = sha256::Hash::hash(&pubkey.key.serialize());
        trace!("Signing key digest {}", digest);
        Ok(account.sign_digest(digest, &mut decryption_key)?)
    }

    pub fn sign_data(
        &self,
        id: XpubIdentifier,
        data: &[u8],
        mut decryption_key: &mut SecretKey,
    ) -> Result<Signature, RuntimeError> {
        let account = self.account_by_id(id).ok_or(Error::NotFound)?;
        Ok(account
            .sign_digest(sha256::Hash::hash(&data), &mut decryption_key)?)
    }
}
