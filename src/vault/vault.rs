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
use lnpbp::bitcoin::secp256k1::{PublicKey, SecretKey};
use lnpbp::bitcoin::util::bip32::{
    DerivationPath, ExtendedPrivKey, ExtendedPubKey, KeyApplication,
};
use lnpbp::bp::chain::{AssetId, Chain};

use super::{driver, keymgm::Error, Driver, FileDriver, Keyring, KeysAccount};
use crate::api::types::AccountInfo;
use crate::error::{BootstrapError, RuntimeError};

pub struct Vault {
    driver: Box<dyn Driver>,
    keyrings: Vec<Keyring>,
}

impl Vault {
    pub fn new(config: &driver::Config) -> Result<Self, BootstrapError> {
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
        name: String,
        description: Option<String>,
        chain: &Chain,
        application: KeyApplication,
        encryption_key: PublicKey,
    ) -> Result<(), RuntimeError> {
        let description = description.unwrap_or("".to_string());
        let keyring = Keyring::with(
            name.clone(),
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
        name: String,
        details: String,
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
        unimplemented!()
    }

    pub fn xpriv(
        &self,
        id: XpubIdentifier,
    ) -> Result<ExtendedPrivKey, RuntimeError> {
        unimplemented!()
    }

    pub fn rpc_sign_psbt(&self) -> Result<ExtendedPrivKey, RuntimeError> {
        unimplemented!()
    }

    pub fn rpc_sign_key(&self) -> Result<ExtendedPrivKey, RuntimeError> {
        unimplemented!()
    }

    pub fn rpc_sign_data(&self) -> Result<ExtendedPrivKey, RuntimeError> {
        unimplemented!()
    }
}
