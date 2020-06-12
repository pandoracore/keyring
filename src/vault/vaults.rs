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

use lnpbp::bitcoin::hash_types::XpubIdentifier;
use lnpbp::bitcoin::secp256k1::{PublicKey, SecretKey};
use lnpbp::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint};
use lnpbp::bitcoin::util::psbt::PartiallySignedTransaction;

use super::{driver, file_driver, Account, Driver, FileDriver};
use crate::api::types::AccountInfo;
use crate::error::{BootstrapError, RuntimeError};

pub struct Vault {
    driver: Box<dyn Driver>,
    keyrings: Vec<Keyring>,
    accounts: Vec<Account>,
}

impl Vault {
    pub fn new(config: &driver::Config) -> Result<Self, BootstrapError> {
        let mut driver = match config {
            driver::Config::File(fdc) => FileDriver::init(fdc)?,
        };
        let accounts = driver.load()?;
        Ok(Self {
            driver: Box::new(driver),
            keyrings: vec![],
            accounts,
        })
    }

    pub fn list(&self) -> Result<Vec<AccountInfo>, RuntimeError> {
        Ok(self
            .accounts
            .iter()
            .map(|account| {
                let details = match account.details().len() {
                    0 => None,
                    _ => Some(account.details().clone()),
                };
                AccountInfo {
                    id: account.id(),
                    name: account.name().clone(),
                    details,
                    xpubkey: account.xpubkey().clone(),
                    path: account.derivation().clone(),
                    fingerprint: account.fingerprint(),
                }
            })
            .collect())
    }

    pub fn seed(
        &mut self,
        name: String,
        description: Option<String>,
        encryption_key: &PublicKey,
    ) -> Result<(), RuntimeError> {
        let account = Account::new(
            name,
            description.unwrap_or("".to_string()),
            None,
            encryption_key,
        );
        self.accounts.push(account);
        trace!(
            "New account created from a seed; total number of accounts {}",
            self.accounts.len()
        );
        self.driver.store(&self.accounts)?;
        Ok(())
    }

    pub fn derive(
        &mut self,
        root: XpubIdentifier,
        path: DerivationPath,
    ) -> Result<AccountInfo, RuntimeError> {
        unimplemented!()
    }

    pub fn xpub(&self, id: XpubIdentifier) -> Result<ExtendedPubKey, RuntimeError> {
        unimplemented!()
    }

    pub fn lock(&self) {
        unimplemented!()
    }

    pub fn unlock(
        &self,
        id: XpubIdentifier,
        unlock: &mut SecretKey,
    ) -> Result<Keyring, RuntimeError> {
        unimplemented!()
    }
}

pub struct Keyring {
    xprivkey: ExtendedPrivKey,
}

impl Keyring {
    pub fn xpriv(&self, id: XpubIdentifier) -> Result<ExtendedPrivKey, RuntimeError> {
        unimplemented!()
    }

    pub fn sign(
        &self,
        psbt: PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction, RuntimeError> {
        unimplemented!()
    }

    pub fn wipe(&mut self) {
        unimplemented!()
    }
}
