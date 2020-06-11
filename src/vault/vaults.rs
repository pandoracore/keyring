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
use lnpbp::bitcoin::secp256k1::SecretKey;
use lnpbp::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint};
use lnpbp::bitcoin::util::psbt::PartiallySignedTransaction;

use super::{driver, file_driver, Account, Driver, FileDriver};
use crate::api::types::Key;
use crate::error::{BootstrapError, RuntimeError};

pub struct Vault {
    driver: Box<dyn Driver>,
    keyrings: Vec<Keyring>,
    accounts: Vec<Account>,
}

impl Vault {
    pub fn new(config: &driver::Config) -> Result<Self, BootstrapError> {
        let driver = match config {
            driver::Config::File(fdc) => FileDriver::init(fdc)?,
        };
        Ok(Self {
            driver: Box::new(driver),
            keyrings: vec![],
            accounts: vec![],
        })
    }

    pub fn list(&self, root: Option<XpubIdentifier>) -> Result<Vec<Key>, RuntimeError> {
        unimplemented!()
    }

    pub fn seed(&mut self) -> Result<(), RuntimeError> {
        let account = Account::new();
        self.accounts.push(account);
        self.driver.store(&self.accounts)?;
        Ok(())
    }

    pub fn derive(
        &mut self,
        root: XpubIdentifier,
        path: DerivationPath,
    ) -> Result<Key, RuntimeError> {
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
