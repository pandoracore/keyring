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

//! Storage drivers for private key vault

use lnpbp::bitcoin::hash_types::XpubIdentifier;
use lnpbp::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint};
use lnpbp::bitcoin::util::psbt::PartiallySignedTransaction;

use crate::api::types::Key;
use crate::error::RuntimeError;

pub trait Vault: Send + Sync {
    type Error: ::std::error::Error + Into<RuntimeError>;

    fn open_or_create<T>(config: T) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn list(&self, root: Option<XpubIdentifier>) -> Result<Vec<Key>, Self::Error>;
    fn seed(&mut self) -> Result<(), Self::Error>;
    fn derive(&mut self, root: XpubIdentifier, path: DerivationPath) -> Result<Key, Self::Error>;
    fn xpub(&self, id: XpubIdentifier) -> Result<ExtendedPubKey, Self::Error>;

    fn unlock(&self, password: &mut str) -> Result<UnlockedVault, Self::Error>;
}

pub struct UnlockedVault {
    xprivkey: ExtendedPrivKey,
}

impl UnlockedVault {
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
