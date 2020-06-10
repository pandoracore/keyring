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

//! File storage drivers for private key vault

use lnpbp::bitcoin::hash_types::XpubIdentifier;
use lnpbp::bitcoin::util::bip32::{DerivationPath, ExtendedPubKey};

use super::Vault;
use crate::api::types::Key;
use crate::error::RuntimeError;
use crate::vault::UnlockedVault;

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct FileVault {}

impl Vault for FileVault {
    type Error = RuntimeError;

    fn open_or_create<T>(config: T) -> Result<Self, Self::Error> {
        unimplemented!()
    }

    fn list(&self, root: Option<XpubIdentifier>) -> Result<Vec<Key>, Self::Error> {
        unimplemented!()
    }

    fn seed(&mut self) -> Result<(), Self::Error> {
        unimplemented!()
    }

    fn derive(&mut self, root: XpubIdentifier, path: DerivationPath) -> Result<Key, Self::Error> {
        unimplemented!()
    }

    fn xpub(&self, id: XpubIdentifier) -> Result<ExtendedPubKey, Self::Error> {
        unimplemented!()
    }

    fn unlock(&self, password: &mut str) -> Result<UnlockedVault, Self::Error> {
        unimplemented!()
    }
}
