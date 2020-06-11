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

use ::core::any::Any;
use lnpbp::bitcoin::hash_types::XpubIdentifier;

use super::file_driver;
use super::Vault;
use crate::error::{BootstrapError, RuntimeError};

pub trait Driver: Send + Sync {
    type Error: ::std::error::Error + Into<RuntimeError>;

    fn init(config: &dyn Any) -> Result<Self, BootstrapError>
    where
        Self: Sized;
    fn index(&self) -> Result<Vec<XpubIdentifier>, Self::Error>;
    fn load(&self, id: XpubIdentifier) -> Result<Vault, Self::Error>;
    fn store(&mut self, vault: &Vault) -> Result<bool, Self::Error>;
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Serialize, Deserialize)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum Config {
    File(file_driver::Config),
    // Terezor,
    // Ledger,
}
