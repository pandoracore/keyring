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

use super::{file_driver, Account};
use crate::error::BootstrapError;

pub trait Driver: Send + Sync {
    fn init(config: &dyn Any) -> Result<Self, BootstrapError>
    where
        Self: Sized;
    fn load(&mut self) -> Result<Vec<Account>, Error>;
    fn store(&mut self, accounts: &Vec<Account>) -> Result<(), Error>;
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Serialize, Deserialize)]
#[serde(tag = "driver")]
#[display_from(Debug)]
#[non_exhaustive]
pub enum Config {
    File(file_driver::Config),
    // Terezor,
    // Ledger,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
pub struct Error(String);

impl<T> From<T> for Error
where
    T: ::std::error::Error,
{
    fn from(err: T) -> Self {
        Self(format!("{:?}", err))
    }
}
