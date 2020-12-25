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

//! Private key vault that uses delegated methods

use ::core::any::Any;
use std::os::raw::{c_int, c_uchar};

use super::{driver, Driver, Keyring};
use crate::error::BootstrapError;

pub type LoadCallback = unsafe extern "C" fn(
    xpubkey: *const c_uchar,
    xprivkey: *mut c_uchar,
) -> c_int;
pub type SaveCallback = unsafe extern "C" fn(
    xpubkey: *const c_uchar,
    xprivkey: *mut c_uchar,
) -> c_int;

#[derive(Debug, Display)]
#[display(Debug)]
pub struct DelegatedDriver {
    config: Config,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(
    crate = "serde_crate",
    from = "ConfigSerializer",
    into = "ConfigSerializer"
)]
pub struct Config {
    pub load_cb: LoadCallback,

    pub save_cb: SaveCallback,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(crate = "serde_crate")]
struct ConfigSerializer {}

impl From<ConfigSerializer> for Config {
    fn from(_: ConfigSerializer) -> Self {
        panic!("Delegated driver config can't be serialized")
    }
}

impl From<Config> for ConfigSerializer {
    fn from(_: Config) -> Self {
        ConfigSerializer {}
    }
}

impl Driver for DelegatedDriver {
    fn init(config: &dyn Any) -> Result<Self, BootstrapError> {
        let config = config.downcast_ref::<Config>().expect(
            "`FileDriver` must be configured with `delegated::Config` object",
        ).clone();
        info!("Initializing delegated driver for the vault");
        Ok(Self { config })
    }

    fn load(&mut self) -> Result<Vec<Keyring>, driver::Error> {
        debug!("Loading vault from delegate");
        Ok(vec![])
    }

    fn store(&mut self, accounts: &Vec<Keyring>) -> Result<(), driver::Error> {
        debug!("Storing vault data to the valut");
        trace!("Vault data stored");
        Ok(())
    }
}
