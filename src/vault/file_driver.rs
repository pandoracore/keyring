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

use ::core::any::Any;
use ::std::collections::BTreeMap;
use ::std::fs;
use ::std::path::PathBuf;

use lnpbp::bitcoin::XpubIdentifier;

use super::Driver;
use crate::error::{BootstrapError, RuntimeError};
use crate::Vault;

#[derive(Debug, Display)]
#[display_from(Debug)]
pub struct FileDriver {
    fd: fs::File,
    //table: BTreeMap<XpubIdentifier, u64>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Serialize, Deserialize)]
#[display_from(Debug)]
pub struct Config {
    pub location: PathBuf,
    pub format: FileFormat,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display, Serialize, Deserialize)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum FileFormat {
    StrictEncoded,
    Yaml,
    Toml,
    Json,
}

impl Driver for FileDriver {
    type Error = RuntimeError;

    fn init(config: &dyn Any) -> Result<Self, BootstrapError> {
        let config = config
            .downcast_ref::<Config>()
            .expect("`FileDriver` must be configured with `file_driver::Config` object");
        info!("Initializing file storage at {:?}", &config.location);
        let fd = fs::File::with_options()
            .write(true)
            .create(true)
            .open(&config.location)?;
        Ok(Self { fd })
    }

    fn index(&self) -> Result<Vec<XpubIdentifier>, Self::Error> {
        unimplemented!()
    }

    fn load(&self, id: XpubIdentifier) -> Result<Vault, Self::Error> {
        unimplemented!()
    }

    fn store(&mut self, vault: &Vault) -> Result<bool, Self::Error> {
        unimplemented!()
    }
}
