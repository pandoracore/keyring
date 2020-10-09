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
use ::std::fs;
use ::std::io;
use ::std::io::{Read, Seek, Write};
use ::std::path::Path;

use lnpbp::strict_encoding::{StrictDecode, StrictEncode};

use super::{driver, Driver, Keyring};
use crate::error::BootstrapError;

#[derive(Debug, Display)]
#[display(Debug)]
pub struct FileDriver {
    fd: fs::File,
    config: Config,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Serialize, Deserialize)]
#[display(Debug)]
pub struct Config {
    pub location: String,
    pub format: FileFormat,
}

#[derive(
    Copy, Clone, PartialEq, Eq, Hash, Debug, Display, Serialize, Deserialize,
)]
#[display(Debug)]
#[non_exhaustive]
pub enum FileFormat {
    StrictEncoded,
    Yaml,
    Toml,
    Json,
}

impl Driver for FileDriver {
    fn init(config: &dyn Any) -> Result<Self, BootstrapError> {
        let config = config.downcast_ref::<Config>().expect(
            "`FileDriver` must be configured with `file_driver::Config` object",
        );
        info!(
            "Initializing file driver for vault in {:?}",
            &config.location
        );
        let exists = Path::new(&config.location).exists();
        let fd = fs::File::with_options()
            .read(true)
            .write(true)
            .create(!exists)
            .open(&config.location)?;
        let mut me = Self {
            fd,
            config: config.clone(),
        };
        if !exists {
            warn!("Vault file does not exist: initializing empty vault");
            me.store(&vec![])?;
        }
        Ok(me)
    }

    fn load(&mut self) -> Result<Vec<Keyring>, driver::Error> {
        debug!("Loading vault from {}", self.config.location);
        self.fd.seek(io::SeekFrom::Start(0))?;
        trace!(
            "Parsing vault data (expected format {})",
            self.config.format
        );
        let accounts = match self.config.format {
            FileFormat::StrictEncoded => {
                Vec::<Keyring>::strict_decode(&mut self.fd)?
            }
            FileFormat::Yaml => serde_yaml::from_reader(&mut self.fd)?,
            FileFormat::Toml => {
                let mut data: Vec<u8> = vec![];
                self.fd.read_to_end(&mut data)?;
                toml::from_slice(&data)?
            }
            FileFormat::Json => serde_json::from_reader(&mut self.fd)?,
        };
        trace!("Vault loaded: {:?}", accounts);
        Ok(accounts)
    }

    fn store(&mut self, accounts: &Vec<Keyring>) -> Result<(), driver::Error> {
        debug!(
            "Storing vault data to the file {} in {} format",
            self.config.location, self.config.format
        );
        trace!("Current vault data: {:?}", accounts);
        self.fd.seek(io::SeekFrom::Start(0))?;
        self.fd.set_len(0)?;
        match self.config.format {
            FileFormat::StrictEncoded => {
                accounts.strict_encode(&mut self.fd)?;
            }
            FileFormat::Yaml => {
                serde_yaml::to_writer(&mut self.fd, accounts)?;
            }
            FileFormat::Toml => {
                let data = toml::to_vec(accounts)?;
                self.fd.write_all(&data)?;
            }
            FileFormat::Json => {
                serde_json::to_writer(&mut self.fd, accounts)?;
            }
        };
        trace!("Vault data stored");
        Ok(())
    }
}
