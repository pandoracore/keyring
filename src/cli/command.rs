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

use lnpbp::bitcoin::hashes::hex::{FromHex, ToHex};
use lnpbp::bitcoin::util::bip32::DerivationPath;
use lnpbp::bitcoin::XpubIdentifier;
use lnpbp::service::Exec;
use lnpbp::strict_encoding::strict_encode;

use super::{Error, Runtime};
use crate::api;
use crate::api::Reply;

/// Command-line commands:
///
///     keyring-cli seed create
///     keyring-cli seed import <fingerprint>
///     keyring-cli seed export <fingerprint> <file>
///
///     keyring-cli xpubkey list [<fingerprint>]
///     keyring-cli xpubkey derive <fingerprint> <derivation_path>
///     keyring-cli xpubkey export <fingerprint> <file>
///
///     keyring-cli xprivkey export <fingerprint> <file>
///     
///     keyring-cli sign <in_file> <out_file>
///
#[derive(Clap, Clone, Debug, Display)]
#[display_from(Debug)]
pub enum Command {
    /// Seed operations: generation, import, export
    Seed {
        /// Subcommand specifying particular operation
        #[clap(subcommand)]
        subcommand: SeedCommand,
    },

    /// Operations with extended public keys
    Xpubkey {
        /// Subcommand specifying particular operation
        #[clap(subcommand)]
        subcommand: XPubkeyCommand,
    },

    /// Operations with extended private keys
    Xprivkey {
        /// Subcommand specifying particular operation
        #[clap(subcommand)]
        subcommand: XPrivkeyCommand,
    },

    /// Signs given PSBT bitcoin transaction with the matching keys
    Sign { in_file: String, out_file: String },
}

#[derive(Clap, Clone, Debug, Display)]
#[display_from(Debug)]
pub enum SeedCommand {
    Create {
        /// Name for newly generated account with a seed phrase
        #[clap()]
        name: String,

        /// More details information about the new account
        #[clap(short, long)]
        details: Option<String>,
    },

    Import {
        #[clap(parse(try_from_str = FromHex::from_hex))]
        id: XpubIdentifier,
    },

    Export {
        #[clap(parse(try_from_str = FromHex::from_hex))]
        id: XpubIdentifier,

        file: String,
    },
}

#[derive(Clap, Clone, Debug, Display)]
#[display_from(Debug)]
pub enum XPubkeyCommand {
    List {
        #[clap(short, long, arg_enum, default_value = "yaml")]
        format: DataFormat,
    },

    Derive {
        #[clap(parse(try_from_str = FromHex::from_hex))]
        id: XpubIdentifier,

        path: DerivationPath,
    },

    Export {
        #[clap(parse(try_from_str = FromHex::from_hex))]
        id: XpubIdentifier,

        file: String,
    },
}

#[derive(Clap, Clone, Debug, Display)]
#[display_from(Debug)]
pub enum XPrivkeyCommand {
    Export {
        #[clap(parse(try_from_str = FromHex::from_hex))]
        id: XpubIdentifier,

        file: String,
    },
}

#[derive(Clap, Clone, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum DataFormat {
    /// JSON
    Json,

    /// YAML
    Yaml,

    /// TOML
    Toml,

    /// Strict encoding - hex representation
    StrictHex,

    /// Strict encoding - base64 representation
    StrictBase64,
}

impl Exec for Command {
    type Runtime = Runtime;
    type Error = Error;

    #[inline]
    fn exec(&self, runtime: &mut Runtime) -> Result<(), Error> {
        match self {
            Command::Seed { subcommand } => subcommand.exec(runtime),
            Command::Xpubkey { subcommand } => subcommand.exec(runtime),
            Command::Xprivkey { subcommand } => subcommand.exec(runtime),
            Command::Sign { in_file, out_file } => self.exec_sign(runtime, in_file, out_file),
        }
    }
}

impl Exec for SeedCommand {
    type Runtime = Runtime;
    type Error = Error;

    #[inline]
    fn exec(&self, runtime: &mut Runtime) -> Result<(), Error> {
        match self {
            SeedCommand::Create { name, details } => {
                self.exec_create(runtime, name.clone(), details.clone())
            }
            SeedCommand::Import { id } => self.exec_import(runtime, id),
            SeedCommand::Export { id, file } => self.exec_export(runtime, id, file),
        }
    }
}

impl Exec for XPubkeyCommand {
    type Runtime = Runtime;
    type Error = Error;

    #[inline]
    fn exec(&self, runtime: &mut Runtime) -> Result<(), Error> {
        match self {
            XPubkeyCommand::List { format } => self.exec_list(runtime, format),
            XPubkeyCommand::Derive { id, path } => self.exec_derive(runtime, id, path),
            XPubkeyCommand::Export { id, file } => self.exec_export(runtime, id, file),
        }
    }
}

impl Exec for XPrivkeyCommand {
    type Runtime = Runtime;
    type Error = Error;

    #[inline]
    fn exec(&self, runtime: &mut Runtime) -> Result<(), Error> {
        match self {
            XPrivkeyCommand::Export { id, file } => self.exec_export(runtime, id, file),
        }
    }
}

impl Command {
    pub fn exec_sign(
        &self,
        runtime: &mut Runtime,
        in_file: &str,
        out_file: &str,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

impl SeedCommand {
    pub fn exec_create(
        &self,
        runtime: &mut Runtime,
        name: String,
        description: Option<String>,
    ) -> Result<(), Error> {
        debug!("Creating new seed");
        let reply = runtime.request(api::Request::Seed(api::message::Seed {
            auth_code: 0,
            name,
            description,
        }))?;
        match reply.as_ref() {
            Reply::Success => {
                info!("New seed created");
                Ok(())
            }
            Reply::Failure(failure) => Err(Error::ServerFailure(failure.clone())),
            _ => Err(Error::UnexpectedServerResponse),
        }
    }

    pub fn exec_import(&self, runtime: &mut Runtime, id: &XpubIdentifier) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn exec_export(
        &self,
        runtime: &mut Runtime,
        id: &XpubIdentifier,
        file: &str,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

impl XPubkeyCommand {
    pub fn exec_list(&self, runtime: &mut Runtime, format: &DataFormat) -> Result<(), Error> {
        const ERR: &'static str = "Error formatting data";

        debug!("Listing known accounts/extended public keys");
        let reply = runtime.request(api::Request::List)?;
        match reply.as_ref() {
            Reply::Keylist(accounts) => {
                let result = match format {
                    DataFormat::Json => serde_json::to_string(accounts).expect(ERR),
                    DataFormat::Yaml => serde_yaml::to_string(accounts).expect(ERR),
                    DataFormat::Toml => toml::to_string(accounts).expect(ERR),
                    DataFormat::StrictHex => strict_encode(accounts).expect(ERR).to_hex(),
                    DataFormat::StrictBase64 => base64::encode(strict_encode(accounts).expect(ERR)),
                };
                println!("{}", result);
                Ok(())
            }
            Reply::Failure(failure) => Err(Error::ServerFailure(failure.clone())),
            _ => Err(Error::UnexpectedServerResponse),
        }
    }

    pub fn exec_derive(
        &self,
        runtime: &mut Runtime,
        id: &XpubIdentifier,
        path: &DerivationPath,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn exec_export(
        &self,
        runtime: &mut Runtime,
        id: &XpubIdentifier,
        file: &str,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

impl XPrivkeyCommand {
    pub fn exec_export(
        &self,
        runtime: &mut Runtime,
        id: &XpubIdentifier,
        file: &str,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}
