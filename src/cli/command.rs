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
use lnpbp::bitcoin::util::bip32::{DerivationPath, KeyApplications};
use lnpbp::bitcoin::XpubIdentifier;
use lnpbp::bp::Chain;
use lnpbp::service::Exec;
use lnpbp::strict_encoding::strict_encode;

use super::Runtime;
use crate::api;
use crate::api::Reply;

pub trait TryFromStr
where
    Self: Sized,
{
    type Error: std::error::Error;
    fn try_from_str(s: &str) -> Result<Self, Self::Error>;
}

/// Error for an unknown enum representation; either string or numeric
#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Error)]
#[display_from(Debug)]
pub struct EnumReprError;

impl TryFromStr for KeyApplications {
    type Error = EnumReprError;
    fn try_from_str(s: &str) -> Result<Self, Self::Error> {
        Ok(match s.to_lowercase().as_str() {
            "pkh" => KeyApplications::Legacy,
            "sh" => KeyApplications::Legacy,
            "wpkh" => KeyApplications::SegWitV0Singlesig,
            "wsh" => KeyApplications::SegWitV0Miltisig,
            "wpkh-sh" => KeyApplications::SegWitLegacySinglesig,
            "wsh-sh" => KeyApplications::SegWitLegacyMultisig,
            _ => Err(EnumReprError)?,
        })
    }
}

/// Command-line commands:
/// ```text
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
/// ```
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
        /// Target chain for the key
        #[clap()]
        chain: Chain,

        /// Application scope. Possible values are:
        /// pkh, sh, wpkh, wsh, wpkh-sh, wsh-sh
        #[clap(parse(try_from_str = KeyApplications::try_from_str))]
        application: KeyApplications,

        /// Name for newly generated account with a seed phrase
        #[clap()]
        name: String,

        /// More details information about the new account
        #[clap()]
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
    type Error = api::Error;

    #[inline]
    fn exec(&self, runtime: &mut Runtime) -> Result<(), Self::Error> {
        match self {
            Command::Seed { subcommand } => subcommand.exec(runtime),
            Command::Xpubkey { subcommand } => subcommand.exec(runtime),
            Command::Xprivkey { subcommand } => subcommand.exec(runtime),
            Command::Sign { in_file, out_file } => {
                self.exec_sign(runtime, in_file, out_file)
            }
        }
    }
}

impl Exec for SeedCommand {
    type Runtime = Runtime;
    type Error = api::Error;

    #[inline]
    fn exec(&self, runtime: &mut Runtime) -> Result<(), Self::Error> {
        match self {
            SeedCommand::Create {
                name,
                details,
                chain,
                application,
            } => self.exec_create(
                runtime,
                name.clone(),
                details.clone(),
                chain.clone(),
                *application,
            ),
            SeedCommand::Import { id } => self.exec_import(runtime, id),
            SeedCommand::Export { id, file } => {
                self.exec_export(runtime, id, file)
            }
        }
    }
}

impl Exec for XPubkeyCommand {
    type Runtime = Runtime;
    type Error = api::Error;

    #[inline]
    fn exec(&self, runtime: &mut Runtime) -> Result<(), Self::Error> {
        match self {
            XPubkeyCommand::List { format } => self.exec_list(runtime, format),
            XPubkeyCommand::Derive { id, path } => {
                self.exec_derive(runtime, id, path)
            }
            XPubkeyCommand::Export { id, file } => {
                self.exec_export(runtime, id, file)
            }
        }
    }
}

impl Exec for XPrivkeyCommand {
    type Runtime = Runtime;
    type Error = api::Error;

    #[inline]
    fn exec(&self, runtime: &mut Runtime) -> Result<(), Self::Error> {
        match self {
            XPrivkeyCommand::Export { id, file } => {
                self.exec_export(runtime, id, file)
            }
        }
    }
}

impl Command {
    pub fn exec_sign(
        &self,
        _runtime: &mut Runtime,
        _in_file: &str,
        _out_file: &str,
    ) -> Result<(), api::Error> {
        unimplemented!()
    }
}

impl SeedCommand {
    pub fn exec_create(
        &self,
        runtime: &mut Runtime,
        name: String,
        description: Option<String>,
        chain: Chain,
        application: KeyApplications,
    ) -> Result<(), api::Error> {
        debug!("Creating new seed");
        let reply =
            runtime.request(api::Request::Seed(api::message::Seed {
                auth_code: 0,
                name,
                chain,
                application,
                description,
            }))?;
        match reply {
            Reply::Success => {
                info!("New seed created");
                Ok(())
            }
            Reply::Failure(failure) => Err(api::Error::ServerFailure(failure)),
            _ => Err(api::Error::UnexpectedServerResponse),
        }
    }

    pub fn exec_import(
        &self,
        _runtime: &mut Runtime,
        _id: &XpubIdentifier,
    ) -> Result<(), api::Error> {
        unimplemented!()
    }

    pub fn exec_export(
        &self,
        _runtime: &mut Runtime,
        _id: &XpubIdentifier,
        _file: &str,
    ) -> Result<(), api::Error> {
        unimplemented!()
    }
}

impl XPubkeyCommand {
    pub fn exec_list(
        &self,
        runtime: &mut Runtime,
        format: &DataFormat,
    ) -> Result<(), api::Error> {
        const ERR: &'static str = "Error formatting data";

        debug!("Listing known accounts/extended public keys");
        let reply = runtime.request(api::Request::List)?;
        match reply {
            Reply::Keylist(accounts) => {
                let result = match format {
                    DataFormat::Json => {
                        serde_json::to_string(&accounts).expect(ERR)
                    }
                    DataFormat::Yaml => {
                        serde_yaml::to_string(&accounts).expect(ERR)
                    }
                    DataFormat::Toml => toml::to_string(&accounts).expect(ERR),
                    DataFormat::StrictHex => {
                        strict_encode(&accounts).expect(ERR).to_hex()
                    }
                    DataFormat::StrictBase64 => {
                        base64::encode(strict_encode(&accounts).expect(ERR))
                    }
                };
                println!("{}", result);
                Ok(())
            }
            Reply::Failure(failure) => {
                Err(api::Error::ServerFailure(failure.clone()))
            }
            _ => Err(api::Error::UnexpectedServerResponse),
        }
    }

    pub fn exec_derive(
        &self,
        _runtime: &mut Runtime,
        _id: &XpubIdentifier,
        _path: &DerivationPath,
    ) -> Result<(), api::Error> {
        unimplemented!()
    }

    pub fn exec_export(
        &self,
        _runtime: &mut Runtime,
        _id: &XpubIdentifier,
        _file: &str,
    ) -> Result<(), api::Error> {
        unimplemented!()
    }
}

impl XPrivkeyCommand {
    pub fn exec_export(
        &self,
        _runtime: &mut Runtime,
        _id: &XpubIdentifier,
        _file: &str,
    ) -> Result<(), api::Error> {
        unimplemented!()
    }
}
