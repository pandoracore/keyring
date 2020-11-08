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

use std::path::PathBuf;

use lnpbp::bitcoin::hashes::hex::{FromHex, ToHex};
use lnpbp::bitcoin::secp256k1;
use lnpbp::bitcoin::util::bip32::DerivationPath;
use lnpbp::bitcoin::XpubIdentifier;
use lnpbp::bp::bip32::KeyApplication;
use lnpbp::bp::Chain;
use lnpbp::strict_encoding::strict_encode;

use super::format;
use super::Runtime;
use crate::api;
use crate::api::Reply;
use crate::Exec;

// Command-line commands:
//
//     keyring-cli seed create
//     keyring-cli seed import <fingerprint>
//     keyring-cli seed export <fingerprint> <file>
//
//     keyring-cli xpub list [<fingerprint>]
//     keyring-cli xpub derive <fingerprint> <derivation_path>
//     keyring-cli xpub export <fingerprint> <file>
//
//     keyring-cli xprivkey export <fingerprint> <file>
//
//     keyring-cli sign <in_file> <out_file>
//
#[derive(Clap, Clone, Debug, Display)]
#[display(Debug)]
pub enum Command {
    /// Seed operations: generation, import, export
    Seed {
        /// Subcommand specifying particular operation
        #[clap(subcommand)]
        subcommand: SeedCommand,
    },

    /// Operations with extended public keys
    Xpub {
        /// Subcommand specifying particular operation
        #[clap(subcommand)]
        subcommand: XPubkeyCommand,
    },

    /// Operations with extended private keys
    Xpriv {
        /// Subcommand specifying particular operation
        #[clap(subcommand)]
        subcommand: XPrivkeyCommand,
    },

    /// Signs given PSBT bitcoin transaction with the matching keys
    Sign {
        /// Subcommand specifying particular type of signatyre
        #[clap(subcommand)]
        subcommand: SignCommand,
    },
}

#[derive(Clap, Clone, Debug, Display)]
#[display(Debug)]
pub enum SeedCommand {
    /// Creates new keyring with new seed and master key pair
    Create {
        /// Target chain for the key
        chain: Chain,

        /// Application scope. Possible values are:
        /// pkh, sh, wpkh, wsh, wpkh-sh, wsh-sh
        application: KeyApplication,

        /// Name for newly generated account with a seed phrase
        name: String,

        /// More details information about the new account
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
#[display(Debug)]
pub enum XPubkeyCommand {
    List {
        #[clap(short, long, arg_enum, default_value = "yaml")]
        format: format::StructuredData,
    },

    /// Derives new keys account from a given master extended public key
    /// identifier and derived path.
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
#[display(Debug)]
pub enum XPrivkeyCommand {
    Export {
        #[clap(parse(try_from_str = FromHex::from_hex))]
        id: XpubIdentifier,

        file: String,
    },
}

#[derive(Clap, Clone, Debug, Display)]
#[display(Debug)]
pub enum SignCommand {
    /// Signs given PSBT
    Psbt {
        #[clap(short = 'f', long = "format", arg_enum, default_value)]
        format: format::Psbt,

        /// Input file to read PSBT from. If absent, and no `data` parameter
        /// is provided, data are read from STDIN. The file and data must be in
        /// a `format` format.
        #[clap(short, long = "in")]
        in_file: Option<PathBuf>,

        /// Data string containing PSBT encoded in hexadecimal format (must
        /// contain even number of 0-9, A-f characters)
        #[clap()]
        data: Option<String>,

        /// Output file to save transcoded data. If absent, data are written to
        /// STDOUT
        #[clap(short, long = "out")]
        out_file: Option<PathBuf>,
    },

    File {},

    Text {},

    Key {
        /// Key identifier for the signature
        #[clap(parse(try_from_str = FromHex::from_hex))]
        id: XpubIdentifier,
    },
}

impl Exec for Command {
    type Runtime = Runtime;
    type Error = api::Error;

    #[inline]
    fn exec(&self, runtime: &mut Runtime) -> Result<(), Self::Error> {
        match self {
            Command::Seed { subcommand } => subcommand.exec(runtime),
            Command::Xpub { subcommand } => subcommand.exec(runtime),
            Command::Xpriv { subcommand } => subcommand.exec(runtime),
            Command::Sign { subcommand } => subcommand.exec(runtime),
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

impl Exec for SignCommand {
    type Runtime = Runtime;
    type Error = api::Error;

    #[inline]
    fn exec(&self, runtime: &mut Runtime) -> Result<(), Self::Error> {
        match self {
            SignCommand::Psbt { .. } => {
                unimplemented!()
                //self.exec_sign_psbt(runtime)
            }
            SignCommand::File { .. } => unimplemented!(),
            SignCommand::Text { .. } => unimplemented!(),
            SignCommand::Key { id } => self.exec_sign_key(runtime, *id),
        }
    }
}

impl SeedCommand {
    pub fn exec_create(
        &self,
        runtime: &mut Runtime,
        name: String,
        description: Option<String>,
        chain: Chain,
        application: KeyApplication,
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
        format: &format::StructuredData,
    ) -> Result<(), api::Error> {
        const ERR: &'static str = "Error formatting data";

        debug!("Listing known accounts/extended public keys");
        let reply = runtime.request(api::Request::List)?;
        match reply {
            Reply::Keylist(accounts) => {
                let result = match format {
                    format::StructuredData::Json => {
                        serde_json::to_string(&accounts).expect(ERR)
                    }
                    format::StructuredData::Yaml => {
                        serde_yaml::to_string(&accounts).expect(ERR)
                    }
                    format::StructuredData::Toml => {
                        toml::to_string(&accounts).expect(ERR)
                    }
                    format::StructuredData::StrictHex => {
                        strict_encode(&accounts).expect(ERR).to_hex()
                    }
                    format::StructuredData::StrictBase64 => {
                        base64::encode(strict_encode(&accounts).expect(ERR))
                    }
                    _ => unimplemented!(),
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

impl SignCommand {
    pub fn exec_sign_key(
        &self,
        runtime: &mut Runtime,
        id: XpubIdentifier,
    ) -> Result<(), api::Error> {
        debug!("Signing public key with private key");
        let reply =
            runtime.request(api::Request::SignKey(api::message::SignKey {
                key_id: id,
                decryption_key: secp256k1::key::ONE_KEY,
                auth_code: 0,
            }))?;
        match reply {
            Reply::Signature(signature) => {
                info!("New signature created: {}", signature);
                Ok(())
            }
            Reply::Failure(failure) => Err(api::Error::ServerFailure(failure)),
            _ => Err(api::Error::UnexpectedServerResponse),
        }
    }
}
