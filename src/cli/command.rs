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

use std::{fs, io};

use lnpbp::bitcoin::consensus::encode::{Decodable, Encodable};
use lnpbp::bitcoin::hashes::hex::ToHex;
use lnpbp::bitcoin::secp256k1;
use lnpbp::bitcoin::util::bip32::DerivationPath;
use lnpbp::bitcoin::XpubIdentifier;
use lnpbp::bp::bip32::KeyApplication;
use lnpbp::bp::{Chain, Psbt};
use lnpbp::strict_encoding::strict_serialize;
use lnpbp_services::format;
use lnpbp_services::shell::Exec;

use super::Client;
use super::{
    Command, SeedCommand, SignCommand, XPrivkeyCommand, XPubkeyCommand,
};
use crate::rpc;

impl Exec for Command {
    type Runtime = Client;
    type Error = rpc::Error;

    #[inline]
    fn exec(&self, runtime: &mut Client) -> Result<(), Self::Error> {
        match self {
            Command::Seed { subcommand } => subcommand.exec(runtime),
            Command::Xpub { subcommand } => subcommand.exec(runtime),
            Command::Xpriv { subcommand } => subcommand.exec(runtime),
            Command::Sign { subcommand } => subcommand.exec(runtime),
        }
    }
}

impl Exec for SeedCommand {
    type Runtime = Client;
    type Error = rpc::Error;

    #[inline]
    fn exec(&self, runtime: &mut Client) -> Result<(), Self::Error> {
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
    type Runtime = Client;
    type Error = rpc::Error;

    #[inline]
    fn exec(&self, runtime: &mut Client) -> Result<(), Self::Error> {
        match self {
            XPubkeyCommand::List { format } => self.exec_list(runtime, format),
            XPubkeyCommand::Derive {
                id,
                path,
                name,
                details,
            } => self.exec_derive(runtime, id, path, name, details),
            XPubkeyCommand::Export { id, file } => {
                self.exec_export(runtime, id, file)
            }
        }
    }
}

impl Exec for XPrivkeyCommand {
    type Runtime = Client;
    type Error = rpc::Error;

    #[inline]
    fn exec(&self, runtime: &mut Client) -> Result<(), Self::Error> {
        match self {
            XPrivkeyCommand::Export { id, file } => {
                self.exec_export(runtime, id, file)
            }
        }
    }
}

impl Exec for SignCommand {
    type Runtime = Client;
    type Error = rpc::Error;

    #[inline]
    fn exec(&self, runtime: &mut Client) -> Result<(), Self::Error> {
        match self {
            SignCommand::Psbt {
                format,
                in_file,
                data,
                out_file,
            } => {
                let reader = match (data, in_file) {
                    (Some(data), _) => {
                        Box::new(io::BufReader::new(io::Cursor::new(data)))
                            as Box<dyn io::BufRead>
                    }
                    (None, None) => Box::new(io::BufReader::new(io::stdin()))
                        as Box<dyn io::BufRead>,
                    (_, Some(filename)) => {
                        Box::new(io::BufReader::new(fs::File::open(filename)?))
                            as Box<dyn io::BufRead>
                    }
                };
                let psbt = match format {
                    format::StructuredData::Bin => {
                        Psbt::consensus_decode(reader)?
                    }
                    _ => unimplemented!(),
                };
                let reply = runtime.request(rpc::Request::SignPsbt(
                    rpc::message::SignPsbt {
                        psbt,
                        decryption_key: secp256k1::key::ONE_KEY,
                        auth_code: 0,
                    },
                ))?;
                let psbt = match reply {
                    rpc::Reply::Psbt(psbt) => psbt,
                    rpc::Reply::Failure(failure) => {
                        Err(rpc::Error::ServerFailure(failure))?
                    }
                    _ => Err(rpc::Error::UnexpectedServerResponse)?,
                };
                let writer = match out_file {
                    Some(filename) => Box::new(io::BufWriter::new(
                        fs::File::create(filename)?,
                    ))
                        as Box<dyn io::Write>,
                    None => Box::new(io::BufWriter::new(io::stdout()))
                        as Box<dyn io::Write>,
                };
                match format {
                    format::StructuredData::Bin => {
                        psbt.consensus_encode(writer)?;
                    }
                    _ => unimplemented!(),
                }
                Ok(())
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
        runtime: &mut Client,
        name: String,
        description: Option<String>,
        chain: Chain,
        application: KeyApplication,
    ) -> Result<(), rpc::Error> {
        debug!("Creating new seed");
        let reply =
            runtime.request(rpc::Request::Seed(rpc::message::Seed {
                auth_code: 0,
                name,
                chain,
                application,
                description,
            }))?;
        match reply {
            rpc::Reply::Success => {
                info!("New seed created");
                Ok(())
            }
            rpc::Reply::Failure(failure) => {
                Err(rpc::Error::ServerFailure(failure))
            }
            _ => Err(rpc::Error::UnexpectedServerResponse),
        }
    }

    pub fn exec_import(
        &self,
        _runtime: &mut Client,
        _id: &XpubIdentifier,
    ) -> Result<(), rpc::Error> {
        unimplemented!()
    }

    pub fn exec_export(
        &self,
        _runtime: &mut Client,
        _id: &XpubIdentifier,
        _file: &str,
    ) -> Result<(), rpc::Error> {
        unimplemented!()
    }
}

impl XPubkeyCommand {
    pub fn exec_list(
        &self,
        runtime: &mut Client,
        format: &format::StructuredData,
    ) -> Result<(), rpc::Error> {
        const ERR: &'static str = "Error formatting data";

        debug!("Listing known accounts/extended public keys");
        let reply = runtime.request(rpc::Request::List)?;
        match reply {
            rpc::Reply::Keylist(accounts) => {
                let result = match format {
                    #[cfg(feature = "serde_json")]
                    format::StructuredData::Json => {
                        serde_json::to_string(&accounts).expect(ERR)
                    }
                    #[cfg(feature = "serde_yaml")]
                    format::StructuredData::Yaml => {
                        serde_yaml::to_string(&accounts).expect(ERR)
                    }
                    #[cfg(feature = "toml")]
                    format::StructuredData::Toml => {
                        toml::to_string(&accounts).expect(ERR)
                    }
                    format::StructuredData::Hex => {
                        strict_serialize(&accounts).expect(ERR).to_hex()
                    }
                    format::StructuredData::Base64 => {
                        base64::encode(strict_serialize(&accounts).expect(ERR))
                    }
                    _ => unimplemented!(),
                };
                println!("{}", result);
                Ok(())
            }
            rpc::Reply::Failure(failure) => {
                Err(rpc::Error::ServerFailure(failure.clone()))
            }
            _ => Err(rpc::Error::UnexpectedServerResponse),
        }
    }

    pub fn exec_derive(
        &self,
        runtime: &mut Client,
        id: &XpubIdentifier,
        path: &DerivationPath,
        name: &String,
        details: &Option<String>,
    ) -> Result<(), rpc::Error> {
        debug!("Deriving new subaccount");
        let reply =
            runtime.request(rpc::Request::Derive(rpc::message::Derive {
                from: *id,
                path: path.clone(),
                name: name.clone(),
                details: details.as_ref().cloned().unwrap_or_default(),
                assets: Default::default(),
                decryption_key: secp256k1::key::ONE_KEY,
                auth_code: 0,
            }))?;
        match reply {
            rpc::Reply::AccountInfo(info) => {
                println!("{}", info);
                Ok(())
            }
            rpc::Reply::Failure(failure) => {
                Err(rpc::Error::ServerFailure(failure.clone()))
            }
            _ => Err(rpc::Error::UnexpectedServerResponse),
        }
    }

    pub fn exec_export(
        &self,
        _runtime: &mut Client,
        _id: &XpubIdentifier,
        _file: &str,
    ) -> Result<(), rpc::Error> {
        unimplemented!()
    }
}

impl XPrivkeyCommand {
    pub fn exec_export(
        &self,
        _runtime: &mut Client,
        _id: &XpubIdentifier,
        _file: &str,
    ) -> Result<(), rpc::Error> {
        unimplemented!()
    }
}

impl SignCommand {
    pub fn exec_sign_key(
        &self,
        runtime: &mut Client,
        id: XpubIdentifier,
    ) -> Result<(), rpc::Error> {
        debug!("Signing public key with private key");
        let reply =
            runtime.request(rpc::Request::SignKey(rpc::message::SignKey {
                key_id: id,
                decryption_key: secp256k1::key::ONE_KEY,
                auth_code: 0,
            }))?;
        match reply {
            rpc::Reply::Signature(signature) => {
                info!("New signature created: {}", signature);
                Ok(())
            }
            rpc::Reply::Failure(failure) => {
                Err(rpc::Error::ServerFailure(failure))
            }
            _ => Err(rpc::Error::UnexpectedServerResponse),
        }
    }
}
