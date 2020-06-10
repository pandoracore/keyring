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

use lnpbp::bitcoin::util::bip32::{DerivationPath, Fingerprint};
use lnpbp::service::Exec;

use super::{Error, Runtime};

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
    Create,

    Import {
        fingerprint: Fingerprint,
    },

    Export {
        fingerprint: Fingerprint,
        file: String,
    },
}

#[derive(Clap, Clone, Debug, Display)]
#[display_from(Debug)]
pub enum XPubkeyCommand {
    List,

    Derive {
        fingerprint: Fingerprint,
        path: DerivationPath,
    },

    Export {
        fingerprint: Fingerprint,
        file: String,
    },
}

#[derive(Clap, Clone, Debug, Display)]
#[display_from(Debug)]
pub enum XPrivkeyCommand {
    Export {
        fingerprint: Fingerprint,
        file: String,
    },
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
            SeedCommand::Create => self.exec_create(runtime),
            SeedCommand::Import { fingerprint } => self.exec_import(runtime, fingerprint),
            SeedCommand::Export { fingerprint, file } => {
                self.exec_export(runtime, fingerprint, file)
            }
        }
    }
}

impl Exec for XPubkeyCommand {
    type Runtime = Runtime;
    type Error = Error;

    #[inline]
    fn exec(&self, runtime: &mut Runtime) -> Result<(), Error> {
        match self {
            XPubkeyCommand::List => self.exec_list(runtime),
            XPubkeyCommand::Derive { fingerprint, path } => {
                self.exec_derive(runtime, fingerprint, path)
            }
            XPubkeyCommand::Export { fingerprint, file } => {
                self.exec_export(runtime, fingerprint, file)
            }
        }
    }
}

impl Exec for XPrivkeyCommand {
    type Runtime = Runtime;
    type Error = Error;

    #[inline]
    fn exec(&self, runtime: &mut Runtime) -> Result<(), Error> {
        match self {
            XPrivkeyCommand::Export { fingerprint, file } => {
                self.exec_export(runtime, fingerprint, file)
            }
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
    pub fn exec_create(&self, runtime: &mut Runtime) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn exec_import(
        &self,
        runtime: &mut Runtime,
        fingerprint: &Fingerprint,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn exec_export(
        &self,
        runtime: &mut Runtime,
        fingerprint: &Fingerprint,
        file: &str,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

impl XPubkeyCommand {
    pub fn exec_list(&self, runtime: &mut Runtime) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn exec_derive(
        &self,
        runtime: &mut Runtime,
        fingerprint: &Fingerprint,
        path: &DerivationPath,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn exec_export(
        &self,
        runtime: &mut Runtime,
        fingerprint: &Fingerprint,
        file: &str,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

impl XPrivkeyCommand {
    pub fn exec_export(
        &self,
        runtime: &mut Runtime,
        fingerprint: &Fingerprint,
        file: &str,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}
