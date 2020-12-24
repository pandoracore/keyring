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

use ::clap::{AppSettings, Clap, ValueHint};
use ::std::path::PathBuf;

use ::lnpbp::bitcoin::util::bip32::DerivationPath;
use ::lnpbp::bitcoin::XpubIdentifier;
use ::lnpbp::bp::bip32::KeyApplication;
use ::lnpbp::bp::Chain;
use ::lnpbp::hex::FromHex;
use ::lnpbp_services::format;

pub const KEYRING_CLI_CONFIG: &'static str = "{data_dir}/keyring-cli.toml";

#[derive(Clap, Clone, Debug)]
#[clap(
    name = "keyring-cli",
    bin_name = "keyring-cli",
    author,
    version,
    setting = AppSettings::ColoredHelp
)]
pub struct Opts {
    /// These params can be read also from the configuration file, not just
    /// command-line args or environment variables
    #[clap(flatten)]
    pub shared: crate::opts::Opts,

    /// Path to the configuration file.
    ///
    /// NB: Command-line options override configuration file values.
    #[clap(
        short,
        long,
        default_value = KEYRING_CLI_CONFIG,
        env = "KEYRING_CLI_CONFIG",
        value_hint = ValueHint::FilePath
    )]
    pub config: String,

    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

impl Opts {
    pub fn process(&mut self) {
        self.shared.process();
        self.shared.process_dir(&mut self.config);
    }
}

#[derive(Clap, Clone, Debug)]
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

#[derive(Clap, Clone, Debug)]
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

#[derive(Clap, Clone, Debug)]
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

#[derive(Clap, Clone, Debug)]
pub enum XPrivkeyCommand {
    Export {
        #[clap(parse(try_from_str = FromHex::from_hex))]
        id: XpubIdentifier,

        file: String,
    },
}

#[derive(Clap, Clone, Debug)]
pub enum SignCommand {
    /// Signs given PSBT
    Psbt {
        #[clap(
            short = 'f',
            long = "format",
            arg_enum,
            default_value = "base64"
        )]
        format: format::StructuredData,

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
