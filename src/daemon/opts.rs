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

pub const KEYRING_CONFIG: &'static str = "{data_dir}/keyringd.toml";
#[cfg(feature = "serde_yaml")]
pub const KEYRING_VAULT_FORMAT: FileFormat = FileFormat::Yaml;
#[cfg(not(feature = "serde_yaml"))]
pub const KEYRING_VAULT_FORMAT: FileFormat = FileFormat::StrictEncoded;
pub const KEYRING_VAULT_FILE: &'static str = "vault.yaml";

#[derive(
    Copy, Clone, PartialEq, Eq, Hash, Debug, Display, Serialize, Deserialize,
)]
#[serde(crate = "serde_crate")]
#[non_exhaustive]
pub enum FileFormat {
    #[display("strict-encoded")]
    StrictEncoded,

    #[cfg(feature = "serde_yaml")]
    #[display("yaml")]
    Yaml,

    #[cfg(feature = "toml")]
    #[display("toml")]
    Toml,

    #[cfg(feature = "serde_json")]
    #[display("json")]
    Json,
}

#[derive(Clap, Clone, PartialEq, Eq, Hash, Debug)]
#[clap(
    name = "keyringd",
    bin_name = "keyringd",
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
        global = true,
        default_value = KEYRING_CONFIG,
        env = "KEYRING_CONFIG",
        value_hint = ValueHint::FilePath
    )]
    pub config: String,
}

impl Opts {
    pub fn process(&mut self) {
        self.shared.process();
        self.shared.process_dir(&mut self.config);
    }
}
