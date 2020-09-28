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

#[cfg(feature = "daemon")]
use crate::vault::file_driver::FileFormat;

#[cfg(feature = "daemon")]
pub const KEYRING_CONFIG: &'static str = "{data_dir}/keyringd.toml";
#[cfg(feature = "cli")]
pub const KEYRING_CLI_CONFIG: &'static str = "{data_dir}/keyringd-cli.toml";
pub const KEYRING_DATA_DIR: &'static str = "/var/lib/keyring";
pub const KEYRING_ZMQ_ENDPOINT: &'static str = "tcp://0.0.0.0:20202"; //"ipc:{data_dir}/zmq.rpc";
#[cfg(feature = "daemon")]
pub const KEYRING_TCP_ENDPOINT: &'static str = "0.0.0.0:20202";
#[cfg(feature = "daemon")]
pub const KEYRING_VAULT_FORMAT: FileFormat = FileFormat::Yaml;
#[cfg(feature = "daemon")]
pub const KEYRING_VAULT_FILE: &'static str = "vault.yaml";

pub use lnpbp::bitcoin::secp256k1::{self, Secp256k1};
