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

use clap::Clap;
use core::fmt::Display;
use core::str::FromStr;

use lnpbp::lnp::transport::zmq::SocketLocator;

use super::Command;
use crate::KEYRING_RPC_ENDPOINT;

#[derive(Clap, Clone, Debug, Display)]
#[display_from(Debug)]
#[clap(
    name = "keyring-cli",
    version = "0.0.1",
    author = "Dr Maxim Orlovsky <orlovsky@pandoracore.com>",
    about = "Command-line interface to Keyring daemon"
)]
pub struct Opts {
    /// Sets verbosity level; can be used multiple times to increase verbosity
    #[clap(
        global = true,
        short = "v",
        long = "verbose",
        min_values = 0,
        max_values = 4,
        parse(from_occurrences)
    )]
    pub verbose: u8,

    /// RPC endpoint of keyring daemon
    #[clap(short, long, default_value = KEYRING_RPC_ENDPOINT)]
    pub endpoint: String,

    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

// We need config structure since not all of the parameters can be specified
// via environment and command-line arguments. Thus we need a config file and
// default set of configuration
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
pub struct Config {
    pub verbose: u8,
    pub endpoint: SocketLocator,
}

impl From<Opts> for Config {
    fn from(opts: Opts) -> Self {
        Self {
            verbose: opts.verbose,
            endpoint: opts.endpoint.parse().unwrap_or_else(|err| {
                panic!("Error parsing parameter `{}`: {}", opts.endpoint, err)
            }),
            ..Config::default()
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            verbose: 0,
            endpoint: KEYRING_RPC_ENDPOINT
                .parse()
                .expect("Broken FUNGIBLED_RPC_ENDPOINT value"),
        }
    }
}