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

use clap::derive::ArgEnum;
use clap::Clap;
use core::fmt::Display;
use core::str::FromStr;
use lnpbp::bp;
use serde::Deserialize;
use std::path::PathBuf;

use lnpbp::internet::InetSocketAddr;
use lnpbp::lnp::transport::zmq::SocketLocator;
use lnpbp::lnp::{LocalNode, NodeLocator};

use crate::constants::*;

#[derive(Clap)]
#[clap(
    name = "keyringd",
    version = "0.1.0",
    author = "Dr Maxim Orlovsky <orlovsky@pandoracore.com>",
    about = "Keyring daemon: extended private & public key management for custodial"
)]
pub struct Opts {
    /// Sets verbosity level; can be used multiple times to increase verbosity
    #[clap(
        short = "v",
        long = "verbose",
        min_values = 0,
        max_values = 4,
        parse(from_occurrences)
    )]
    pub verbose: u8,

    /// Data directory path
    #[clap(short, long, default_value = KEYRING_DATA_DIR, env = "KEYRING_DATA_DIR")]
    pub data_dir: String,

    /// ZMQ socket address string for RPC API
    #[clap(
        long = "rpc",
        default_value = KEYRING_ZMQ_ENDPOINT,
        env = "KEYRING_ZMQ_ENDPOINT"
    )]
    pub zmq_endpoint: String,

    /// ZMQ socket address string for RPC API
    #[clap(
        long = "rpc",
        default_value = KEYRING_TCP_ENDPOINT,
        env = "KEYRING_TCP_ENDPOINT"
    )]
    pub tcp_endpoint: InetSocketAddr,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
pub struct Config {
    pub node_auth: LocalNode,
    pub data_dir: PathBuf,
    pub verbose: u8,
    pub zmq_endpoint: SocketLocator,
    pub tcp_endpoint: InetSocketAddr,
}

impl From<Opts> for Config {
    fn from(opts: Opts) -> Self {
        let mut me = Self {
            data_dir: opts.data_dir.into(),
            verbose: opts.verbose,
            tcp_endpoint: opts.tcp_endpoint,
            ..Config::default()
        };
        me.zmq_endpoint = me.parse_param(opts.zmq_endpoint);
        me
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            node_auth: LocalNode::new(),
            data_dir: KEYRING_DATA_DIR
                .parse()
                .expect("Error in KEYRING_DATA_DIR constant value"),
            verbose: 0,
            zmq_endpoint: KEYRING_ZMQ_ENDPOINT
                .parse()
                .expect("Error in KEYRING_ZMQ_ENDPOINT constant value"),
            tcp_endpoint: KEYRING_TCP_ENDPOINT
                .parse()
                .expect("Error in KEYRING_TCP_ENDPOINT constant value"),
        }
    }
}

impl Config {
    pub fn parse_param<T>(&self, param: String) -> T
    where
        T: FromStr,
        T::Err: Display,
    {
        param
            .replace("{id}", "default")
            .replace("{data_dir}", self.data_dir.to_str().unwrap())
            .replace("{node_id}", &self.node_auth.node_id().to_string())
            .parse()
            .unwrap_or_else(|err| panic!("Error parsing parameter `{}`: {}", param, err))
    }
}
