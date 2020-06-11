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

use ::core::convert::TryFrom;
use ::core::fmt::Display;
use ::core::str::FromStr;
use ::settings::{self, Config as Settings, ConfigError};
use ::std::env;
use ::std::net::SocketAddr;
use ::std::path::PathBuf;
use clap::derive::ArgEnum;
use clap::Clap;
use log::LevelFilter;

use lnpbp::bitcoin::secp256k1;
use lnpbp::bp;
use lnpbp::lnp::transport::zmq::SocketLocator;
use lnpbp::lnp::NodeLocator;

use crate::constants::*;
use crate::vault;

#[derive(Clap, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
#[clap(
    name = "keyringd",
    version = "0.1.0-alpha",
    author = "Dr Maxim Orlovsky <orlovsky@pandoracore.com>",
    about = "Keyring daemon: extended private & public key management for custodial"
)]
pub struct Opts {
    /// Initializes config file with the default values
    #[clap(long)]
    pub init: bool,

    /// Path to the configuration file.
    /// NB: Command-line options override configuration file values.
    #[clap(short, long, default_value = KEYRING_CONFIG, env = "KEYRING_CONFIG")]
    pub config: String,

    /// Sets verbosity level; can be used multiple times to increase verbosity
    #[clap(min_values = 0, max_values = 4, parse(from_occurrences))]
    pub verbose: u8,

    /// Data directory path
    #[clap(short, long, env = "KEYRING_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// ZMQ socket address string for RPC API
    #[clap(long = "zmq", env = "KEYRING_ZMQ_ENDPOINT")]
    pub zmq_endpoint: Option<String>,

    /// ZMQ socket address string for RPC API
    #[clap(long = "tcp", env = "KEYRING_TCP_ENDPOINT")]
    pub tcp_endpoint: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Serialize, Deserialize)]
#[display_from(Debug)]
pub struct Config {
    pub node_key: secp256k1::SecretKey,
    pub data_dir: PathBuf,
    pub verbose: u8,
    pub zmq_endpoint: SocketLocator,
    pub tcp_endpoint: SocketAddr,
    pub vault: vault::driver::Config,
}

impl TryFrom<Opts> for Config {
    type Error = ConfigError;

    fn try_from(opts: Opts) -> Result<Self, Self::Error> {
        let mut s = Settings::new();
        s.merge(settings::File::with_name(&opts.config))?;

        let mut me: Self = s.try_into()?;
        if opts.verbose > 0 {
            me.verbose = opts.verbose
        }
        if let Some(data_dir) = opts.data_dir {
            me.data_dir = data_dir
        }
        if let Some(tcp_endpoint) = opts.tcp_endpoint {
            me.tcp_endpoint = me.parse_param(tcp_endpoint)
        }
        if let Some(zmq_endpoint) = opts.zmq_endpoint {
            me.zmq_endpoint = me.parse_param(zmq_endpoint)
        }
        Ok(me)
    }
}

impl Default for Config {
    fn default() -> Self {
        use lnpbp::rand::thread_rng;
        let mut rng = thread_rng();
        let node_key = secp256k1::SecretKey::new(&mut rng);
        Self {
            node_key,
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
            vault: vault::driver::Config::File(vault::file_driver::Config {
                filename: KEYRING_VAULT_FILE
                    .parse()
                    .expect("Error in KEYRING_VAULT_FILE constant value"),
                format: KEYRING_VAULT_FORMAT,
            }),
        }
    }
}

impl Config {
    pub fn apply(&self) {
        if env::var("RUST_LOG").is_err() {
            env::set_var(
                "RUST_LOG",
                match self.verbose {
                    0 => "error",
                    1 => "warn",
                    2 => "info",
                    3 => "debug",
                    4 => "trace",
                    _ => "trace",
                },
            );
        }
        env_logger::init();
        log::set_max_level(LevelFilter::Trace);
    }

    pub fn parse_param<T>(&self, param: String) -> T
    where
        T: FromStr,
        T::Err: Display,
    {
        param
            .replace("{id}", "default")
            .replace("{data_dir}", self.data_dir.to_str().unwrap())
            .replace("{node_id}", &self.node_id().to_string())
            .parse()
            .unwrap_or_else(|err| panic!("Error parsing parameter `{}`: {}", param, err))
    }

    pub fn node_id(&self) -> secp256k1::PublicKey {
        let secp = secp256k1::Secp256k1::new();
        secp256k1::PublicKey::from_secret_key(&secp, &self.node_key)
    }
}
