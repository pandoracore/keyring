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
use ::std::fs::File;
use ::std::io::Write;
use ::std::net::SocketAddr;
use ::std::process::exit;
use clap::Clap;
use num_traits::FromPrimitive;

use lnpbp::bitcoin::secp256k1;
use lnpbp::lnp::transport::zmq::SocketLocator;

use crate::constants::*;
use crate::error::ConfigInitError;
use crate::vault;

#[derive(Clap, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(Debug)]
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
    #[clap(short, long, parse(from_occurrences))]
    pub verbose: u8,

    /// Data directory path
    #[clap(short, long, env = "KEYRING_DATA_DIR")]
    pub data_dir: Option<String>,

    /// ZMQ socket address string for RPC API
    #[clap(long = "zmq", env = "KEYRING_ZMQ_ENDPOINT")]
    pub zmq_endpoint: Option<String>,

    /// ZMQ socket address string for RPC API
    #[clap(long = "tcp", env = "KEYRING_TCP_ENDPOINT")]
    pub tcp_endpoint: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Serialize, Deserialize)]
#[display(Debug)]
pub struct Config {
    #[serde(with = "serde_with::rust::display_fromstr")]
    pub node_key: secp256k1::SecretKey,
    pub data_dir: String,
    pub log_level: LogLevel,
    #[serde(with = "serde_with::rust::display_fromstr")]
    pub zmq_endpoint: SocketLocator,
    pub tcp_endpoint: SocketAddr,
    pub vault: vault::driver::Config,
}

#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    Debug,
    Display,
    Serialize,
    Deserialize,
    FromPrimitive,
    ToPrimitive,
)]
#[display(Debug)]
pub enum LogLevel {
    Error = 0,
    Warn,
    Info,
    Debug,
    Trace,
}

impl TryFrom<Opts> for Config {
    type Error = ConfigError;

    fn try_from(opts: Opts) -> Result<Self, Self::Error> {
        let log_level =
            LogLevel::from_u8(opts.verbose).unwrap_or(LogLevel::Trace);

        setup_verbose(log_level);
        debug!("Verbosity level set to {}", opts.verbose);

        let mut proto = Self::default();
        if let Some(data_dir) = opts.data_dir {
            proto.data_dir = data_dir
        }

        let conf_file: String = proto.parse_param(opts.config);
        let mut me = if !opts.init {
            debug!("Reading config file {}", conf_file);
            let mut s = Settings::new();
            match s.merge(settings::File::with_name(&conf_file)) {
                Ok(_) => {}
                Err(ConfigError::Foreign(err)) => {
                    error!("{}", ConfigError::Foreign(err));
                    eprintln!(
                        "Config file {} not found: please either specify a correct \
                     configuration file path with `--config` argument or \
                     init default config parameters with `--init`",
                        conf_file
                    );
                    exit(1);
                }
                Err(err) => Err(err)?,
            }
            trace!("Config file read; applying read config");

            s.try_into()?
        } else {
            Self::default()
        };

        trace!("Applying command-line arguments & environment");
        me.data_dir = proto.data_dir;
        if opts.verbose > 0 {
            me.log_level = log_level
        }
        if let Some(tcp_endpoint) = opts.tcp_endpoint {
            me.tcp_endpoint = me.parse_param(tcp_endpoint)
        }
        if let Some(zmq_endpoint) = opts.zmq_endpoint {
            me.zmq_endpoint = me.parse_param(zmq_endpoint)
        }

        match me.vault {
            vault::driver::Config::File(ref mut fdc) => {
                fdc.location = format!("{}/{}", me.data_dir, fdc.location)
            }
        }

        if opts.init {
            if let Err(err) = init_config(&conf_file, me) {
                error!("Error during config file creation: {}", err);
                eprintln!(
                    "Unable to create configuration file {}: {}",
                    conf_file, err
                );
                exit(1);
            }
            exit(0);
        }

        debug!("Configuration init succeeded");
        Ok(me)
    }
}

impl Default for Config {
    fn default() -> Self {
        use lnpbp::bitcoin::secp256k1::rand::thread_rng;
        let mut rng = thread_rng();
        let node_key = secp256k1::SecretKey::new(&mut rng);
        Self {
            node_key,
            data_dir: KEYRING_DATA_DIR
                .parse()
                .expect("Error in KEYRING_DATA_DIR constant value"),
            log_level: LogLevel::Warn,
            zmq_endpoint: KEYRING_ZMQ_ENDPOINT
                .parse()
                .expect("Error in KEYRING_ZMQ_ENDPOINT constant value"),
            tcp_endpoint: KEYRING_TCP_ENDPOINT
                .parse()
                .expect("Error in KEYRING_TCP_ENDPOINT constant value"),
            vault: vault::driver::Config::File(vault::file_driver::Config {
                location: KEYRING_VAULT_FILE
                    .parse()
                    .expect("Error in KEYRING_VAULT_FILE constant value"),
                format: KEYRING_VAULT_FORMAT,
            }),
        }
    }
}

impl Config {
    pub fn apply(&self) {}

    pub fn parse_param<T>(&self, param: String) -> T
    where
        T: FromStr,
        T::Err: Display,
    {
        param
            .replace("{id}", "default")
            .replace("{data_dir}", &self.data_dir)
            .replace("{node_id}", &self.node_id().to_string())
            .parse()
            .unwrap_or_else(|err| {
                panic!("Error parsing parameter `{}`: {}", param, err)
            })
    }

    pub fn node_id(&self) -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_secret_key(&SECP256K1, &self.node_key)
    }
}

fn setup_verbose(verbose: LogLevel) {
    if env::var("RUST_LOG").is_err() {
        env::set_var(
            "RUST_LOG",
            match verbose {
                LogLevel::Error => "error",
                LogLevel::Warn => "warn",
                LogLevel::Info => "info",
                LogLevel::Debug => "debug",
                LogLevel::Trace => "trace",
            },
        );
    }
    env_logger::init();
}

fn init_config(conf_file: &str, config: Config) -> Result<(), ConfigInitError> {
    info!("Initializing config file at {}", conf_file);

    let conf_str = toml::to_string(&config)?;
    trace!("Serialized config:\n\n{}", conf_str);

    trace!("Creating config file");
    let mut conf_fd = File::create(conf_file)?;

    trace!("Writing config to the file");
    conf_fd.write(conf_str.as_bytes())?;

    debug!("Config file successfully created");
    return Ok(());
}
