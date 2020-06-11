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
use ::std::path::PathBuf;
use ::std::process::exit;
use clap::derive::ArgEnum;
use clap::Clap;

use lnpbp::bitcoin::secp256k1;
use lnpbp::bp;
use lnpbp::lnp::transport::zmq::SocketLocator;
use lnpbp::lnp::NodeLocator;

use crate::constants::*;
use crate::error::{BootstrapError, ConfigInitError};
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
    #[clap(short, long, parse(from_occurrences))]
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
        setup_verbose(opts.verbose);
        debug!("Verbosity level set to {}", opts.verbose);

        let mut proto = Self::default();
        if let Some(data_dir) = opts.data_dir {
            proto.data_dir = data_dir
        }

        let conf_file: String = proto.parse_param(opts.config);
        if opts.init {
            if let Err(err) = init_config(&conf_file, proto) {
                error!("Error during config file creation: {}", err);
                eprintln!("Unable to create configuration file {}: {}", conf_file, err);
                exit(1);
            }
            exit(0);
        }

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
        let mut me: Self = s.try_into()?;

        trace!("Applying command-line arguments & environment");
        me.data_dir = proto.data_dir;
        if opts.verbose > 0 {
            me.verbose = opts.verbose
        }
        if let Some(tcp_endpoint) = opts.tcp_endpoint {
            me.tcp_endpoint = me.parse_param(tcp_endpoint)
        }
        if let Some(zmq_endpoint) = opts.zmq_endpoint {
            me.zmq_endpoint = me.parse_param(zmq_endpoint)
        }

        debug!("Configuration init succeeded");
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
        setup_verbose(self.verbose);
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

fn setup_verbose(verbose: u8) {
    if env::var("RUST_LOG").is_err() {
        env::set_var(
            "RUST_LOG",
            match verbose {
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
