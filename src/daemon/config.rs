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

use ::core::convert::{TryFrom, TryInto};
use ::core::fmt::Display;
use ::core::str::FromStr;
use ::serde_with::DisplayFromStr;
use ::settings::{self, Config as Settings, ConfigError};
use ::std::fs::File;
use ::std::io::Write;
use ::std::process::exit;

use lnpbp::bitcoin::secp256k1;
use lnpbp::lnp::zmqsocket::ZmqSocketAddr;
use lnpbp_services::shell::LogLevel;

use super::opts::{KEYRING_VAULT_FILE, KEYRING_VAULT_FORMAT};
use super::Opts;
use crate::error::ConfigInitError;
use crate::opts::{KEYRING_DATA_DIR, KEYRING_RPC_SOCKET_NAME};
use crate::vault;

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(crate = "serde_crate")]
pub struct Config {
    #[serde_as(as = "DisplayFromStr")]
    pub node_key: secp256k1::SecretKey,
    pub data_dir: String,
    pub log_level: LogLevel,
    #[serde_as(as = "DisplayFromStr")]
    pub endpoint: ZmqSocketAddr,
    pub vault: vault::driver::Config,
}

impl TryFrom<Opts> for Config {
    type Error = ConfigError;

    fn try_from(opts: Opts) -> Result<Self, Self::Error> {
        let log_level =
            LogLevel::from_verbosity_flag_count(opts.shared.verbose);

        let mut proto = Self::default();
        proto.data_dir = opts.shared.data_dir.to_string_lossy().to_string();

        let conf_file: String = proto.parse_param(opts.config);
        let mut me = if !opts.shared.init {
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
            Config::default()
        };

        trace!("Applying command-line arguments & environment");
        me.data_dir = proto.data_dir;
        me.log_level = log_level;
        me.endpoint = opts
            .shared
            .rpc_socket
            .try_into()
            .expect("Only ZMQ RPC is supported");

        match me.vault {
            vault::driver::Config::File(ref mut fdc) => {
                fdc.location = format!("{}/{}", me.data_dir, fdc.location)
            }
            _ => {}
        }

        if opts.shared.init {
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

        debug!("Configuration successfully loaded");
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
            endpoint: KEYRING_RPC_SOCKET_NAME
                .parse()
                .expect("Error in KEYRING_ZMQ_ENDPOINT constant value"),
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
            .replace("{data_dir}", &self.data_dir)
            .replace("{node_id}", &self.node_id().to_string())
            .parse()
            .unwrap_or_else(|err| {
                panic!("Error parsing parameter `{}`: {}", param, err)
            })
    }

    pub fn node_id(&self) -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_secret_key(&lnpbp::SECP256K1, &self.node_key)
    }
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
