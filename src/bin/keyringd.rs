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

//! Main daemon file

#[macro_use]
extern crate log;

use ::core::convert::TryInto;
use ::std::fs::File;
use ::std::io::Write;
use clap::derive::Clap;

use lnpbp::TryService;

use keyring::daemon::{Config, Opts, Runtime};
use keyring::error::{BootstrapError, ConfigInitError};

#[tokio::main]
async fn main() -> Result<(), BootstrapError> {
    let opts: Opts = Opts::parse();
    let config: Config = opts.clone().try_into()?;
    config.apply();

    info!("keyringd: private/public key managing service");

    if opts.init {
        if let Err(err) = init_config(opts, config) {
            error!("Error during config file creation: {}", err);
            return Err(BootstrapError::ConfigInitError);
        }
        return Ok(());
    }

    let runtime = Runtime::init(config).await?;
    runtime.run_or_panic("keyringd runtime").await
}

fn init_config(opts: Opts, config: Config) -> Result<(), ConfigInitError> {
    info!("Initializing config file at {}", opts.config);

    let conf_str = toml::to_string(&config)?;
    trace!("Serialized config:\n\n{}", conf_str);

    trace!("Creating config file");
    let mut conf_fd = File::create(opts.config)?;

    trace!("Writing config to the file");
    conf_fd.write(conf_str.as_bytes())?;

    debug!("Config file successfully created");
    return Ok(());
}
