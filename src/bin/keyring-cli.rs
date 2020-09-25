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

//! Command-line interface to the keyring daemon

#![feature(never_type)]

#[macro_use]
extern crate log;

use clap::Clap;
use log::LevelFilter;
use std::env;

use lnpbp::service::Exec;

use keyring::cli::{Config, Opts, Runtime};
use keyring::error::BootstrapError;

#[tokio::main]
async fn main() -> Result<(), BootstrapError> {
    let opts: Opts = Opts::parse();
    let config: Config = opts.clone().into();

    if env::var("RUST_LOG").is_err() {
        env::set_var(
            "RUST_LOG",
            match opts.verbose {
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

    debug!("Command-line interface to the keyring daemon");
    let mut runtime = Runtime::init(config).await?;

    trace!("Executing command: {:?}", opts.command);
    opts.command
        .exec(&mut runtime)
        .unwrap_or_else(|err| error!("{}", err));

    Ok(())
}
