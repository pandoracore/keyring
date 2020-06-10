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

use clap::derive::Clap;
use log::LevelFilter;
use std::env;

use lnpbp::TryService;

use keyring::daemon::{Config, Opts, Runtime};
use keyring::error::BootstrapError;

#[tokio::main]
async fn main() -> Result<(), BootstrapError> {
    // TODO: Move on configure_me
    let opts: Opts = Opts::parse();
    let config: Config = opts.into();

    if env::var("RUST_LOG").is_err() {
        env::set_var(
            "RUST_LOG",
            match config.verbose {
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

    let runtime = Runtime::init(config).await?;
    runtime.run_or_panic("RGBd runtime").await
}
