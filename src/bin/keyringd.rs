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

#![feature(never_type)]

#[macro_use]
extern crate log;

use amplify::TryService;
use clap::Clap;
use core::convert::TryInto;
use log::LevelFilter;

use keyring::daemon::{Config, Opts, Runtime};
use keyring::error::BootstrapError;

#[tokio::main]
async fn main() -> Result<!, BootstrapError> {
    log::set_max_level(LevelFilter::Trace);
    info!("keyringd: private/public key managing service");

    let opts: Opts = Opts::parse();
    let config: Config = opts.clone().try_into()?;
    config.apply();

    let runtime = Runtime::init(config).await?;
    runtime.run_or_panic("keyringd runtime").await;

    unreachable!()
}
