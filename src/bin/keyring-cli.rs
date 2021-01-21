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

#![recursion_limit = "256"]
// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    //missing_docs
)]

#[macro_use]
extern crate log;

use clap::Clap;
use microservices::shell::Exec;
use std::convert::TryInto;

use keyring::cli::{Client, Config, Opts};

fn main() {
    println!("keyring-cli: command-line tool for using keyringd service");

    let mut opts = Opts::parse();
    trace!("Command-line arguments: {:?}", &opts);
    opts.process();
    trace!("Processed arguments: {:?}", &opts);

    let config: Config = opts.clone().try_into().expect("Wrong configuration");
    trace!("Tool configuration: {:?}", &config);
    debug!("RPC socket {}", &config.endpoint);

    debug!("Command-line interface to the keyring daemon");
    let mut client = Client::with(config).expect("Error initializing client");

    trace!("Executing command: {:?}", opts.command);
    opts.command
        .exec(&mut client)
        .unwrap_or_else(|err| eprintln!("{}", err));
}
