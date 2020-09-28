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

#![allow(dead_code)]
#![feature(never_type, with_options)]
#![feature(map_first_last)]

#[cfg(any(feature = "daemon"))]
#[macro_use]
extern crate amplify;
#[macro_use]
extern crate amplify_derive;
#[cfg(any(feature = "daemon"))]
#[macro_use]
extern crate async_trait;
#[cfg(any(feature = "daemon"))]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate derive_wrapper;
#[macro_use]
extern crate serde;
#[cfg(any(feature = "daemon", feature = "cli"))]
#[macro_use]
extern crate clap;
#[cfg(any(feature = "daemon", feature = "cli"))]
#[macro_use]
extern crate log;
#[cfg(feature = "daemon")]
#[macro_use]
extern crate num_derive;
#[macro_use]
extern crate lnpbp_derive;
#[cfg(feature = "server")]
extern crate settings;

pub mod api;
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(any(feature = "integration", feature = "daemon"))]
pub mod constants;
#[cfg(feature = "daemon")]
pub mod daemon;
#[cfg(any(feature = "integration", feature = "daemon"))]
pub mod error;
#[cfg(any(feature = "integration", feature = "daemon"))]
pub mod i9n;
#[cfg(feature = "daemon")]
pub mod vault;

#[cfg(any(feature = "integration", feature = "daemon"))]
pub use constants::*;
#[cfg(feature = "daemon")]
pub use vault::Vault;
