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

#![feature(never_type)]

#[macro_use]
extern crate async_trait;
#[macro_use]
extern crate derive_wrapper;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lnpbp;
#[macro_use]
extern crate lnpbp_derive;

pub mod cli;
mod constants;
pub mod daemon;
pub mod error;
pub(crate) mod rpc;
pub(crate) mod vault;

pub use constants::*;
pub use vault::Vault;
