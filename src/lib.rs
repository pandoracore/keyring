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

#[macro_use]
extern crate derive_wrapper;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate lnpbp;
#[macro_use]
extern crate lnpbp_derive;

mod cli;
mod constants;
mod daemon;
mod error;
mod rpc;
mod vault;

pub use constants::*;
pub use vault::Vault;
