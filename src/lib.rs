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

#![recursion_limit = "256"]
// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code
    // missing_docs,
)]

#[cfg_attr(any(feature = "server", feature = "embedded"), macro_use)]
extern crate amplify;
#[macro_use]
extern crate amplify_derive;
#[macro_use]
extern crate lnpbp;
#[macro_use]
extern crate internet2;
#[macro_use]
extern crate lazy_static;

#[cfg(feature = "serde")]
extern crate serde_crate as serde;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_with;

#[cfg(feature = "clap")]
extern crate clap;
#[cfg(feature = "log")]
#[macro_use]
extern crate log;

#[cfg(feature = "cli")]
pub mod cli;
mod error;
#[cfg(any(feature = "shell", feature = "embedded"))]
pub(crate) mod opts;
#[cfg(any(feature = "node", feature = "client"))]
pub mod rpc;

#[cfg(feature = "node")]
pub mod daemon;
#[cfg(feature = "node")]
pub mod vault;
#[cfg(feature = "node")]
pub use vault::Vault;

pub use error::RuntimeError;
#[cfg(any(feature = "shell"))]
pub use opts::Opts;

lazy_static! {
    /// Global Secp256k1 context object
    pub static ref SECP256K1: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All> =
        bitcoin::secp256k1::Secp256k1::new();
}
