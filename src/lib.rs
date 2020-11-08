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
#![feature(never_type, with_options, map_first_last)]

#[cfg(any(feature = "daemon"))]
#[macro_use]
extern crate amplify;
#[cfg(any(feature = "daemon"))]
#[macro_use]
extern crate async_trait;

#[cfg(feature = "cli")]
#[macro_use]
extern crate clap;

#[cfg(feature = "shell")]
#[macro_use]
extern crate log;
#[cfg(feature = "shell")]
extern crate settings;
#[cfg(feature = "shell")]
#[macro_use]
extern crate num_derive;

#[macro_use]
extern crate amplify_derive;
#[macro_use]
extern crate lnpbp_derive;
#[macro_use]
extern crate serde;

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

// TODO: Remove after migration on lnpbp_service

/// Marker trait that can be implemented for data structures used by `Clap` or
/// by any other form of API handling.
pub trait Exec {
    /// Runtime context data type, that is provided for execution context.
    type Runtime: Sized;
    /// Error type that may result from the execution
    type Error: std::error::Error;
    /// Main execution routine
    fn exec(&self, runtime: &mut Self::Runtime) -> Result<(), Self::Error>;
}

/// Trait for simpler service implementation with run loops
#[async_trait]
pub trait Service {
    /// Run loop for the service, which must never return. If you have a run
    /// loop that may fail, use [`TryService`] trait instead
    async fn run_loop(self);
}

/// Trait for simpler service implementation with run loops which may fail with
/// `TryService::ErrorType` errors; otherwise they should never return
#[async_trait]
pub trait TryService: Sized {
    /// Type of the error which is produced in case of service failure and
    /// is returned from the internal [`try_run_loop()`] procedure
    type ErrorType: std::error::Error;

    /// NB: Do not reimplement this one: the function keeps in check that if the
    /// failure happens during run loop, the program will panic reporting the
    /// failure. To implement the actual run loop please provide implementation
    /// for [`try_run_loop()`]
    async fn run_or_panic(self, service_name: &str) {
        panic!(match self.try_run_loop().await {
            Err(err) => {
                format!(
                    "{} run loop has failed with error {}",
                    service_name, err
                );
            }
            Ok(_) => {
                format!(
                    "{} has failed without reporting a error",
                    service_name
                );
            }
        })
    }

    /// Main failable run loop implementation. Must produce an error of type
    /// [`TryService::ErrorType`] or never return.
    async fn try_run_loop(self) -> Result<(), Self::ErrorType>;
}
