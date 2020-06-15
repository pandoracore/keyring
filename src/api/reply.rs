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

//use lnpbp::bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};
use lnpbp::lnp::presentation::Error;

#[cfg(feature = "server")]
use crate::error::RuntimeError;

#[derive(Clone, Debug, Display, LnpApi)]
#[lnp_api(encoding = "strict")]
#[display_from(Debug)]
#[non_exhaustive]
pub enum Reply {
    #[lnp_api(type = 0x0003)]
    Success,

    #[lnp_api(type = 0x0001)]
    Failure(crate::api::message::Failure),

    #[lnp_api(type = 0x0103)]
    Keylist(Vec<crate::api::types::AccountInfo>),
    //#[lnp_api(type = 0x0301)]
    //XPriv(::lnpbp::bitcoin::util::bip32::ExtendedPrivKey),

    //#[lnp_api(type = 0x0303)]
    //XPub(::lnpbp::bitcoin::util::bip32::ExtendedPubKey),
}

impl From<Error> for Reply {
    fn from(err: Error) -> Self {
        // TODO: Save error code taken from `Error::to_value()` after
        //       implementation of `ToValue` trait and derive macro for enums
        Reply::Failure(crate::api::message::Failure {
            code: 0,
            info: format!("{}", err),
        })
    }
}

#[cfg(feature = "server")]
impl From<RuntimeError> for Reply {
    fn from(err: RuntimeError) -> Self {
        // TODO: Save error code taken from `Error::to_value()` after
        //       implementation of `ToValue` trait and derive macro for enums
        Reply::Failure(crate::api::message::Failure {
            code: 0,
            info: format!("{}", err),
        })
    }
}
