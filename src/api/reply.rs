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

#[cfg(feature = "daemon")]
use crate::error::RuntimeError;

#[derive(Clone, Debug, Display, LnpApi)]
#[lnp_api(encoding = "strict")]
#[display(Debug)]
#[non_exhaustive]
pub enum Reply {
    #[lnp_api(type = 0x0100)]
    Success,

    #[lnp_api(type = 0x0102)]
    Failure(crate::api::message::Failure),

    #[lnp_api(type = 0x0200)]
    Keylist(Vec<crate::api::types::AccountInfo>),

    #[lnp_api(type = 0x0202)]
    AccountInfo(crate::api::types::AccountInfo),

    #[lnp_api(type = 0x0300)]
    XPriv(::lnpbp::bitcoin::util::bip32::ExtendedPrivKey),

    #[lnp_api(type = 0x0302)]
    XPub(::lnpbp::bitcoin::util::bip32::ExtendedPubKey),

    #[lnp_api(type = 0x0500)]
    Signature(::lnpbp::bitcoin::secp256k1::Signature),

    #[lnp_api(type = 0x0502)]
    Psbt(::lnpbp::bitcoin::util::psbt::PartiallySignedTransaction),
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

#[cfg(feature = "daemon")]
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
