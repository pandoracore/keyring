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

//use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};
use internet2::presentation::Error;

#[cfg(any(feature = "server", feature = "embedded"))]
use crate::error::RuntimeError;

#[derive(Clone, Debug, Display, Api)]
#[api(encoding = "strict")]
#[non_exhaustive]
pub enum Reply {
    #[api(type = 0x0100)]
    #[display("success()")]
    Success,

    #[api(type = 0x0102)]
    #[display("failure({0})")]
    Failure(microservices::rpc::Failure),

    #[api(type = 0x0200)]
    #[display("keylist(...)")]
    Keylist(Vec<crate::rpc::types::AccountInfo>),

    #[api(type = 0x0202)]
    #[display("account_info({0})")]
    AccountInfo(crate::rpc::types::AccountInfo),

    #[api(type = 0x0300)]
    #[display("xpriv(...)")]
    XPriv(::bitcoin::util::bip32::ExtendedPrivKey),

    #[api(type = 0x0302)]
    #[display("xpub({0})")]
    XPub(::bitcoin::util::bip32::ExtendedPubKey),

    #[api(type = 0x0500)]
    #[display("signature({0})")]
    Signature(::bitcoin::secp256k1::Signature),

    #[api(type = 0x0502)]
    #[display("psbt(...)")]
    Psbt(::bitcoin::util::psbt::PartiallySignedTransaction),
}

impl From<Error> for Reply {
    fn from(err: Error) -> Self {
        // TODO: Save error code taken from `Error::to_value()` after
        //       implementation of `ToValue` trait and derive macro for enums
        Reply::Failure(microservices::rpc::Failure {
            code: 0,
            info: format!("{}", err),
        })
    }
}

#[cfg(any(feature = "server", feature = "embedded"))]
impl From<RuntimeError> for Reply {
    fn from(err: RuntimeError) -> Self {
        // TODO: Save error code taken from `Error::to_value()` after
        //       implementation of `ToValue` trait and derive macro for enums
        Reply::Failure(microservices::rpc::Failure {
            code: 0,
            info: format!("{}", err),
        })
    }
}
