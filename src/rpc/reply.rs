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

use core::any::Any;
use std::io;
use std::sync::Arc;

use lnpbp::bitcoin::hash_types::XpubIdentifier;
use lnpbp::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint};
use lnpbp::lnp::presentation::Error;
use lnpbp::lnp::{Type, TypedEnum, UnknownTypeError, UnmarshallFn, Unmarshaller};
use lnpbp::strict_encoding::{strict_encode, StrictDecode};
use lnpbp::Wrapper;

use super::message;
use super::types::*;

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum Reply {
    Success,
    Failure(message::Failure),
    Keylist(Vec<Key>),
    XPriv(ExtendedPrivKey),
    XPub(ExtendedPubKey),
}

impl TypedEnum for Reply {
    fn try_from_type(type_id: Type, data: &dyn Any) -> Result<Self, UnknownTypeError> {
        Ok(match type_id.into_inner() {
            MSG_TYPE_SUCCESS => Self::Success,
            MSG_TYPE_FAILURE => Self::Failure(
                data.downcast_ref::<message::Failure>()
                    .expect("Internal API parsing inconsistency")
                    .clone(),
            ),
            MSG_TYPE_KEYLIST => unimplemented!(),
            MSG_TYPE_XPUB => unimplemented!(),
            MSG_TYPE_XPRIV => unimplemented!(),

            // Here we receive odd-numbered messages. However, in terms of RPC,
            // there is no "upstream processor", so we return error (but do not
            // break connection).
            _ => Err(UnknownTypeError)?,
        })
    }

    fn get_type(&self) -> Type {
        Type::from_inner(match self {
            Reply::Success => MSG_TYPE_SUCCESS,
            Reply::Failure(_) => MSG_TYPE_FAILURE,
            _ => unimplemented!(),
        })
    }

    fn get_payload(&self) -> Vec<u8> {
        match self {
            Reply::Success => vec![],
            Reply::Failure(failure) => {
                strict_encode(failure).expect("Strict encoding for string has failed")
            }
            _ => unimplemented!(),
        }
    }
}

impl Reply {
    pub fn create_unmarshaller() -> Unmarshaller<Self> {
        Unmarshaller::new(bmap! {
            MSG_TYPE_SUCCESS => Self::parse_success as UnmarshallFn<_>,
            MSG_TYPE_FAILURE => Self::parse_failure as UnmarshallFn<_>
        })
    }

    fn parse_success(_: &mut dyn io::Read) -> Result<Arc<dyn Any>, Error> {
        struct NoData;
        Ok(Arc::new(NoData))
    }

    fn parse_failure(mut reader: &mut dyn io::Read) -> Result<Arc<dyn Any>, Error> {
        Ok(Arc::new(message::Failure::strict_decode(&mut reader)?))
    }
}

impl From<Error> for Reply {
    fn from(err: Error) -> Self {
        // TODO: Save error code taken from `Error::to_value()` after
        //       implementation of `ToValue` trait and derive macro for enums
        Reply::Failure(message::Failure {
            code: 0,
            info: format!("{}", err),
        })
    }
}
