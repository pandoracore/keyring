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

use lnpbp::lnp::presentation::Error;
use lnpbp::lnp::{Type, TypedEnum, UnknownTypeError, UnmarshallFn, Unmarshaller};
use lnpbp::strict_encoding::{strict_encode, StrictDecode};
use lnpbp::Wrapper;

use super::message;
use super::types::*;

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum Request {
    Keys,
    Seed(AuthCode),
    Export(message::Export),
    Derive(message::Derive),
}

impl TypedEnum for Request {
    fn try_from_type(type_id: Type, data: &dyn Any) -> Result<Self, UnknownTypeError> {
        Ok(match type_id.into_inner() {
            // Here we receive odd-numbered messages. However, in terms of RPC,
            // there is no "upstream processor", so we return error (but do not
            // break connection).
            _ => Err(UnknownTypeError)?,
        })
    }

    fn get_type(&self) -> Type {
        Type::from_inner(match self {
            Request::Seed(_) => MSG_TYPE_SEED,
            _ => unimplemented!(),
        })
    }

    fn get_payload(&self) -> Vec<u8> {
        match self {
            Request::Seed(auth) => strict_encode(auth).expect("Strict encoding for u32 has failed"),
            _ => unimplemented!(),
        }
    }
}

impl Request {
    pub fn create_unmarshaller() -> Unmarshaller<Self> {
        Unmarshaller::new(bmap! {
            MSG_TYPE_SEED => Self::parse_seed as UnmarshallFn<_>
        })
    }

    fn parse_seed(mut reader: &mut dyn io::Read) -> Result<Arc<dyn Any>, Error> {
        Ok(Arc::new(AuthCode::strict_decode(&mut reader)?))
    }
}
