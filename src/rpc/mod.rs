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

use lnpbp::bitcoin::hash_types::XpubIdentifier;
use lnpbp::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint};

const MSG_TYPE_OK: u16 = 1;
const MSG_TYPE_ERROR: u16 = 0;
const MSG_TYPE_KEYS: u16 = 1000;
const MSG_TYPE_KEYLIST: u16 = 1001;
const MSG_TYPE_SEED: u16 = 2000;
const MSG_TYPE_EXPORT: u16 = 2100;
const MSG_TYPE_XPRIV: u16 = 2101;
const MSG_TYPE_XPUB: u16 = 2101;
const MSG_TYPE_DERIVE: u16 = 3000;

pub type AuthCode = u32;

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub struct Key {
    pub id: XpubIdentifier,
    pub xpubkey: ExtendedPubKey,
    pub path: DerivationPath,
    pub fingerprint: Fingerprint,
}

pub mod message {
    use super::AuthCode;
    use lnpbp::bitcoin::hash_types::XpubIdentifier;
    use lnpbp::bitcoin::util::bip32::DerivationPath;

    #[derive(Clone, Debug, Display)]
    #[display_from(Debug)]
    #[non_exhaustive]
    pub struct Export {
        pub key_id: XpubIdentifier,
        pub auth_code: AuthCode,
    }

    #[derive(Clone, Debug, Display)]
    #[display_from(Debug)]
    #[non_exhaustive]
    pub struct Derive {
        pub from: XpubIdentifier,
        pub path: DerivationPath,
        pub auth_code: AuthCode,
    }

    #[derive(Clone, Debug, Display)]
    #[display_from(Debug)]
    #[non_exhaustive]
    pub struct Error {
        pub code: u16,
        pub info: String,
    }
}

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum Request {
    Keys,
    Seed(AuthCode),
    Export(message::Export),
    Derive(message::Derive),
}

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum Reply {
    Ok,
    Error(message::Error),
    Keylist(Vec<Key>),
    XPriv(ExtendedPrivKey),
    XPub(ExtendedPubKey),
}
