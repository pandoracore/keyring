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

use std::collections::HashSet;

use lnpbp::bitcoin::hash_types::XpubIdentifier;
use lnpbp::bitcoin::util::bip32::KeySource;
use lnpbp::bitcoin::util::bip32::{
    DefaultResolver, Fingerprint, KeyApplication,
};
use lnpbp::bp::chain::AssetId;

#[cfg(feature = "daemon")]
use crate::vault::{Keyring, KeysAccount};

pub type AuthCode = u32;

#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
    Serialize,
    Deserialize,
)]
#[display_from(Debug)]
#[non_exhaustive]
pub struct AccountInfo {
    pub id: XpubIdentifier,
    pub name: String,
    pub details: Option<String>,
    pub key_id: XpubIdentifier,
    pub fingerprint: Fingerprint,
    pub assets: HashSet<AssetId>,
    pub application: Option<KeyApplication>,
    pub key_source: Option<KeySource>,
}

#[cfg(feature = "daemon")]
impl From<&Keyring> for AccountInfo {
    fn from(keyring: &Keyring) -> Self {
        let mut info = AccountInfo::from(keyring.master_account());
        info.key_source = keyring.key_source().clone();
        info
    }
}

#[cfg(feature = "daemon")]
impl From<&KeysAccount> for AccountInfo {
    fn from(account: &KeysAccount) -> Self {
        let details = match account.details().len() {
            0 => None,
            _ => Some(account.details().clone()),
        };
        Self {
            id: account.identifier(),
            name: account.name().clone(),
            details,
            key_id: account.identifier(),
            fingerprint: account.fingerprint(),
            application: account
                .xpubkey()
                .version
                .application::<DefaultResolver>(),
            assets: account.assets().clone(),
            key_source: None,
        }
    }
}
