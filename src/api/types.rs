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

pub(super) const MSG_TYPE_SUCCESS: u16 = 0x0003;
pub(super) const MSG_TYPE_FAILURE: u16 = 0x0001;
pub(super) const MSG_TYPE_LIST: u16 = 0x0101;
pub(super) const MSG_TYPE_KEYLIST: u16 = 0x0103;
pub(super) const MSG_TYPE_SEED: u16 = 0x0201;
pub(super) const MSG_TYPE_EXPORT: u16 = 0x0301;
pub(super) const MSG_TYPE_XPRIV: u16 = 0x0301;
pub(super) const MSG_TYPE_XPUB: u16 = 0x0303;
pub(super) const MSG_TYPE_DERIVE: u16 = 0x0401;

pub type AuthCode = u32;

#[derive(
    Clone, PartialEq, Eq, Debug, Display, StrictEncode, StrictDecode, Serialize, Deserialize,
)]
#[display_from(Debug)]
#[non_exhaustive]
pub struct AccountInfo {
    pub id: XpubIdentifier,
    pub name: String,
    pub details: Option<String>,
    pub xpubkey: ExtendedPubKey,
    pub path: Option<DerivationPath>,
    pub fingerprint: Fingerprint,
}
