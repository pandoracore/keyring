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

pub(super) const MSG_TYPE_SUCCESS: u16 = 0x0001;
pub(super) const MSG_TYPE_FAILURE: u16 = 0x0000;
pub(super) const MSG_TYPE_KEYS: u16 = 0x0100;
pub(super) const MSG_TYPE_KEYLIST: u16 = 0x0101;
pub(super) const MSG_TYPE_SEED: u16 = 0x0200;
pub(super) const MSG_TYPE_EXPORT: u16 = 0x0300;
pub(super) const MSG_TYPE_XPRIV: u16 = 0x0301;
pub(super) const MSG_TYPE_XPUB: u16 = 0x0302;
pub(super) const MSG_TYPE_DERIVE: u16 = 0x0400;

pub type AuthCode = u32;

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[display_from(Debug)]
#[non_exhaustive]
pub struct Key {
    pub id: XpubIdentifier,
    pub xpubkey: ExtendedPubKey,
    pub path: DerivationPath,
    pub fingerprint: Fingerprint,
}
