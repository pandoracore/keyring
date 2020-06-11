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

use lnpbp::bitcoin::util::bip32::{DerivationPath, ExtendedPubKey};

#[derive(
    Getters,
    Clone,
    PartialEq,
    Eq,
    Display,
    Debug,
    Serialize,
    Deserialize,
    StrictEncode,
    StrictDecode,
)]
#[display_from(Debug)]
pub struct Account {
    xpubkey: ExtendedPubKey,
    encrypted_xprivkey: Vec<u8>,
    name: String,
    details: String,
    derivation: Option<DerivationPath>,
}

impl Account {
    pub fn new() -> Self {
        unimplemented!()
    }
}
