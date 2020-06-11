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

use super::types::AuthCode;
use lnpbp::bitcoin::hash_types::XpubIdentifier;
use lnpbp::bitcoin::util::bip32::DerivationPath;

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[display_from(Debug)]
#[non_exhaustive]
pub struct Seed {
    pub auth_code: AuthCode,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[display_from(Debug)]
#[non_exhaustive]
pub struct Export {
    pub key_id: XpubIdentifier,
    pub auth_code: AuthCode,
}

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[display_from(Debug)]
#[non_exhaustive]
pub struct Derive {
    pub from: XpubIdentifier,
    pub path: DerivationPath,
    pub auth_code: AuthCode,
}

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[display_from(Debug)]
#[non_exhaustive]
pub struct Failure {
    pub code: u16,
    pub info: String,
}
