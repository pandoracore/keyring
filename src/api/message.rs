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
use lnpbp::bitcoin::secp256k1::SecretKey;
use lnpbp::bitcoin::util::bip32::{DerivationPath, KeyApplication};
use lnpbp::bitcoin::util::psbt::PartiallySignedTransaction;
use lnpbp::bp::chain::AssetId;
use lnpbp::bp::Chain;

use super::types::AuthCode;

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[display_from(Debug)]
pub struct Failure {
    pub code: u16,
    pub info: String,
}

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[display_from(Debug)]
pub struct Seed {
    pub name: String,
    pub chain: Chain,
    pub application: KeyApplication,
    pub description: Option<String>,
    pub auth_code: AuthCode,
}

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[display_from(Debug)]
pub struct Export {
    pub key_id: XpubIdentifier,
    pub decryption_key: SecretKey,
    pub auth_code: AuthCode,
}

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[display_from(Debug)]
pub struct Derive {
    pub from: XpubIdentifier,
    pub path: DerivationPath,
    pub name: String,
    pub details: String,
    pub assets: HashSet<AssetId>,
    pub decryption_key: SecretKey,
    pub auth_code: AuthCode,
}

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[display_from(Debug)]
pub struct SignPsbt {
    pub psbt: PartiallySignedTransaction,
    pub auth_code: AuthCode,
}

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[display_from(Debug)]
pub struct SignKey {
    pub key_id: XpubIdentifier,
    pub auth_code: AuthCode,
}

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[display_from(Debug)]
pub struct SignData {
    pub data: Vec<u8>,
    pub auth_code: AuthCode,
}
