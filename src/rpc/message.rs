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

use bitcoin::hash_types::XpubIdentifier;
use bitcoin::secp256k1::SecretKey;
use bitcoin::util::bip32::DerivationPath;
use bitcoin::util::psbt::PartiallySignedTransaction;
use lnpbp::chain::{AssetId, Chain};
use slip132::KeyApplication;

use super::types::AuthCode;

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[display("{name}, {chain}, {application:?} ...")]
pub struct Seed {
    pub name: String,
    pub chain: Chain,
    pub application: KeyApplication,
    pub description: Option<String>,
    pub auth_code: AuthCode,
}

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[display("{key_id}, ...")]
pub struct Export {
    pub key_id: XpubIdentifier,
    pub decryption_key: SecretKey,
    pub auth_code: AuthCode,
}

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[display("{from}, {path}, {name}, ...")]
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
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[display("...")]
pub struct SignPsbt {
    pub psbt: PartiallySignedTransaction,
    pub decryption_key: SecretKey,
    pub auth_code: AuthCode,
}

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[display("{key_id}, ...")]
pub struct SignKey {
    pub key_id: XpubIdentifier,
    pub decryption_key: SecretKey,
    pub auth_code: AuthCode,
}

#[derive(Clone, Debug, Display, StrictEncode, StrictDecode)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[display("{key_id}, {data:#x?}, ...")]
pub struct SignData {
    pub key_id: XpubIdentifier,
    pub data: Vec<u8>,
    pub decryption_key: SecretKey,
    pub auth_code: AuthCode,
}
