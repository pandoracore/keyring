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

use bitcoin_wallet::{account::Seed, context::SecpContext};

use lnpbp::bitcoin;
use lnpbp::bitcoin::secp256k1;
use lnpbp::bitcoin::util::bip32::{DerivationPath, ExtendedPubKey};
use lnpbp::bp;
use lnpbp::rand::{thread_rng, RngCore};

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
    encrypted: Vec<u8>,
    name: String,
    details: String,
    derivation: Option<DerivationPath>,
}

impl Account {
    pub fn new(
        name: String,
        details: String,
        derivation: Option<DerivationPath>,
        encryption_key: &secp256k1::PublicKey,
    ) -> Self {
        let mut random = vec![0u8; 32];
        thread_rng().fill_bytes(random.as_mut_slice());
        let seed = Seed(random);
        let context = SecpContext::new();
        let encrypted = seed
            .encrypt_elgamal(encryption_key)
            .expect("Encryption failed");
        let master_key = context
            .master_private_key(bitcoin::Network::Bitcoin, &seed)
            .expect("Public key generation failed");
        let xpubkey = context.extended_public_from_private(&master_key);
        Self {
            xpubkey,
            encrypted,
            name,
            details,
            derivation,
        }
    }
}
