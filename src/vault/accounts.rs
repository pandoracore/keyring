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

use serde::{Deserialize, Deserializer, Serializer};
use std::convert::TryFrom;

use lnpbp::bitcoin;
use lnpbp::bitcoin::hashes::hex::{FromHex, ToHex};
use lnpbp::bitcoin::secp256k1;
use lnpbp::bitcoin::util::bip32::{
    DefaultResolver, DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint, KeyApplications,
    VersionResolver,
};
use lnpbp::bitcoin::XpubIdentifier;
use lnpbp::bp::Chains;
use lnpbp::elgamal::encrypt_elgamal;
use secp256k1::rand::{thread_rng, RngCore};

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
pub struct Keyring {
    xpubkey: ExtendedPubKey,
    #[serde(serialize_with = "to_hex", deserialize_with = "from_hex")]
    encrypted: Vec<u8>,
    unblinding: secp256k1::PublicKey,
    name: String,
    details: String,
    derivation: Option<DerivationPath>,
}

impl Keyring {
    /// Returns [Option::None] if any of Scep256k1 cryptographic functions fail
    /// due to negligible probability that one of generated random private keys
    /// does not belong to elliptic curve group. In this case the caller just
    /// need to retry the generation in a loop like
    /// ```
    /// # use lnpbp::bitcoin::secp256k1;
    /// # use lnpbp::bitcoin::util::bip32::KeyApplications;
    /// # use lnpbp::bp::Chains;
    /// let keyring = loop {
    ///     if let Some(kr) = Keyring::new(
    ///         Defailt::default(),
    ///         Default::default(),
    ///         Chains::Mainnet,
    ///         KeyApplications::SegWitV0Singlesig,
    ///         secp256k1::SecretKey::from_slice(&[1u8; 32])
    ///     ) { break kr }
    /// };
    /// ```
    pub fn new(
        name: String,
        details: String,
        chain: Chains,
        application: KeyApplications,
        derivation: Option<DerivationPath>,
        encryption_key: secp256k1::PublicKey,
    ) -> Option<Self> {
        let mut random = [0u8; 32];
        thread_rng().fill_bytes(&mut random);
        let mut seed = random;

        let mut xprivkey = ExtendedPrivKey::new_master(
            DefaultResolver::resolve(
                bitcoin::Network::try_from(chain).unwrap_or(bitcoin::Network::Bitcoin),
                application,
                true,
            ),
            &seed,
        )
        .ok()?;
        let xpubkey = ExtendedPubKey::from_private(&lnpbp::SECP256K1, &xprivkey)?;
        // Wiping xprv:
        thread_rng().fill_bytes(&mut random);
        xprivkey.private_key.key.add_assign(&random).ok()?;

        thread_rng().fill_bytes(&mut random);
        let mut blinding = secp256k1::SecretKey::from_slice(&random).ok()?;
        let unblinding = secp256k1::PublicKey::from_secret_key(&lnpbp::SECP256K1, &blinding);
        let encrypted = encrypt_elgamal(&seed, encryption_key, &mut blinding).ok()?;
        // Wiping out seed and blinding source
        thread_rng().fill_bytes(&mut random);
        thread_rng().fill_bytes(&mut seed);

        Some(Self {
            xpubkey,
            encrypted,
            unblinding,
            name,
            details,
            derivation,
        })
    }

    pub fn id(&self) -> XpubIdentifier {
        self.xpubkey.identifier()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.xpubkey.fingerprint()
    }
}

/// Serializes `buffer` to a lowercase hex string.
pub fn to_hex<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&buffer.as_ref().to_hex())
}

/// Deserializes a lowercase hex string to a `Vec<u8>`.
pub fn from_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| Vec::from_hex(&string).map_err(|err| Error::custom(err.to_string())))
}
