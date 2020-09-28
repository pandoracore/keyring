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

//! Mod defines data structures and error types related to the storage and
//! operations with keyrings and keys accounts in the vault. You may think of
//! keys accounts like a key from a banking cell; where each cell can be opened
//! by different combinations of different keys. Keyring is a set of keys,
//! suited for a given category of bank cells.
//!
//! # Vault key managemet
//!
//! Vault contains a list of Keyrings, each of which has a master key account,
//! which may be derived from some seed directly or under certain derivation
//! path; and a list of subaccounts, derived with well-defined derivation paths
//! from the master account.

use serde::{Deserialize, Deserializer, Serializer};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::convert::TryFrom;

use lnpbp::bitcoin;
use lnpbp::bitcoin::hashes::hex::{FromHex, ToHex};
use lnpbp::bitcoin::secp256k1;
use lnpbp::bitcoin::util::bip32::{
    self, DefaultResolver, DerivationPath, ExtendedPrivKey, ExtendedPubKey,
    Fingerprint, IntoDerivationPath, KeyApplication, KeySource,
    VersionResolver,
};
use lnpbp::bitcoin::XpubIdentifier;
use lnpbp::bp::chain::AssetId;
use lnpbp::bp::Chain;
use lnpbp::elgamal;
use lnpbp::miniscript::bitcoin::secp256k1::Signature;
use secp256k1::rand::{thread_rng, RngCore};

/// Error cases related to keyring & keys account management and usage
#[derive(Clone, PartialEq, Eq, Debug, Display, From, Error)]
#[display(Debug)]
pub enum Error {
    /// Error indicating that secret/private key generation failed due to
    /// the fact that produced entropy was not a member of Secp256k1 elliptic
    /// curve group Z.
    ///
    /// This error has a negligible probability: much less than a meteorite
    /// hitting right into the computer while you are reading this sentence, so
    /// you can either simply ignore it with `unwrap()`/`expect()`, or handle
    /// by calling the function within a loop so if this error happens the
    /// function is just got re-called.
    PrivkeyGeneration,

    /// Elliptic curve operation lead to an overflow (i.e. for instance a
    /// public key tweak can't be applied, resulting in a point at infinity)
    GroupOverflow,

    /// The account keys can't be derived with hardened path; a private key
    /// is required. The error is returned by [KeysAccount::derive] function
    /// if a hardened derivation path is used, but no decryption key for the
    /// secret key is provided.
    HardenedDerivation,

    /// This error implies that secret key storage was corrupted and that
    /// either the encrypted key has wrong length or wrong bytes, so
    /// ElGamal algorithm can't process/decrypt it.
    SecretKeyCorrupted,

    /// Run out of memory during encryption/decryption process
    NotEnoughMemory,

    /// Secp256k1 library returned an unexpected error type, implying that the
    /// library code was changed in an incompatible way or broken and
    /// needs devs attention
    Secp256k1Broken,

    /// Produced when trying to derive a subaccount with a derivation path
    /// that is already used by some other key (including empty derivation path
    /// corresponding to the master key)
    DerivationAlreadyUsed,

    /// Produced when the item is not found, for instance a subaccount with a
    /// given derivation path does not exist.
    NotFound,

    /// Lists assets ids for which operation has failed (for instance, these
    /// asset ids are not known or do not exist)
    AssetIds(HashSet<AssetId>),

    /// Indicates function failure due to the fact that it has no operation to
    /// perform for a given set of the function arguments
    NoOp,

    /// Indicates failure when some operation can't be applied to the master
    /// account (i.e. account with none/empty derivation path)
    MasterAccount,

    /// Indicates failure to parse derivation path, for instance using
    /// [`FromStr`] or [`TryFrom`]/[`TryInto`] traits
    #[from(bip32::Error)]
    InvalidDerivationPath,

    /// Error happens when operations related to [`ExtendedPubKey`] or
    /// [`ExtendedPrivKey`] resolving tasks has failed. Key resolving is done
    /// using resolvers implementing [`VersionResolver`], and fail if there
    /// is no known matches of key version to the network and other type
    /// information.
    ResolverFailure,
}

impl From<elgamal::Error> for Error {
    fn from(err: elgamal::Error) -> Self {
        match err {
            elgamal::Error::UnpaddedLength
            | elgamal::Error::InvalidEncryptedMessage => {
                Self::SecretKeyCorrupted
            }
            elgamal::Error::GroupOverflow => Self::GroupOverflow,
            elgamal::Error::NotEnoughMemory => Self::NotEnoughMemory,
            elgamal::Error::Secp256k1Broken => Self::Secp256k1Broken,
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Self {
        match err {
            secp256k1::Error::InvalidSecretKey => Self::PrivkeyGeneration,
            secp256k1::Error::InvalidTweak => Self::GroupOverflow,
            _ => Self::Secp256k1Broken,
        }
    }
}

/// Mode for an update operation
#[derive(Copy, Clone, PartialEq, Eq, Debug, Display)]
#[display(Debug)]
pub enum UpdateMode {
    /// Add new qualifiers to existing ones
    Add,

    /// Add new qualifiers **replacing** existing ones
    Replace,

    /// Removes qualifiers from the provided list; if some of the qualifiers
    /// are not found just ignore them and process the rest
    RemoveIgnore,

    /// Removes qualifiers from the provided list; if any of the qualifiers
    /// is not found then the function fails returning error, not updating any
    /// of the qualifiers
    RemoveOrFail,
}

impl Default for UpdateMode {
    fn default() -> Self {
        Self::Add
    }
}

/// Keyring is a root account governed by the single extended private/public key
/// pair. This pair can be a master key - or represent some derivation from
/// another master; however in this case this master should not a be part of the
/// same vault.
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
#[display(Debug)]
pub struct Keyring {
    master_account: KeysAccount,
    key_source: Option<KeySource>,
    sub_accounts: BTreeMap<DerivationPath, KeysAccount>,
}

impl Keyring {
    /// Returns [Option::None] if any of Scep256k1 cryptographic functions fail
    /// due to negligible probability that one of generated random private keys
    /// does not belong to elliptic curve group. In this case the caller just
    /// need to retry the generation in a loop like
    /// ```
    /// #[macro_use]
    /// extern crate amplify;
    ///
    /// use std::str::FromStr;
    /// use lnpbp::bitcoin::secp256k1;
    /// use lnpbp::bitcoin::util::bip32::KeyApplication;
    /// use lnpbp::bp::Chain;
    ///
    /// let keyring = loop {
    ///     if let Some(kr) = Keyring::new(
    ///         "Main account",
    ///         "Default",
    ///         &Chain::Mainnet,
    ///         KeyApplication::SegWitV0Singlesig,
    ///         None,
    ///         secp256k1::PublicKey::from_str(
    ///             "03933615cab8f016c8375602884804b56061bcdd8fe362eb7e12c87d61c5275c5f"
    ///         ).unwrap()
    ///     ) {
    ///         break kr;
    ///     }
    /// };
    /// ```
    pub fn with(
        name: impl ToString,
        details: impl ToString,
        chain: &Chain,
        application: KeyApplication,
        key_source: Option<KeySource>,
        encryption_key: secp256k1::PublicKey,
    ) -> Result<Self, Error> {
        let master_account = KeysAccount::with(
            name,
            details,
            set![],
            chain,
            application,
            encryption_key,
        )?;
        Ok(Self {
            master_account,
            key_source,
            sub_accounts: Default::default(),
        })
    }

    /// Returns name of the keyring
    pub fn name(&self) -> &String {
        &self.master_account.name
    }

    /// Returns detailed description of the keyring (use purpose)
    pub fn details(&self) -> &String {
        &self.master_account.details
    }

    /// Returns extended public key identifier from the master account
    pub fn identifier(&self) -> XpubIdentifier {
        self.master_account.identifier()
    }

    /// Returns fingerprint of the extended public key from the master account
    pub fn fingerprint(&self) -> Fingerprint {
        self.master_account.fingerprint()
    }

    /// Returns master extended master public key of the keyring
    pub fn master_xpubkey(&self) -> &ExtendedPubKey {
        &self.master_account.xpubkey
    }

    /// Returns [`KeysAccount`] for a given `key_id`, or [`Option::None`] if
    /// account does not exist under the current keyring
    pub fn account_by_id(
        &self,
        key_id: XpubIdentifier,
    ) -> Option<&KeysAccount> {
        if self.identifier() == key_id {
            Some(&self.master_account)
        } else {
            self.sub_accounts
                .iter()
                .find(|(_, account)| account.identifier() == key_id)
                .map(|v| v.1)
        }
    }

    /// Creates new sub-account and does all required derivation for a given
    /// derivation path [`DerivationPath`] and a list of assets identified by
    /// respective [`AssetId`] (may be empty). Returns derivation error if the
    /// path is already used or the provided `decryption_key` is invalid;
    /// otherwise returns a newly created [`KeysAccount`]
    ///
    /// # Example
    ///
    /// ```
    /// #[macro_use]
    /// extern crate amplify;
    ///
    /// use keyring::vault::keymgm::{Error, Keyring, KeysAccount, UpdateMode};
    /// use lnpbp::bitcoin::secp256k1;
    /// use lnpbp::bitcoin::util::bip32::{DerivationPath, KeyApplication};
    /// use lnpbp::bp::Chain;
    /// use std::str::FromStr;
    ///
    /// # fn main() -> Result<(), Error> {
    /// let keyring = Keyring::with(
    ///     "Sample", "",
    ///     &Chain::Mainnet,
    ///     KeyApplication::SegWitV0Singlesig,
    ///     None,
    ///     secp256k1::PublicKey::from_str(
    ///         "03933615cab8f016c8375602884804b56061bcdd8fe362eb7e12c87d61c5275c5f"
    ///     ).unwrap()
    /// ).expect("We can safely do it here due to negligible error probability");
    ///
    /// let dumb_asset = AssetId::hash("dumb data");
    ///
    /// keyring.create_account(
    ///     "m/0/1",
    ///     "Default",
    ///     "",
    ///     set![dumb_asset],
    ///     secp256k1::key::ONE_KEY, // Don't use this in real-world cases
    /// )?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn create_account(
        &mut self,
        derivation: impl IntoDerivationPath,
        name: impl ToString,
        details: impl ToString,
        assets: HashSet<AssetId>,
        decryption_key: &mut secp256k1::SecretKey,
    ) -> Result<&KeysAccount, Error> {
        let derivation = derivation.into_derivation_path()?;

        // Check if the derivation path is already used and return error
        if self.derivation_paths().contains(&derivation) {
            return Err(Error::DerivationAlreadyUsed);
        }

        // Find a proper extended key to derive from: it must be the one
        // which is maximally close to the derivation target by its path
        let derivation_ref = derivation.as_ref();
        let mut sorted = self
            .all_accounts()
            .into_iter()
            .map(|(path, acc)| {
                let path_ref = path.as_ref();
                if path_ref.len() < derivation_ref.len()
                    && path_ref == &derivation_ref[..path_ref.len()]
                {
                    Some((&derivation[path_ref.len()..], acc))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        sorted.sort_by(|item1, item2| {
            if let (Some((path1, ..)), Some((path2, ..))) = (item1, item2) {
                path1.len().cmp(&path2.len())
            } else {
                Ordering::Equal
            }
        });
        let from = sorted.first().expect(
            "We always have at least one element equal to the master key path",
        ).expect("...and we know that this element is a parent item");

        // Do a derivation starting from the found key account
        let account =
            from.1
                .derive(from.0, name, details, assets, decryption_key)?;
        self.sub_accounts.insert(derivation.clone(), account);
        Ok(self.sub_accounts.get(&derivation).unwrap())
    }

    /// Updates name and/or details for the keyring
    ///
    /// # Returns
    ///
    /// If both name and details are [`Option::None`], returns [`Error:NoOp`];
    /// otherwise returns `Ok()`
    pub fn update_master(
        &mut self,
        name: Option<impl ToString>,
        details: Option<impl ToString>,
    ) -> Result<(), Error> {
        self.master_account.update(
            name,
            details,
            None,
            UpdateMode::default(),
        )?;
        Ok(())
    }

    /// Updates one of the sub-accounts identified by a `derivation` path
    /// [`DerivationPath`], returning error [`Error::NotFound`] if the account
    /// with the path does not exist.
    ///
    /// # Parameters
    ///
    /// - `derivation`: subaccount identifier
    /// - `name`: new account name in a form of [`Option::Some`]; it the name
    ///   should not be changed use [`Option::None`]
    /// - `details`: new account details in a form of [`Option::Some`]; it the
    ///   details should not be changed use [`Option::None`]
    /// - `assets`: update information for the asset list. If none of the asset
    ///   information should be changed, use [`Option::None`]. Otherwise, the
    ///   value of this argument is interpreted depending on the `update_mode`
    ///   argument:
    /// - `update_mode`: how the asset information update has to be processed:
    ///   * [`UpdateMode::Add`] extend the list of assets with the provided
    ///     additional assets from the `assets` argument
    ///   * [`UpdateMode::Replace`] replace all assets with the list of the
    ///     provided assets from the `assets` argument
    ///   * [`UpdateMode::RemoveIgnore`] remove only those assets which are
    ///     provided in the `assets` list; if any of the asset ids are not found
    ///     the function ignores them
    ///   * [`UpdateMode::RemoveOrFail`] remove only those assets which are
    ///     provided in the `assets` list; if any of the asset ids are not found
    ///     the function fails by returning [`Error::AssetIds`] listing all not
    ///     found asset ids. In this case, none of the assets (even those, which
    ///     were present) are removed.
    ///   If the `assets` argument is set to [`Option::None`], the value of the
    ///   `update_mode` is ignored and can be safely set to
    ///   [`Default::default()`]
    ///
    /// # Returns
    ///
    /// If the operation was successful, number of updated asset ids inside of
    /// [`Result::Ok`] (zero if none of the assets were provided or updated).
    /// Otherwise, function returns the following errors:
    /// - [`Error::MasterAccount`] if the function was provided with an empty
    ///   (i.e. master) `derivation` path
    /// - [`Error::NoOp`], if no update information was provided to the function
    /// - [`Error::NotFound`], if subaccount with the provided `derivation` path
    ///   does not exits
    /// - [`Error::AssetIds`], if `update_mode` was set to
    ///   [`UpdateMode::RemoveOrFail`] and at least one of the provided
    ///   [`AssetId`]'s from the `assets` argument was not found.
    ///
    /// # Examples
    ///
    /// ## Success cases
    ///
    /// ```
    /// # #[macro_use]
    /// # extern crate amplify;
    /// use keyring::vault::keymgm::{Error, Keyring, KeysAccount, UpdateMode};
    /// use lnpbp::bitcoin::secp256k1;
    /// use lnpbp::bitcoin::util::bip32::{DerivationPath, KeyApplication};
    /// use lnpbp::bp::Chain;
    /// use std::str::FromStr;
    ///
    /// # fn main() -> Result<(), Error> {
    /// let keyring = Keyring::with(
    ///     "Sample", "",
    ///     &Chain::Mainnet,
    ///     KeyApplication::SegWitV0Singlesig,
    ///     None,
    ///     secp256k1::PublicKey::from_str(
    ///         "03933615cab8f016c8375602884804b56061bcdd8fe362eb7e12c87d61c5275c5f"
    ///     ).unwrap()
    /// ).expect("We can safely do it here due to negligible error probability");
    ///
    /// let dumb_asset1 = AssetId::hash("dumb data 1");
    /// let dumb_asset2 = AssetId::hash("dumb data 2");
    ///
    /// keyring.create_account(
    ///     "m/0/1",
    ///     "Default",
    ///     "",
    ///     set![dumb_asset1],
    ///     secp256k1::key::ONE_KEY, // Don't use this in real-world cases
    /// )?;
    ///
    /// keyring
    ///     .update_subaccount(
    ///         "m/0/1",
    ///         "New name",
    ///         None,
    ///         Some(set![dumb_asset2]),
    ///         UpdateMode::Replace,
    ///     )
    ///     .unwrap();
    ///
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Failure cases
    ///
    /// Let's assume here we have a `keyring` with a single account using
    /// `dumb_asset1` from the sample above. Then, the following cases will
    /// fail:
    ///
    /// ```
    /// # #[macro_use]
    /// # extern crate amplify;
    /// # use keyring::vault::keymgm::{Error, Keyring, KeysAccount, UpdateMode};
    /// # use lnpbp::bitcoin::secp256k1;
    /// # use lnpbp::bitcoin::util::bip32::{DerivationPath, KeyApplication};
    /// # use lnpbp::bp::Chain;
    /// # use std::str::FromStr;
    /// #
    /// # fn main() -> Result<(), Error> {
    /// #
    /// # let keyring = Keyring::with(
    /// #     "Sample", "",
    /// #     &Chain::Mainnet,
    /// #     KeyApplication::SegWitV0Singlesig,
    /// #     None,
    /// #     secp256k1::PublicKey::from_str(
    /// #         "03933615cab8f016c8375602884804b56061bcdd8fe362eb7e12c87d61c5275c5f"
    /// #     ).unwrap()
    /// # ).expect("We can safely do it here due to negligible error probability");
    /// #
    ///
    /// let dumb_asset1 = AssetId::hash("dumb data 1");
    /// let dumb_asset2 = AssetId::hash("dumb data 2");
    ///
    /// keyring.create_account(
    ///     "m/0/1",
    ///     "Default",
    ///     "",
    ///     set![dumb_asset1],
    ///     secp256k1::key::ONE_KEY, // Don't use this in real-world cases
    /// )?;
    ///
    /// // We can't update master account; `update_master` must be used instead:
    /// assert_eq!(
    ///     keyring.update_subaccount("m", None, None, None, UpdateMode::Add),
    ///     Err(Error::MasterAccount)
    /// );
    ///
    /// // Nothing to update
    /// assert_eq!(
    ///     keyring.update_subaccount("m/0/1", None, None, None, UpdateMode::Add),
    ///     Err(Error::NoOp)
    /// );
    ///
    /// // Account does not exit
    /// assert_eq!(
    ///     keyring.update_subaccount("m/0/2", None, None, None, UpdateMode::Add),
    ///     Err(Error::NotFound)
    /// );
    ///
    /// // Attempt to remove an asset id which was not registered before
    /// assert_eq!(
    ///     keyring.update_subaccount(
    ///         "m/0/1",
    ///         None,
    ///         None,
    ///         Some(set![dumb_asset1, dumb_asset2]),
    ///         UpdateMode::RemoveOrFail
    ///     ),
    ///     Err(Error::AssetIds(dumb_asset2))
    /// );
    ///
    /// // But if we change `UpdateMode`, it must succeed:
    /// assert_eq!(
    ///     keyring.update_subaccount(
    ///         "m/0/1",
    ///         None,
    ///         None,
    ///         Some(set![dumb_asset2]),
    ///         UpdateMode::RemoveIgnore
    ///     ),
    ///     Ok(0)
    /// );
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn update_subaccount(
        &mut self,
        derivation: impl IntoDerivationPath,
        name: Option<impl ToString>,
        details: Option<impl ToString>,
        assets: Option<HashSet<AssetId>>,
        update_mode: UpdateMode,
    ) -> Result<usize, Error> {
        let derivation = derivation.into_derivation_path()?;

        if derivation.is_master() {
            return Err(Error::MasterAccount);
        }

        let account = if let Some(acc) = self.sub_accounts.get_mut(&derivation)
        {
            acc
        } else {
            return Err(Error::NotFound);
        };

        account.update(name, details, assets, update_mode)
    }

    /// Returns all accounts, i.e. master key account plus all subaccounts
    /// joined into a single structure
    fn all_accounts(&self) -> BTreeMap<DerivationPath, &KeysAccount> {
        let mut accounts =
            bmap! { DerivationPath::master() => &self.master_account };
        accounts.extend(self.sub_accounts.iter().map(|(k, v)| (k.clone(), v)));
        accounts
    }

    /// Collects all derivation paths used by the keys in the keyring, that
    /// includes master key zero derivation path and all subkey derivation paths
    fn derivation_paths(&self) -> BTreeSet<DerivationPath> {
        let mut paths = bset![DerivationPath::master()];
        paths
            .extend(self.sub_accounts.keys().cloned().collect::<BTreeSet<_>>());
        paths
    }
}

/// Key account is a structure holding information necessary to create a
/// transaction signature. It represents an abstraction of signature domain:
/// a specific set of use or application cases for a given area; like signatures
/// involved in a corporate account, private account, relations with particular
/// customer or a service provider etc.
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
#[display(Debug)]
pub struct KeysAccount {
    xpubkey: ExtendedPubKey,

    name: String,

    details: String,

    assets: HashSet<AssetId>,

    #[serde(serialize_with = "to_hex", deserialize_with = "from_hex")]
    encrypted: Vec<u8>,

    unblinding: secp256k1::PublicKey,
}

impl KeysAccount {
    /// Creates new keys account and does all required derivation for a given
    /// derivation path [`DerivationPath`] and a list of assets identified by
    /// respective [`AssetId`] (may be empty). Returns derivation error if the
    /// path is already used or the provided `decryption_key` is invalid;
    /// otherwise returns a newly created [`KeysAccount`]
    pub(self) fn with(
        name: impl ToString,
        details: impl ToString,
        assets: HashSet<AssetId>,
        chain: &Chain,
        application: KeyApplication,
        encryption_key: secp256k1::PublicKey,
    ) -> Result<Self, Error> {
        let mut random = [0u8; 32];
        thread_rng().fill_bytes(&mut random);
        let mut seed = random;
        // Clearing random value right after the copy takes place
        thread_rng().fill_bytes(&mut random);

        let mut xprivkey = ExtendedPrivKey::new_master(
            DefaultResolver::resolve(
                bitcoin::Network::try_from(chain)
                    .unwrap_or(bitcoin::Network::Bitcoin),
                application,
                true,
            ),
            &seed,
        )?;
        // Wiping out seed
        thread_rng().fill_bytes(&mut seed);
        // Generating extended pubkey
        let xpubkey =
            ExtendedPubKey::from_private(&lnpbp::SECP256K1, &xprivkey)
                .ok_or(Error::ResolverFailure)?;

        thread_rng().fill_bytes(&mut random);
        let mut blinding = secp256k1::SecretKey::from_slice(&random)?;
        let unblinding =
            secp256k1::PublicKey::from_secret_key(&lnpbp::SECP256K1, &blinding);
        let encrypted = elgamal::encrypt(
            &xprivkey.encode(),
            encryption_key,
            &mut blinding,
        )?;
        // Instantly wiping out xpriv:
        xprivkey.private_key.key.add_assign(&random)?;
        // Wiping out blinding source
        thread_rng().fill_bytes(&mut random);

        Ok(Self {
            xpubkey,
            name: name.to_string(),
            details: details.to_string(),
            assets,
            encrypted,
            unblinding,
        })
    }

    /// Derives a new subaccount with a given relative `derivation` path,
    /// `name`, detailed information (`details`) and a list of supported asset
    /// ids, using provided secret key `decryption_key`. The value of the
    /// decryption key is instantly reset to noise after the derivation
    /// procedure.
    pub fn derive(
        &self,
        derivation: impl IntoDerivationPath,
        name: impl ToString,
        details: impl ToString,
        assets: HashSet<AssetId>,
        mut decryption_key: &mut secp256k1::SecretKey,
    ) -> Result<KeysAccount, Error> {
        let derivation = derivation.into_derivation_path()?;

        let mut random = [0u8; 32];

        // Deriving encryption key from the decryption key
        let encryption_key = secp256k1::PublicKey::from_secret_key(
            &lnpbp::SECP256K1,
            decryption_key,
        );

        let mut master_xpriv = self.xprivkey(&mut decryption_key)?;
        let master_xpub =
            ExtendedPubKey::from_private(&lnpbp::SECP256K1, &master_xpriv)
                .ok_or(Error::ResolverFailure)?;
        if master_xpub != self.xpubkey {
            // Instantly wiping out xpriv:
            master_xpriv.private_key.key.add_assign(&random)?;
            return Err(Error::SecretKeyCorrupted);
        }

        // Deriving new secret key
        let xprivkey =
            master_xpriv.derive_priv(&lnpbp::SECP256K1, &derivation)?;
        let xpubkey =
            ExtendedPubKey::from_private(&lnpbp::SECP256K1, &xprivkey)
                .ok_or(Error::ResolverFailure)?;

        // Creating blinding and unblinding keys; doing the encryption
        thread_rng().fill_bytes(&mut random);
        let mut blinding = secp256k1::SecretKey::from_slice(&random)?;
        let unblinding =
            secp256k1::PublicKey::from_secret_key(&lnpbp::SECP256K1, &blinding);
        let encrypted = elgamal::encrypt(
            &xprivkey.encode(),
            encryption_key,
            &mut blinding,
        )?;
        // Instantly wiping out xpriv and blinding data
        thread_rng().fill_bytes(&mut random);
        master_xpriv.private_key.key.add_assign(&random)?;

        Ok(Self {
            xpubkey,
            name: name.to_string(),
            details: details.to_string(),
            assets,
            encrypted,
            unblinding,
        })
    }

    /// Returns extended public key identifier from the master account
    pub fn identifier(&self) -> XpubIdentifier {
        self.xpubkey.identifier()
    }

    /// Returns fingerprint of the extended public key from the master account
    pub fn fingerprint(&self) -> Fingerprint {
        self.xpubkey.fingerprint()
    }

    /// Returns extended private key by decrypting it's data using
    /// `decryption_key`, clearing it's content after
    pub fn xprivkey(
        &self,
        decryption_key: &mut secp256k1::SecretKey,
    ) -> Result<ExtendedPrivKey, Error> {
        let mut random = [0u8; 32];

        // Decrypting private key & clearing decryption key
        let mut secret_data =
            elgamal::decrypt(&self.encrypted, decryption_key, self.unblinding)?;

        // Instantly wiping our decryption key
        thread_rng().fill_bytes(&mut random);
        decryption_key.add_assign(&random)?;

        let xprivkey =
            ExtendedPrivKey::<DefaultResolver>::decode(&secret_data)?;
        // Wiping out secred data
        thread_rng().fill_bytes(&mut secret_data);

        Ok(xprivkey)
    }

    /// Updates information inside keys account. For information on the
    /// function check [`Keyring::update_subaccount()`]
    pub(crate) fn update(
        &mut self,
        name: Option<impl ToString>,
        details: Option<impl ToString>,
        assets: Option<HashSet<AssetId>>,
        update_mode: UpdateMode,
    ) -> Result<usize, Error> {
        if name.is_none() && details.is_none() && assets.is_none() {
            return Err(Error::NoOp);
        }

        let mut count = 0;

        if let Some(name) = name {
            self.name = name.to_string();
        }
        if let Some(details) = details {
            self.details = details.to_string();
        }
        match (assets, update_mode) {
            (Some(assets), UpdateMode::Add) => {
                count = assets.len();
                self.assets.extend(assets);
            }
            (Some(assets), UpdateMode::Replace) => {
                count = self.assets.len() + assets.len();
                self.assets = assets;
            }
            (Some(assets), UpdateMode::RemoveIgnore) => {
                assets.iter().for_each(|a| {
                    if self.assets.remove(a) {
                        count += 1
                    }
                });
            }
            (Some(assets), UpdateMode::RemoveOrFail) => {
                let diff = assets
                    .difference(&self.assets)
                    .cloned()
                    .collect::<HashSet<AssetId>>();
                if diff.is_empty() {
                    return Err(Error::AssetIds(diff));
                }
                count = self.assets.len() - assets.len();
                self.assets =
                    self.assets.difference(&assets).cloned().collect();
            }
            (None, _) => {
                // Nothing to do here
            }
        }

        Ok(count)
    }

    /// Produced signature for a given byte string `message`
    pub fn sign_digest<H>(
        &self,
        digest: H,
        mut decryption_key: &mut secp256k1::SecretKey,
    ) -> Result<Signature, Error>
    where
        // TODO: add `<LEN=secp256k::MESSAGE_SIZE>` later when <https://github.com/rust-lang/rust/issues/70256> will be solved
        H: bitcoin::hashes::Hash,
    {
        let mut random = [0u8; 32];

        let mut xprivkey = self.xprivkey(&mut decryption_key)?;

        let signature = lnpbp::SECP256K1.sign(
            &secp256k1::Message::from_slice(&digest[..])?,
            &xprivkey.private_key.key,
        );

        thread_rng().fill_bytes(&mut random);
        xprivkey.private_key.key.add_assign(&random)?;

        Ok(signature)
    }
}

/// Serializes `buffer` to a lowercase hex string.
pub(self) fn to_hex<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&buffer.as_ref().to_hex())
}

/// Deserializes a lowercase hex string to a `Vec<u8>`.
pub(self) fn from_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        Vec::from_hex(&string).map_err(|err| Error::custom(err.to_string()))
    })
}
