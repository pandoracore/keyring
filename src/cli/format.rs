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

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

#[derive(Clap, Copy, Clone, Debug, DisplayEnum)]
pub enum BinaryData {
    /// Raw/binary file with data
    File,

    /// Data encoded as hexadecimal (Base16) string
    Hex,

    /// Data encoded as Base64 string
    Base64,
}

impl Default for BinaryData {
    fn default() -> Self {
        BinaryData::Hex
    }
}

#[derive(Clap, Copy, Clone, Debug, DisplayEnum)]
pub enum Script {
    /// Binary script source encoded as hexadecimal string
    Hex,

    /// Binary script source encoded as Base64 string
    Base64,

    /// Miniscript string or descriptor
    Miniscript,

    /// String with opcodes
    Opcode,
}

impl Default for Script {
    fn default() -> Self {
        Script::Miniscript
    }
}

#[derive(Clap, Copy, Clone, Debug, DisplayEnum)]
pub enum StructuredData {
    /// JSON
    Json,

    /// YAML
    Yaml,

    /// TOML
    Toml,

    /// Strict encoding - hex representation
    StrictHex,

    /// Strict encoding - Bech32 representation
    StrictBech32,

    /// Strict encoding - base64 representation
    StrictBase64,
}

#[derive(Clap, Copy, Clone, Debug, DisplayEnum)]
pub enum Tx {
    /// Binary transaction data
    Binary,

    /// Transaction encoded as hexadecimal string
    Hex,

    /// Transaction encoded with Base64 encoding
    Base64,

    /// JSON description of transaction structure
    Json,

    /// YAML description of transaction structure
    Yaml,

    /// TOML description of transaction structure
    Toml,
}

impl Default for Tx {
    fn default() -> Self {
        Tx::Binary
    }
}

#[derive(Clap, Copy, Clone, Debug, DisplayEnum)]
pub enum Psbt {
    /// Binary PSBT data
    Binary,

    /// Hexadecimal encoding of PSBT data
    Hex,

    /// Base64 encoding of PSBT data
    Base64,

    /// JSON description of PSBT structure
    Json,

    /// YAML description of PSBT structure
    Yaml,

    /// TOML description of PSBT structure
    Toml,
}

impl Default for Psbt {
    fn default() -> Self {
        Self::Base64
    }
}

#[derive(Clap, Copy, Clone, Debug, DisplayEnum)]
pub enum KeyType {
    A,
}

impl Default for KeyType {
    fn default() -> Self {
        Self::A
    }
}

#[derive(Clap, Copy, Clone, Debug)]
pub enum SigHashType {
    All,
    None,
    Single,
    AnyoneCanPay,
}
