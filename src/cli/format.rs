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

use clap::Clap;

#[derive(Clap, Copy, Clone, Debug, Display)]
#[display(doc_comments)]
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

#[derive(Clap, Copy, Clone, Debug, Display)]
#[display(Debug)]
pub enum KeyType {
    A,
}

impl Default for KeyType {
    fn default() -> Self {
        Self::A
    }
}

#[derive(Clap, Copy, Clone, Debug, Display)]
#[display(doc_comments)]
pub enum SigHashType {
    /// SIGHASH_ALL
    All,

    /// SIGHASH_NONE
    None,

    /// SIGHASH_SINGLE
    Single,

    /// |ANYONE_CAN_PAY
    AnyoneCanPay,
}
