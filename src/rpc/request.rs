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

#[derive(Clone, Debug, Display, Api)]
#[api(encoding = "strict")]
#[non_exhaustive]
pub enum Request {
    #[api(type = 0x0010)]
    #[display("list()")]
    List,

    #[api(type = 0x0020)]
    #[display("seed({0})")]
    Seed(crate::rpc::message::Seed),

    #[api(type = 0x0030)]
    #[display("exporT_xpub({0})")]
    ExportXpub(crate::rpc::message::Export),

    #[api(type = 0x0032)]
    #[display("export_xpriv({0})")]
    ExportXpriv(crate::rpc::message::Export),

    #[api(type = 0x0040)]
    #[display("derive({0})")]
    Derive(crate::rpc::message::Derive),

    #[api(type = 0x0050)]
    #[display("sign_psbt({0})")]
    SignPsbt(crate::rpc::message::SignPsbt),

    #[api(type = 0x0052)]
    #[display("sign_key({0})")]
    SignKey(crate::rpc::message::SignKey),

    #[api(type = 0x0054)]
    #[display("sign_data({0})")]
    SignData(crate::rpc::message::SignData),
}
