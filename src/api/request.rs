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

#[derive(Clone, Debug, Display, LnpApi)]
#[lnp_api(encoding = "strict")]
#[display_from(Debug)]
#[non_exhaustive]
pub enum Request {
    #[lnp_api(type = 0x0010)]
    List,

    #[lnp_api(type = 0x0020)]
    Seed(crate::api::message::Seed),

    #[lnp_api(type = 0x0030)]
    ExportXpub(crate::api::message::Export),

    #[lnp_api(type = 0x0032)]
    ExportXpriv(crate::api::message::Export),

    #[lnp_api(type = 0x0040)]
    Derive(crate::api::message::Derive),

    #[lnp_api(type = 0x0050)]
    SignPsbt(crate::api::message::SignPsbt),

    #[lnp_api(type = 0x0052)]
    SignKey(crate::api::message::SignKey),

    #[lnp_api(type = 0x0054)]
    SignData(crate::api::message::SignData),
}
