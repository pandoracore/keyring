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

use crate::api::message::Failure;
use lnpbp::lnp;

#[derive(Clone, Debug, Display, Error, From)]
#[display_from(Debug)]
pub enum Error {
    UnexpectedServerResponse,

    #[derive_from]
    ServerFailure(Failure),

    #[derive_from]
    PresentationError(lnp::presentation::Error),

    #[derive_from]
    TransportError(lnp::transport::Error),
}