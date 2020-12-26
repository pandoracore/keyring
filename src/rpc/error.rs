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

use amplify::IoError;
use lnpbp::bitcoin;
use lnpbp::lnp;
use lnpbp_services::rpc::Failure;

#[derive(Clone, Debug, Display, Error, From)]
#[display(Debug)]
pub enum Error {
    UnexpectedServerResponse,

    #[from(std::io::Error)]
    Io(IoError),

    #[from(bitcoin::consensus::encode::Error)]
    Encoding,

    #[from]
    ServerFailure(Failure),

    #[from]
    PresentationError(lnp::presentation::Error),

    #[from]
    TransportError(lnp::transport::Error),
}

impl lnpbp_services::error::Error for Error {}
