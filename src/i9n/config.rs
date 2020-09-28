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

use lnpbp::lnp::transport::zmq::SocketLocator;

use crate::constants::KEYRING_ZMQ_ENDPOINT;

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display(Debug)]
pub struct Config {
    pub endpoint: SocketLocator,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // TODO: Replace on KEYRING_TCP_ENDPOINT
            endpoint: KEYRING_ZMQ_ENDPOINT
                .parse()
                .expect("Error in KEYRING_ZMQ_ENDPOINT constant value"),
        }
    }
}
