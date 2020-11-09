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

use lnpbp::lnp::presentation::Encode;
use lnpbp::lnp::zmqsocket::{self, ZmqType};
use lnpbp::lnp::{
    session, CreateUnmarshaller, PlainTranscoder, Session, Unmarshall,
    Unmarshaller,
};

use super::Config;
use crate::api::{self, Reply, Request};
use crate::error::BootstrapError;

pub struct Runtime {
    pub(super) config: Config,
    pub(super) session_rpc:
        session::Raw<PlainTranscoder, zmqsocket::Connection>,
    pub(super) unmarshaller: Unmarshaller<Reply>,
}

impl Runtime {
    pub fn init(config: Config) -> Result<Self, BootstrapError> {
        let session_rpc = session::Raw::with_zmq_unencrypted(
            ZmqType::Req,
            &config.endpoint,
            None,
            None,
        )?;
        Ok(Self {
            config,
            session_rpc,
            unmarshaller: Reply::create_unmarshaller(),
        })
    }

    pub fn request(&mut self, request: Request) -> Result<Reply, api::Error> {
        let data = request.encode()?;
        self.session_rpc.send_raw_message(&data)?;
        let raw = self.session_rpc.recv_raw_message()?;
        let reply = self.unmarshaller.unmarshall(&raw)?;
        Ok((&*reply).clone())
    }
}
