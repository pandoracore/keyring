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

use internet2::zmqsocket::{self, ZmqType};
use internet2::{
    session, CreateUnmarshaller, PlainTranscoder, Session, TypedEnum,
    Unmarshall, Unmarshaller,
};

use super::Config;
use crate::error::BootstrapError;
use crate::rpc::{self, Reply, Request};

#[repr(C)]
pub struct Client {
    config: Config,
    session_rpc: session::Raw<PlainTranscoder, zmqsocket::Connection>,
    unmarshaller: Unmarshaller<Reply>,
}

impl Client {
    pub fn with(config: Config) -> Result<Self, BootstrapError> {
        debug!("Initializing runtime");
        trace!("Connecting to keyring daemon at {}", config.endpoint);
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

    pub fn request(
        &mut self,
        mut request: Request,
    ) -> Result<Reply, rpc::Error> {
        // Inserting decryption key if needed
        if let Some(decryption_key) = match request {
            Request::ExportXpriv(ref mut req) => Some(&mut req.decryption_key),
            Request::Derive(ref mut req) => Some(&mut req.decryption_key),
            Request::SignPsbt(ref mut req) => Some(&mut req.decryption_key),
            Request::SignKey(ref mut req) => Some(&mut req.decryption_key),
            Request::SignData(ref mut req) => Some(&mut req.decryption_key),
            _ => None,
        } {
            *decryption_key = self.config.node_key;
        }

        trace!("Sending request to the server: {:?}", request);
        let data = request.serialize();
        trace!("Raw request data ({} bytes): {:?}", data.len(), data);
        self.session_rpc.send_raw_message(&data)?;
        trace!("Awaiting reply");
        let raw = self.session_rpc.recv_raw_message()?;
        trace!("Got reply ({} bytes), parsing", raw.len());
        let reply = self.unmarshaller.unmarshall(&raw)?;
        trace!("Reply: {:?}", reply);
        Ok((&*reply).clone())
    }
}
