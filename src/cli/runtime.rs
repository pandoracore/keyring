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

use std::io;
use std::sync::Arc;

use lnpbp::lnp::presentation::{Encode, Error as LnpError};
use lnpbp::lnp::transport::zmq::ApiType;
use lnpbp::lnp::{transport, NoEncryption, Session, Unmarshall, Unmarshaller};

use super::{Config, Error};
use crate::error::BootstrapError;
use crate::rpc::{Reply, Request};

pub struct Runtime {
    config: Config,
    context: zmq::Context,
    session_rpc: Session<NoEncryption, transport::zmq::Connection>,
    unmarshaller: Unmarshaller<Reply>,
}

impl Runtime {
    pub async fn init(config: Config) -> Result<Self, BootstrapError> {
        let mut context = zmq::Context::new();
        let session_rpc = Session::new_zmq_unencrypted(
            ApiType::Client,
            &mut context,
            config.endpoint.clone(),
            None,
        )?;
        Ok(Self {
            config,
            context,
            session_rpc,
            unmarshaller: Reply::create_unmarshaller(),
        })
    }

    fn request(&mut self, request: Request) -> Result<Arc<Reply>, LnpError> {
        unimplemented!()
        /*
        let data = request.encode()?;
        self.session_rpc.send_raw_message(data)?;
        let raw = self.session_rpc.recv_raw_message()?;
        let reply = self.unmarshaller.unmarshall(&raw)?;
        Ok(reply)
         */
    }
}
