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

use clap::derive::Clap;
use std::sync::Arc;

use lnpbp::lnp::presentation::Encode;
use lnpbp::lnp::zmq::ApiType;
use lnpbp::lnp::{transport, NoEncryption, Session, Unmarshall, Unmarshaller};
use lnpbp::TryService;

use super::Config;
use crate::error::{BootstrapError, RuntimeError};
use crate::rpc::{types::AuthCode, Reply, Request};
use crate::{vault::FileVault, Vault};

pub struct Runtime {
    /// Original configuration object
    config: Config,

    /// Stored sessions
    session_rpc: Session<NoEncryption, transport::zmq::Connection>,

    /// Secure key vault
    vault: Arc<dyn Vault>,

    /// Unmarshaller instance used for parsing RPC request
    unmarshaller: Unmarshaller<Request>,
}

impl Runtime {
    pub async fn init(config: Config) -> Result<Self, BootstrapError> {
        let mut context = zmq::Context::new();

        let session_rpc = Session::new_zmq_unencrypted(
            ApiType::Server,
            &mut context,
            config.zmq_endpoint.clone(),
            None,
        )?;

        Ok(Self {
            config,
            session_rpc,
            vault: Arc::new(FileVault {}),
            unmarshaller: Request::create_unmarshaller(),
        })
    }
}

#[async_trait]
impl TryService for Runtime {
    type ErrorType = RuntimeError;

    async fn try_run_loop(mut self) -> Result<!, Self::ErrorType> {
        loop {
            match self.run().await {
                Ok(_) => debug!("API request processing complete"),
                Err(err) => {
                    error!("Error processing API request: {}", err);
                    Err(err)?;
                }
            }
        }
    }
}

impl Runtime {
    async fn run(&mut self) -> Result<(), RuntimeError> {
        let raw = self.session_rpc.recv_raw_message()?;
        let reply = self.rpc_process(raw).await.unwrap_or_else(|err| err);
        let data = reply.encode()?;
        self.session_rpc.send_raw_message(data)?;
        Ok(())
    }

    async fn rpc_process(&mut self, raw: Vec<u8>) -> Result<Reply, Reply> {
        let message = &*self.unmarshaller.unmarshall(&raw)?;
        match message {
            Request::Seed(auth) => self.rpc_seed_create(*auth).await,
            _ => unimplemented!(),
        }
    }

    async fn rpc_seed_create(&mut self, auth: AuthCode) -> Result<Reply, Reply> {
        Ok(Reply::Success)
    }
}
