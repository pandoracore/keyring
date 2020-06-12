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
use tokio::sync::Mutex;

use lnpbp::lnp::presentation::Encode;
use lnpbp::lnp::zmq::ApiType;
use lnpbp::lnp::{transport, NoEncryption, Session, Unmarshall, Unmarshaller};
use lnpbp::TryService;

use super::Config;
use crate::api::{message, types::AuthCode, Reply, Request};
use crate::error::{BootstrapError, RuntimeError};
use crate::{vault, vault::driver, vault::file_driver, Vault};

pub struct Runtime {
    /// Original configuration object
    config: Config,

    /// Stored sessions
    session_rpc: Session<NoEncryption, transport::zmq::Connection>,

    /// Secure key vault
    vault: Arc<Mutex<Vault>>,

    /// Unmarshaller instance used for parsing RPC request
    unmarshaller: Unmarshaller<Request>,
}

impl Runtime {
    pub async fn init(config: Config) -> Result<Self, BootstrapError> {
        debug!("Initializing vault {}", config.vault);
        let vault = Vault::new(&config.vault)?;

        debug!("Opening ZMQ socket {}", config.zmq_endpoint);
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
            vault: Arc::new(Mutex::new(vault)),
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
        trace!("Awaiting for ZMQ RPC requests...");
        let raw = self.session_rpc.recv_raw_message()?;
        let reply = self.rpc_process(raw).await.unwrap_or_else(|err| err);
        trace!("Preparing ZMQ RPC reply: {:?}", reply);
        let data = reply.encode()?;
        trace!(
            "Sending {} bytes back to the client over ZMQ RPC",
            data.len()
        );
        self.session_rpc.send_raw_message(data)?;
        Ok(())
    }

    async fn rpc_process(&mut self, raw: Vec<u8>) -> Result<Reply, Reply> {
        trace!("Got {} bytes over ZMQ RPC: {:?}", raw.len(), raw);
        let message = (&*self.unmarshaller.unmarshall(&raw)?).clone();
        debug!("Received ZMQ RPC request: {:?}", message);
        match message {
            Request::Seed(seed) => self.rpc_seed_create(seed).await,
            Request::List => self.rpc_list().await,
            _ => unimplemented!(),
        }
    }

    async fn rpc_seed_create(&mut self, seed: message::Seed) -> Result<Reply, Reply> {
        trace!("Awaiting for the vault lock");
        self.vault
            .lock()
            .await
            .seed(seed.name, seed.description, &self.config.node_id())?;
        trace!("Vault lock released");
        Ok(Reply::Success)
    }

    async fn rpc_list(&mut self) -> Result<Reply, Reply> {
        trace!("Awaiting for the vault lock");
        let accounts = self.vault.lock().await.list()?;
        trace!("Vault lock released");
        Ok(Reply::Keylist(accounts))
    }
}
