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

use std::any::Any;

use internet2::zmqsocket::{self, ZmqType};
use internet2::{
    session, CreateUnmarshaller, PlainTranscoder, Session, TypedEnum,
    Unmarshall, Unmarshaller,
};
use microservices::node::TryService;

use super::Config;
use crate::error::{BootstrapError, RuntimeError};
use crate::rpc::{message, Reply, Request};
use crate::Vault;

pub fn run(config: Config) -> Result<(), BootstrapError> {
    let runtime = Runtime::init(config)?;

    runtime.run_or_panic("keyringd");

    Ok(())
}

pub struct Runtime {
    /// Original configuration object
    config: Config,

    /// Stored sessions
    session_rpc: session::Raw<PlainTranscoder, zmqsocket::Connection>,

    /// Secure key vault
    vault: Vault,

    /// Unmarshaller instance used for parsing RPC request
    unmarshaller: Unmarshaller<Request>,
}

impl Runtime {
    pub fn init(config: Config) -> Result<Self, BootstrapError> {
        debug!("Initializing vault {}", config.vault);
        let vault = Vault::with(&config.vault)?;

        debug!("Opening ZMQ socket {}", config.endpoint);
        let session_rpc = session::Raw::with_zmq_unencrypted(
            ZmqType::Rep,
            &config.endpoint,
            None,
            None,
        )?;

        Ok(Self {
            config,
            session_rpc,
            vault,
            unmarshaller: Request::create_unmarshaller(),
        })
    }
}

impl TryService for Runtime {
    type ErrorType = RuntimeError;

    fn try_run_loop(mut self) -> Result<(), Self::ErrorType> {
        loop {
            match self.run() {
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
    fn run(&mut self) -> Result<(), RuntimeError> {
        trace!("Awaiting for ZMQ RPC requests...");
        let raw = self.session_rpc.recv_raw_message()?;
        let reply = self.rpc_process(raw).unwrap_or_else(|err| err);
        trace!("Preparing ZMQ RPC reply: {:?}", reply);
        let data = reply.serialize();
        trace!(
            "Sending {} bytes back to the client over ZMQ RPC",
            data.len()
        );
        self.session_rpc.send_raw_message(&data)?;
        Ok(())
    }

    fn rpc_process(&mut self, raw: Vec<u8>) -> Result<Reply, Reply> {
        trace!("Got {} bytes over ZMQ RPC", raw.len());
        let message = (&*self.unmarshaller.unmarshall(&raw)?).clone();
        debug!("Received ZMQ RPC request: {:?}", message.type_id());
        match message {
            Request::Seed(seed) => self.rpc_seed_create(seed),
            Request::List => self.rpc_list(),
            Request::Derive(derive) => self.rpc_derive(derive),
            Request::ExportXpub(export) => self.rpc_export_xpub(export),
            Request::ExportXpriv(export) => self.rpc_export_xpriv(export),
            Request::SignPsbt(sign) => self.rpc_sign_psbt(sign),
            Request::SignKey(sign) => self.rpc_sign_key(sign),
            Request::SignData(sign) => self.rpc_sign_data(sign),
        }
    }

    fn rpc_seed_create(&mut self, seed: message::Seed) -> Result<Reply, Reply> {
        trace!("Awaiting for the vault lock");
        self.vault.seed(
            seed.name,
            seed.description,
            &seed.chain,
            seed.application,
            self.config.node_id(),
        )?;
        trace!("Vault lock released");
        Ok(Reply::Success)
    }

    fn rpc_list(&mut self) -> Result<Reply, Reply> {
        trace!("Awaiting for the vault lock");
        let accounts = self.vault.list()?;
        trace!("Vault lock released");
        Ok(Reply::Keylist(accounts))
    }

    fn rpc_derive(&mut self, derive: message::Derive) -> Result<Reply, Reply> {
        trace!("Awaiting for the vault lock");
        let mut seckey = self.config.node_key.clone();
        let account = self.vault.derive(
            derive.from,
            derive.path,
            derive.name,
            Some(derive.details),
            derive.assets,
            &mut seckey, //TODO: &mut derive.decryption_key,
        )?;
        trace!("Vault lock released");
        Ok(Reply::AccountInfo(account))
    }

    fn rpc_export_xpub(
        &mut self,
        export: message::Export,
    ) -> Result<Reply, Reply> {
        trace!("Awaiting for the vault lock");
        let key = self.vault.xpub(export.key_id)?;
        trace!("Vault lock released");
        Ok(Reply::XPub(key))
    }

    fn rpc_export_xpriv(
        &mut self,
        mut export: message::Export,
    ) -> Result<Reply, Reply> {
        trace!("Awaiting for the vault lock");
        let key = self
            .vault
            .xpriv(export.key_id, &mut export.decryption_key)?;
        trace!("Vault lock released");
        Ok(Reply::XPriv(key))
    }

    fn rpc_sign_psbt(
        &mut self,
        message: message::SignPsbt,
    ) -> Result<Reply, Reply> {
        trace!("Awaiting for the vault lock");
        let mut seckey = self.config.node_key.clone();
        let psbt = self.vault.sign_psbt(
            message.psbt,
            &mut seckey, //TODO: &mut derive.decryption_key,
        )?;
        trace!("Vault lock released");
        Ok(Reply::Psbt(psbt))
    }

    fn rpc_sign_key(
        &mut self,
        mut message: message::SignKey,
    ) -> Result<Reply, Reply> {
        trace!("Awaiting for the vault lock");
        trace!("Lock acquired");
        let signature = self
            .vault
            .sign_key(message.key_id, &mut message.decryption_key)?;
        trace!("Vault lock released");
        Ok(Reply::Signature(signature))
    }

    fn rpc_sign_data(
        &mut self,
        mut message: message::SignData,
    ) -> Result<Reply, Reply> {
        trace!("Awaiting for the vault lock");
        trace!("Lock acquired");
        let signature = self.vault.sign_data(
            message.key_id,
            &message.data,
            &mut message.decryption_key,
        )?;
        trace!("Vault lock released");
        Ok(Reply::Signature(signature))
    }
}
