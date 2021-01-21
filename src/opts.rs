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

use clap::{Clap, ValueHint};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use internet2::PartialNodeAddr;
use lnpbp::Chain;
use microservices::shell::LogLevel;

#[cfg(any(target_os = "linux"))]
pub const KEYRING_DATA_DIR: &'static str = "~/.keyring";
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub const KEYRING_DATA_DIR: &'static str = "~/.keyring";
#[cfg(target_os = "macos")]
pub const KEYRING_DATA_DIR: &'static str =
    "~/Library/Application Support/Keyring";
#[cfg(target_os = "windows")]
pub const KEYRING_DATA_DIR: &'static str = "~\\AppData\\Local\\Keyring";
#[cfg(target_os = "ios")]
pub const KEYRING_DATA_DIR: &'static str = "~/Documents";
#[cfg(target_os = "android")]
pub const KEYRING_DATA_DIR: &'static str = ".";

pub const KEYRING_RPC_SOCKET_NAME: &'static str =
    "lnpz://0.0.0.0:20202?api=rpc"; //"ipc:{data_dir}/zmq.rpc";

#[derive(Clap, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Opts {
    /// Initializes config file with the default values
    #[clap(long)]
    pub init: bool,

    /// Data directory path
    ///
    /// Path to the directory that contains LNP Node data, and where ZMQ RPC
    /// socket files are located
    #[clap(
        short,
        long,
        global = true,
        default_value = KEYRING_DATA_DIR,
        env = "KEYRING_DATA_DIR",
        value_hint = ValueHint::DirPath
    )]
    pub data_dir: PathBuf,

    /// Set verbosity level
    ///
    /// Can be used multiple times to increase verbosity
    #[clap(short, long, global = true, parse(from_occurrences))]
    pub verbose: u8,

    /// Use Tor
    ///
    /// If set, specifies SOCKS5 proxy used for Tor connectivity and directs
    /// all network traffic through Tor network.
    /// If the argument is provided in form of flag, without value, uses
    /// `127.0.0.1:9050` as default Tor proxy address.
    #[clap(
        short = 'T',
        long,
        alias = "tor",
        global = true,
        env = "KEYRING_TOR_PROXY",
        value_hint = ValueHint::Hostname
    )]
    pub tor_proxy: Option<Option<SocketAddr>>,

    /// ZMQ socket name/address for daemon RPC interface
    ///
    /// Internal interface for control PRC protocol communications
    /// Defaults to `ctl.rpc` file inside `--data-dir` directory, unless
    /// `--use-threads` is specified; in that cases uses in-memory
    /// communication protocol.
    #[clap(
        short = 'x',
        long,
        global = true,
        env = "KEYRING_RPC_SOCKET",
        value_hint = ValueHint::FilePath,
        default_value = KEYRING_RPC_SOCKET_NAME
    )]
    pub rpc_socket: PartialNodeAddr,

    /// Blockchain to use
    #[clap(
        short = 'n',
        long,
        global = true,
        alias = "network",
        default_value = "testnet",
        env = "KEYRING_NETWORK"
    )]
    // TODO: Put it back to `signet` default network once rust-bitcoin will
    //       release signet support
    pub chain: Chain,
}

impl Opts {
    pub fn process(&mut self) {
        LogLevel::from_verbosity_flag_count(self.verbose).apply();
        let mut me = self.clone();

        me.data_dir = PathBuf::from(
            shellexpand::tilde(&me.data_dir.to_string_lossy().to_string())
                .to_string(),
        );
        fs::create_dir_all(&self.data_dir)
            .expect("Unable to access data directory");

        for s in vec![&mut self.rpc_socket] {
            match s {
                PartialNodeAddr::ZmqIpc(path, ..)
                | PartialNodeAddr::Posix(path) => {
                    me.process_dir(path);
                }
                _ => {}
            }
        }
    }

    pub fn process_dir(&self, path: &mut String) {
        *path = path.replace("{data_dir}", &self.data_dir.to_string_lossy());
        *path = shellexpand::tilde(path).to_string();
    }
}
