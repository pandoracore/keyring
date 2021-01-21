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

#[cfg(any(feature = "shell", feature = "embedded"))]
use settings::ConfigError;
use std::io;

#[cfg(any(feature = "server", feature = "embedded"))]
use crate::vault;

#[cfg(any(feature = "shell", feature = "embedded"))]
#[derive(Debug, Display, Error, From)]
#[display(Debug)]
pub enum ConfigInitError {
    #[from]
    IoError(io::Error),

    #[from]
    Toml(toml::ser::Error),
}

#[derive(Debug, Display, Error, From)]
#[display(Debug)]
pub enum BootstrapError {
    #[cfg(any(feature = "shell", feature = "server", feature = "embedded"))]
    #[from]
    ConfigError(ConfigError),

    TorNotYetSupported,

    #[from]
    IoError(io::Error),

    #[from]
    ArgParseError(String),

    #[from]
    ZmqSocketError(zmq::Error),

    #[cfg(feature = "monitoring")]
    MonitorSocketError(Box<dyn std::error::Error + Send>),

    #[from]
    TransportError(internet2::transport::Error),

    #[cfg(any(feature = "server", feature = "embedded"))]
    #[from]
    VaultError(vault::driver::Error),

    #[cfg(any(feature = "server", feature = "embedded"))]
    ConfigInitError,

    Other,
}

#[derive(Debug, Display, Error, From)]
#[display(Debug)]
pub enum RuntimeError {
    #[from(internet2::transport::Error)]
    Transport,

    #[from(internet2::presentation::Error)]
    Message,

    #[cfg(any(feature = "server", feature = "embedded"))]
    #[from]
    VaultDriver(vault::driver::Error),

    #[cfg(any(feature = "server", feature = "embedded"))]
    #[from]
    KeyManagement(vault::keymgm::Error),
}
