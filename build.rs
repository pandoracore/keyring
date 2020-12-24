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

use clap::IntoApp;
use clap_generate::{generate_to, generators::*};

#[macro_use]
extern crate amplify_derive;
#[macro_use]
extern crate serde_crate as serde;

pub mod opts {
    include!("src/opts.rs");
}

pub mod cli {
    include!("src/cli/opts.rs");
}

pub mod keyringd {
    include!("src/daemon/opts.rs");
}

fn main() -> Result<(), configure_me_codegen::Error> {
    let outdir = "./shell";

    for app in [keyringd::Opts::into_app(), cli::Opts::into_app()].iter_mut() {
        let name = app.get_name().to_string();
        generate_to::<Bash, _, _>(app, &name, &outdir);
        generate_to::<PowerShell, _, _>(app, &name, &outdir);
        generate_to::<Zsh, _, _>(app, &name, &outdir);
    }

    configure_me_codegen::build_script_auto()
}
