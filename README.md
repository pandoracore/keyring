# Keyring: bitcoin key management for cypherpunks

![Rust](https://github.com/pandoracore/keyring/workflows/Rust/badge.svg)
[![codecov](https://codecov.io/gh/pandoracore/keyring/branch/master/graph/badge.svg)](https://codecov.io/gh/pandoracore/keyring)
[![AGPL licensed](https://img.shields.io/badge/license-AGPL-green.svg)](./LICENSE)

Backend for private keys management and signatures

One of the real-world apps working purely on LNP P2P/RPC protocols and 
utilizing [LNP/BP Core Library](https://github.com/LNP-BP/rust-lnpbp)

Usage:

    keyring-cli seed create
    keyring-cli seed import <fingerprint>
    keyring-cli seed export <fingerprint> <file>

    keyring-cli xpubkey list [<fingerprint>]
    keyring-cli xpubkey derive <fingerprint> <derivation_path>
    keyring-cli xpubkey export <fingerprint> <file>

    keyring-cli xprivkey export <fingerprint> <file>
    
    keyring-cli sign <in_file> <out_file>
