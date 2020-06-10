# Keyring backend by Pandora Core

Backend for private keys management and signatures

Usage:

    keyring-cli seed create
    keyring-cli seed import <fingerprint>
    keyring-cli seed export <fingerprint> <file>

    keyring-cli xpubkey list [<fingerprint>]
    keyring-cli xpubkey derive <fingerprint> <derivation_path>
    keyring-cli xpubkey export <fingerprint> <file>

    keyring-cli xprivkey export <fingerprint> <file>
    
    keyring-cli sign <in_file> <out_file>
