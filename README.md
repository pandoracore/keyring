# Keyring backend by Pandora Core

[![TravisCI](https://api.travis-ci.com/pandoracore/keyring.svg?branch=master)](https://api.travis-ci.com/pandoracore/keyring)
[![codecov](https://codecov.io/gh/pandoracore/keyring/branch/master/graph/badge.svg)](https://codecov.io/gh/pandoracore/keyring)

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
