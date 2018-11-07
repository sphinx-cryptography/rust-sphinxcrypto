# rust-sphinxcrypto
[![](https://travis-ci.org/david415/rust-sphinxcrypto.png?branch=master)](https://www.travis-ci.org/david415/rust-sphinxcrypto) [![](https://img.shields.io/crates/v/sphinxcrypto.svg)](https://crates.io/crates/sphinxcrypto) [![](https://docs.rs/sphinxcrypto/badge.svg)](https://docs.rs/sphinxcrypto/)

This crate provides a concrete parameterization of the Sphinx
cryptographic packet format and follows this "Sphinx Mix Network
Cryptographic Packet Format Specification" document:

https://github.com/katzenpost/docs/blob/master/specs/sphinx.rst

Sphinx has the following features:

* Single Use Reply Blocks
* per hop bitwise unlinkability
* indistinguishable replies
* hidden the path length
* hidden the relay position
* tagging attack detection
* reply attack detection

Read the Sphinx paper, **Sphinx: A Compact and Provably Secure Mix Format**
by George Danezis and Ian Goldberg. See https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf

# warning

This code has not been formally audited by a cryptographer. It
therefore should not be considered safe or correct. Use it at your own
risk!


# details

The currently implemented Sphinx cryptographic parameterization is:

* EXP(X, Y) - X25519
* MAC(K, M), H(M) - Blake2b
* S(K, IV) - Chacha20
* KDF(SALT, IKM) - HKDF Sha256
* SPRP_Encrypt(K, M)/SPRP_Decrypt(K, M) - AEZ

The Sphinx packet geometry is parameterized in the **constants** submodule.


# Usage

To import `sphinxcrypto`, add the following to the dependencies section of
your project's `Cargo.toml`:
```toml
sphinxcrypto = "^0.0.13"
```
Then import the crate as:
```rust,no_run
extern crate sphinxcrypto;
```


# acknowledgments

This library is a Rust language port of Yawning's Katzenpost Sphinx implementation:

https://github.com/katzenpost/core/tree/master/sphinx

Thanks to Jeff Burdges for helping me with some of my rust problems.


# license

GNU AFFERO GENERAL PUBLIC LICENSE
