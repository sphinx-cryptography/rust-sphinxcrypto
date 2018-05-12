# rust-sphinxcrypto
[![](https://travis-ci.org/david415/rust-sphinxcrypto.png?branch=master)](https://www.travis-ci.org/david415/rust-sphinxcrypto) [![](https://img.shields.io/crates/v/sphinxcrypto.svg)](https://crates.io/crates/sphinxcrypto) [![](https://docs.rs/sphinxcrypto/badge.svg)](https://docs.rs/sphinxcrypto/)

This crate provides a concrete parameterization of the Sphinx
cryptographic packet format and follows this "Sphinx Mix Network
Cryptographic Packet Format Specification" document:

https://github.com/katzenpost/docs/blob/master/specs/sphinx.rst

Sphinx has the following features:

* Single Use Reply Blocks
* bitwise unlinkability for each hop
* indistinguishable replies
* hiding the path length
* hiding the relay position
* detection of tagging attacks
* detection of reply attacks

Read the Sphinx paper, **Sphinx: A Compact and Provably Secure Mix Format**
by George Danezis and Ian Goldberg. See
<http://research.microsoft.com/en-us/um/people/gdane/papers/sphinx-eprint.pdf>.


# warning

This code has not been formally audited by a cryptographer. It
therefore should not be considered safe or correct. Use it at your own
risk!


# details

The currently implemented Sphinx cryptographic parameterization is:

* EXP(X, Y) - X25519 sodiumoxide crate
* MAC(K, M), H(M) - Blake2b rust-crypto crate
* S(K, IV) - Chacha20 rust-crypto crate
* KDF(SALT, IKM) - SHAKE256 tiny-keccak crate
* SPRP_Encrypt(K, M)/SPRP_Decrypt(K, M) - Lioness
    with the following: Blake2b and Chacha20. rust-lioness crate

One of the goals is to remove dependency on the rust-crypto crate,
currently I am still using it for Blake2b and Chacha20.

The Sphinx packet geometry is parameterized in the **constants** submodule.


# Usage

To import `sphinxcrypto`, add the following to the dependencies section of
your project's `Cargo.toml`:
```toml
sphinxcrypto = "^0.0.4"
```
Then import the crate as:
```rust,no_run
extern crate sphinxcrypto;
```


# acknowledgments

This library is a Rust language port of Yawning's Katzenpost Sphinx implementation:

https://github.com/katzenpost/core/tree/master/sphinx

These will NOT be binary compatible unless using the exact same cipher
suite. I don't have an AEZ cipher implementation written in Rust
handy so I will keep using Lioness for the time being. If someone
cares about performance then please let me know.

Thanks to Jeff Burdges for helping me with some of my rust problems.


# license

MIT License
