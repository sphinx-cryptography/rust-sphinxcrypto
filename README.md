# rust-sphinxcrypto [![](https://travis-ci.org/sphinx-cryptography/rust-sphinxcrypto.png?branch=master)](https://www.travis-ci.org/sphinx-cryptography/rust-sphinxcrypto) [![](https://img.shields.io/crates/v/sphinxcrypto.svg)](https://crates.io/crates/sphinxcrypto) [![](https://docs.rs/sphinxcrypto/badge.svg)](https://docs.rs/sphinxcrypto/)

This crate provides a concrete parameterization of the Sphinx
cryptographic packet format which can be used to construct a
great many different kinds of cryptographic packet switching
networks including high and low latency anonymity networks;<br />
especially **mix networks.**


## sphinx

<img style="float: right; width: auto; height: 415px;"
  src="https://github.com/applied-mixnetworks/rust-sphinxcrypto/raw/master/pix/dawn_on_the_great_sphinx.jpg"/>

<br />
<i>"An ancient Egyptian stone figure having a lion's body and a human or animal head."</i>
<br />
<br />

The reference implementation of Sphinx used the Lioness, a wide-block cipher (aka SPRP) to
encrypt the packet body, hence its namesake. This implementation uses
<A HREF="https://github.com/sphinx-cryptography/aez">AEZ</A>
to encrypt the packet body instead of Lioness because it's much faster.

**"Sphinx Mix Network Cryptographic Packet Format Specification"** :<BR>
https://github.com/katzenpost/docs/blob/master/specs/sphinx.rst

**Sphinx: A Compact and Provably Secure Mix Format**
by George Danezis and Ian Goldberg.<BR> https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf

The currently implemented Sphinx cryptographic parameterization is:

* EXP(X, Y) - X25519
* MAC(K, M), H(M) - Blake2b
* S(K, IV) - Chacha20
* KDF(SALT, IKM) - HKDF Sha256
* SPRP_Encrypt(K, M)/SPRP_Decrypt(K, M) - AEZ

The Sphinx packet geometry is parameterized in the **constants** submodule.

Sphinx has the following features:

* Single Use Reply Blocks
* per hop bitwise unlinkability
* indistinguishable replies
* hidden path length
* hidden relay position
* tagging attack detection
* reply attack detection


# warning

This code has not been formally audited by a cryptographer. It
therefore should not be considered safe or correct. Use it at your own
risk!


# installation

To import `sphinxcrypto`, add the following to the dependencies section of
your project's `Cargo.toml`:
```toml
sphinxcrypto = "^0.0.18"
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
