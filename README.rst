
rust-sphinxcrypto
=================

.. image:: https://travis-ci.org/david415/rust-sphinxcrypto.png?branch=master
    :target: https://www.travis-ci.org/david415/rust-sphinxcrypto
    :alt: travis build status

.. image:: https://coveralls.io/repos/github/david415/rust-sphinxcrypto/badge.svg?branch=master
  :target: https://coveralls.io/github/david415/rust-sphinxcrypto
  :alt: coveralls

.. image:: https://docs.rs/sphinxcrypto/badge.svg
  :target: https://docs.rs/sphinxcrypto/
  :alt: api docs

.. image:: https://img.shields.io/crates/v/sphinxcrypto.svg
  :target: https://crates.io/crates/sphinxcrypto
  :alt: crates.io link


about
-----

This crate provides a concrete parameterization of the Sphinx
cryptographic packet format. Sphinx is used in mix networks,
a kind of traffic analysis resistant communications network.
Sphinx has recently been used in the design of HORNET and
Lightening Onion. Sphinx has the following features:

* bitwise unlinkability for each hop
* indistinguishable replies
* hiding the path length
* hiding the relay position
* detection of tagging attacks
* detection of reply attacks

Sphinx is described in **Sphinx: A Compact and Provably Secure Mix
Format** by George Danezis and Ian Goldberg. See
<http://research.microsoft.com/en-us/um/people/gdane/papers/sphinx-eprint.pdf>.

If you are interested in using the Sphinx cryptographic packet format
in your designs then I recommend at least reading the Security and
Anonymity Consideration sections of the
**"Sphinx Mix Network Cryptographic Packet Format Specification"**:
https://github.com/katzenpost/docs/blob/master/specs/sphinx.txt


warning
-------

This code has not been formally audited by a cryptographer. It
therefore should not be considered safe or correct. Use it at your own
risk!


details
-------

The currently implemented Sphinx cryptographic parameterization is:

* EXP(X, Y) - X25519 sodiumoxide crate
* MAC(K, M), H(M) - Blake2b rust-crypto crate
* S(K, IV) - Chacha20 rust-crypto crate
* KDF(SALT, IKM) - SHAKE256 tiny-keccak crate
* SPRP_Encrypt(K, M)/SPRP_Decrypt(K, M) - Lioness
    with the following: Blake2b and Chacha20. rust-lioness crate

One of the goals is to remove dependency on the rust-crypto crate,
currently I am still using it for Blake2b and Chacha20.


status
------

Incomplete. Work-in-progress.


acknowledgments
---------------

A couple of years ago the initial code here was a partial Sphinx
implementation (with only the server side) that Jeff Burdges helped me
write. Recently I decided to make this library essentially a Rust
language port of Yawning's Katzenpost Sphinx implementation:

https://github.com/katzenpost/core/tree/master/sphinx

These will NOT be binary compatible unless using the exact same cipher
suite. I don't have an AEZ cipher implementation written in Rust
handy so I will keep using Lioness for the time being. If someone
cares about performance then please let me know.


license
-------

MIT License
