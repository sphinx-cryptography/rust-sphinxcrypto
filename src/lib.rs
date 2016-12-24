// Copyright 2016 Jeffrey Burdges and David Stainton

//! Sphinx mixnet packet crypto

#[macro_use]
extern crate arrayref;
extern crate crypto;

use crypto::digest::Digest;
use crypto::blake2b::Blake2b;
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::chacha20::ChaCha20;

pub mod crypto_primitives;
pub use crypto_primitives::GroupCurve25519;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
