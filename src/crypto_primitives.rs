// Copyright 2016 Jeffrey Burdges and David Stainton

//! Sphinx crypto primitives

extern crate crypto;

use crypto::chacha20::ChaCha20;
use crypto::blake2b::Blake2b;
use crypto::digest::Digest;
use crypto::symmetriccipher::SynchronousStreamCipher;
use std::vec::Vec;

pub const CURVE25519_SIZE: usize = 32;
pub const HASH_REPLAY_PREFIX: u8 = 0x55;
pub const HASH_BLINDING_PREFIX: u8 = 0x11;
pub const HASH_STREAM_KEY_PREFIX: u8 = 0x22;
pub const HASH_HMAC_KEY_PREFIX: u8 = 0x33;


/// stream cipher for sphinx crypto usage
#[derive(Clone, Copy)]
pub struct SphinxStreamCipher {}

impl SphinxStreamCipher {

    /// create a new SphinxStreamCipher struct
    pub fn new() -> SphinxStreamCipher {
        SphinxStreamCipher {
        }
    }

    /// given a key return a cipher stream of length n
    pub fn generate_stream(self, key: &[u8; 32], n: usize) -> Vec<u8> {
        let nonce = [0u8; 8];
        let mut cipher = ChaCha20::new(key, &nonce);
        let zeros = vec![0u8; n];
        let mut output = vec![0u8; n];
        cipher.process(zeros.as_slice(), output.as_mut_slice());
        output
    }
}

/// Various digest operations specific to sphinx crypto
pub struct SphinxDigest {
    digest: Blake2b,
}

impl SphinxDigest {
    pub fn new() -> SphinxDigest {
        SphinxDigest {
            digest: Blake2b::new(32),
        }
    }

    /// Produce 32 byte hash output
    pub fn hash(&mut self, input: &[u8]) -> [u8; 32] {
        self.digest.input(input);
        let mut out = [0u8; 32];
        self.digest.result(&mut out);
        self.digest.reset();
        out
    }

    /// Produce prefixed hash output used to detect mixnet replay attacks
    pub fn hash_replay(&mut self, input: &[u8; 32]) -> [u8; 32] {
        self.digest.input(&[HASH_REPLAY_PREFIX]);
        self.digest.input(input);
        let mut out = [0u8; 32];
        self.digest.result(&mut out);
        self.digest.reset();
        out
    }

    /// Produce prefixed hash output used to derive a blinding factor
    pub fn hash_blinding(&mut self, public_key: &[u8; 32], private_key: &[u8; 32]) -> [u8; 32] {
        self.digest.input(&[HASH_BLINDING_PREFIX]);
        self.digest.input(public_key);
        self.digest.input(private_key);
        let mut out = [0u8; 32];
        self.digest.result(&mut out);
        self.digest.reset();
        out
    }

    /// Derive a stream cipher key
    pub fn derive_stream_cipher_key(&mut self, secret: &[u8; 32]) -> [u8; 32] {
        assert!(secret.len() == 32);
        self.digest.input(&[HASH_STREAM_KEY_PREFIX]);
        self.digest.input(secret);
        let mut out = [0u8; 32];
        self.digest.result(&mut out);
        self.digest.reset();
        out
    }

    /// Derive an HMAC key
    pub fn derive_hmac_key(&mut self, secret: &[u8; 32]) -> [u8; 16] {
        let mut digest = Blake2b::new(16);
        digest.input(&[HASH_HMAC_KEY_PREFIX]);
        digest.input(secret);
        let mut out = [0u8; 16];
        digest.result(&mut out);
        out
    }

    /// Perform an HMAC on the given data
    pub fn hmac(&mut self, key: &[u8; 16], data: &[u8]) -> [u8; 16] {
        let mut m = Blake2b::new_keyed(16, &key[..]);
        m.input(data);
        let mut out = [0u8; 16];
        m.result(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;
    use super::*;
    use self::rustc_serialize::hex::FromHex;
    //use self::rustc_serialize::hex::{FromHex, ToHex};

    #[test]
    fn stream_cipher_test() {
        let cipher = SphinxStreamCipher::new();
        let key = "82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b4".from_hex().unwrap();
        let stream = cipher.generate_stream(array_ref!(&key,0,32), 50);
        let want = "8e295c33753c49121b3d4e8508a3f796079600df41a1401542d2346f32c0813082b2bef9059128e3da9a6bd73da43a44daa5".from_hex().unwrap();
        assert!(stream == want)
    }

    #[test]
    fn derive_hmac_key_test() {
        let mut digest = SphinxDigest::new();
        let secret = "82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b4".from_hex().unwrap();
        let key = digest.derive_hmac_key(array_ref!(secret, 0, 32));
        let want_key = "eba2ad216a65c5230ad2018b4c536c45".from_hex().unwrap();
        assert!(key == want_key.as_slice());
        let data = "4171bd9a48a58cf7579e9fa662fe0ac2acb8c6eed3056cd970fd35dd4d026cae".from_hex().unwrap();
        let mac = digest.hmac(&key, &data);
        let want_mac = "77724528a77692be295f07bcfc8bd5eb".from_hex().unwrap();
        assert!(mac == want_mac.as_slice());
    }
}
