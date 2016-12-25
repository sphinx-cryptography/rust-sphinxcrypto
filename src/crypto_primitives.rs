// Copyright 2016 Jeffrey Burdges and David Stainton

//! Sphinx crypto primitives

extern crate lioness;
extern crate crypto;

use self::lioness::{Lioness, RAW_KEY_SIZE};
use crypto::chacha20::ChaCha20;
use crypto::blake2b::Blake2b;
use crypto::digest::Digest;
use crypto::curve25519::curve25519;
use crypto::symmetriccipher::SynchronousStreamCipher;

pub const CURVE25519_SIZE: usize = 32;
pub const HASH_REPLAY_PREFIX: u8 = 0x55;
pub const HASH_BLINDING_PREFIX: u8 = 0x11;
pub const HASH_STREAM_KEY_PREFIX: u8 = 0x22;
pub const HASH_HMAC_KEY_PREFIX: u8 = 0x33;


/// Group operations in the curve25519
#[derive(Clone, Copy)]
pub struct GroupCurve25519 {
    _g: [u8; CURVE25519_SIZE],
}

impl GroupCurve25519 {
    /// return a new GroupCurve25519 struct
    pub fn new() -> GroupCurve25519 {
        GroupCurve25519 {
            _g: [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    /// Perform scalar multiplication on curve25519
    pub fn exp_on(self, base: &[u8; CURVE25519_SIZE], n: &[u8]) -> [u8; CURVE25519_SIZE] {
        curve25519(n, base)
    }

    /// Perform accumulating multiplication for each scalar
    pub fn multi_exp_on(self, base: &[u8; CURVE25519_SIZE], n: &[&[u8]]) -> [u8; CURVE25519_SIZE] {
        n.iter().fold(*base, |acc, x| curve25519(x, &acc))
    }

    /// flip some bits
    pub fn make_exp(n: &[u8; CURVE25519_SIZE]) -> [u8; CURVE25519_SIZE] {
        let mut ret = [0u8; CURVE25519_SIZE];
        for (l, r) in ret.iter_mut().zip(n.iter()) {
            *l = *r;
        }
        ret[0] &= 248;
        ret[31] &= 127;
        ret[31] |= 64;
        ret
    }
}

/// stream cipher for sphinx crypto usage
pub struct SphinxStreamCipher {

}

impl SphinxStreamCipher {

    /// create a new SphinxStreamCipher struct
    pub fn new() -> SphinxStreamCipher {
        SphinxStreamCipher {
        }
    }

    /// given a key return a cipher stream of length n
    pub fn generate_stream<'a>(key: &[u8; 32], n: usize) -> &'a[u8] {
        let nonce = [0u8; 8];
        let mut cipher = ChaCha20::new(key, &nonce);
        let mut zeros = vec![0u8; n];
        let mut output = vec![0u8; n];
        cipher.process(zeros.as_slice(), output.as_mut_slice());
        output.as_slice()
    }
}

/// A sphinx has the body of a lion. That is, the body of a sphinx packet
/// is encrypted with the Lioness wide-block cipher. Since the Lioness keys
/// are so huge (192 bytes) we use a stream cipher in our key derivation function.
pub struct SphinxLionessBlockCipher {

}

impl SphinxLionessBlockCipher {

    /// return a new SphinxLionessBlockCipher struct
    pub fn new() -> SphinxLionessBlockCipher {
        SphinxLionessBlockCipher {
        }
    }

    /// given a 32 byte secret, derive a key suitable for use with our wide block cipher
    pub fn derive_key(secret: &[u8; CURVE25519_SIZE]) -> [u8; RAW_KEY_SIZE] {
        let mut ret = [0u8; RAW_KEY_SIZE];
        ret
    }

    /// encrypt a block
    pub fn encrypt() {
    }

    /// decrypt a block
    pub fn decrypt() {
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
        out
    }

    /// Produce prefixed hash output used to detect mixnet replay attacks
    pub fn hash_replay(&mut self, input: &[u8]) -> [u8; 32] {
        self.digest.input(&[HASH_REPLAY_PREFIX]);
        self.digest.input(input);
        let mut out = [0u8; 32];
        self.digest.result(&mut out);
        self.digest.reset();
        out
    }

    /// Produce prefixed hash output used to derive a blinding factor
    pub fn hash_blinding(&mut self, public_key: &[u8], private_key: &[u8]) -> [u8; 32] {
        self.digest.input(&[HASH_BLINDING_PREFIX]);
        self.digest.input(public_key);
        self.digest.input(private_key);
        let mut out = [0u8; 32];
        self.digest.result(&mut out);
        self.digest.reset();
        out
    }

    /// Derive a stream cipher key
    pub fn derive_stream_cipher_key(&mut self, secret: &[u8]) -> [u8; 32] {
        self.digest.input(&[HASH_STREAM_KEY_PREFIX]);
        self.digest.input(secret);
        let mut out = [0u8; 32];
        self.digest.result(&mut out);
        self.digest.reset();
        out
    }

    /// Derive an HMAC key
    pub fn derive_hmac_key(&mut self, secret: &[u8]) -> [u8; 16] {
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
    fn derive_hmac_key_test() {
        let mut digest = SphinxDigest::new();
        let secret = "82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b4".from_hex().unwrap();
        let key = digest.derive_hmac_key(&secret);
        let want_key = "eba2ad216a65c5230ad2018b4c536c45".from_hex().unwrap();
        assert!(key == want_key.as_slice());
        let data = "4171bd9a48a58cf7579e9fa662fe0ac2acb8c6eed3056cd970fd35dd4d026cae".from_hex().unwrap();
        let mac = digest.hmac(&key, &data);
        let want_mac = "77724528a77692be295f07bcfc8bd5eb".from_hex().unwrap();
        assert!(mac == want_mac.as_slice());
    }

    #[test]
    fn commutativity_test() {
        let curve1 = "82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b4".from_hex().unwrap();
        let curve2 = "4171bd9a48a58cf7579e9fa662fe0ac2acb8c6eed3056cd970fd35dd4d026cae".from_hex().unwrap();

        let group = GroupCurve25519::new();
        let generator = group._g;
        let exp1 = group.exp_on(&generator, &curve1);
        let exp1 = group.exp_on(&exp1, &curve2);
        let exp2 = group.exp_on(&generator, &curve2);
        let exp2 = group.exp_on(&exp2, &curve1);

        assert!(exp1 == exp2);
        let want = "84b87479a6036249a18ef279b73db5a4811f641c50337ae3f21fb0be43cc8040".from_hex().unwrap();
        assert!(exp1 == want.as_slice());

        let keys: &[&[u8]] = &[&curve1, &curve2];
        let fu = group.multi_exp_on(&generator, &keys);
        assert_eq!(fu, exp1);
    }
}
