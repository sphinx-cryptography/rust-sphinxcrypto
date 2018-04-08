// ecdh.rs - wrapping library for curve25519 dh operations
// Copyright (C) 2018  David Stainton.

extern crate rand;
use self::rand::{Rng};
use self::rand::os::OsRng;

use crypto::curve25519::{curve25519, curve25519_base};

pub const CURVE25519_SIZE: usize = 32;

pub fn exp(x: &[u8], y: &[u8]) -> [u8; 32] {
    curve25519(y, x)
}

pub fn exp_g(x: &[u8]) -> [u8; 32] {
    curve25519_base(x)
}

#[derive(Clone, Copy, Default)]
pub struct PublicKey {
    _key: [u8; CURVE25519_SIZE],
}

impl PublicKey {
    pub fn blind(&mut self, blinding_factor: &[u8; CURVE25519_SIZE]) {
        self._key = exp(&self._key, blinding_factor)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self._key.to_vec()
    }

    pub fn from_bytes(&mut self, b: &[u8]) -> Result<(), &'static str> {
        if b.len() != CURVE25519_SIZE {
            return Err("errInvalidKey")
        }
        for (l, r) in self._key.iter_mut().zip(b.iter()) {
            *l = *r;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
pub struct PrivateKey {
    public_key: PublicKey,
    _priv_bytes: [u8; CURVE25519_SIZE],
}

impl PrivateKey {

    pub fn generate() -> Result<PrivateKey,()> {
        let mut rnd = OsRng::new().unwrap();
        let raw_key = rnd.gen_iter::<u8>().take(CURVE25519_SIZE).collect::<Vec<u8>>();
        let pub_key = PublicKey{
            _key: exp_g(&raw_key),
        };
        let mut priv_key_array = [0u8; CURVE25519_SIZE];
        for (l, r) in priv_key_array.iter_mut().zip(raw_key.iter()) {
            *l = *r;
        }
        let key = PrivateKey{
            public_key: pub_key,
            _priv_bytes: priv_key_array,
        };
        Ok(key)
    }
    
    /// Exp calculates the shared secret with the provided public key.
    pub fn exp(&self, public_key: &PublicKey) -> [u8; CURVE25519_SIZE] {
        exp(public_key.to_vec().as_slice(), &self._priv_bytes)
    }
    
    pub fn to_vec(&self) -> Vec<u8> {
        self._priv_bytes.to_vec()
    }

    pub fn from_bytes(&mut self, b: &[u8]) -> Result<(), &'static str> {
        if b.len() != CURVE25519_SIZE {
            return Err("errInvalidKey")
        }
        for (l, r) in self._priv_bytes.iter_mut().zip(b.iter()) {
            *l = *r;
        }
        self.public_key._key = exp_g(&self._priv_bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;
    extern crate rand;
    use super::*;
    use self::rand::{Rng};
    use self::rand::os::OsRng;

    #[test]
    fn dh_ops_test() {
        let alice_private_key = PrivateKey::generate().unwrap();        
        let mut bob_sk = [0u8; CURVE25519_SIZE];
        let mut rnd = OsRng::new().unwrap();
        let raw = rnd.gen_iter::<u8>().take(CURVE25519_SIZE).collect::<Vec<u8>>();
        bob_sk.copy_from_slice(raw.as_slice());
        let bob_pk = exp_g(&bob_sk);
        let tmp1 = exp_g(alice_private_key.to_vec().as_slice());
        assert_eq!(tmp1, alice_private_key.public_key._key);
        let alice_s = exp(&bob_pk, alice_private_key.to_vec().as_slice());
        let bob_s = exp(&alice_private_key.public_key._key, &bob_sk);
        assert_eq!(alice_s, bob_s);
    }
}
