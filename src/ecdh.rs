// ecdh.rs - wrapper for X25519 Diffie-Hellman and blinding operations
// Copyright (C) 2018  David Anthony Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Wrapper for X25519 Diffie-Hellman and blinding operations.

extern crate rand;
extern crate sodiumoxide;

use self::rand::{Rng};
use sodiumoxide::crypto::scalarmult::curve25519::{Scalar, GroupElement, scalarmult, scalarmult_base};

const CURVE25519_SIZE: usize = 32;

/// KEY_SIZE is the size in bytes of the keys.
pub const KEY_SIZE: usize = CURVE25519_SIZE;

pub fn exp(x: &[u8; KEY_SIZE], y: &[u8; KEY_SIZE]) -> [u8; 32] {
    let group_element = GroupElement(*x);
    let g = scalarmult(&Scalar(*y), &group_element).unwrap();
    let mut out = [0u8; KEY_SIZE];
    out.copy_from_slice(&g[..]);
    out
}

pub fn exp_g(x: &[u8; KEY_SIZE]) -> [u8; 32] {
    let g = scalarmult_base(&Scalar(*x));
    let mut out = [0u8; KEY_SIZE];
    out.copy_from_slice(&g[..]);
    out
}

#[derive(Clone, Copy, Default)]
pub struct PublicKey {
    _key: [u8; KEY_SIZE],
}

impl PublicKey {
    pub fn blind(&mut self, blinding_factor: &[u8; KEY_SIZE]) {
        self._key = exp(&self._key, blinding_factor)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self._key.to_vec()
    }

    pub fn as_array(&self) -> [u8; KEY_SIZE] {
        self._key
    }

    pub fn from_bytes(&mut self, b: &[u8]) -> Result<(), &'static str> {
        if b.len() != KEY_SIZE {
            return Err("errInvalidKey")
        }
        self._key.copy_from_slice(b);
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
pub struct PrivateKey {
    public_key: PublicKey,
    _priv_bytes: [u8; KEY_SIZE],
}

impl PrivateKey {
    pub fn generate<R: Rng>(rng: &mut R) -> Result<PrivateKey, &'static str> {
        let mut raw_key = [0u8; KEY_SIZE];
        rng.fill_bytes(&mut raw_key);
        let pub_key = PublicKey{
            _key: exp_g(&raw_key),
        };
        let key = PrivateKey{
            public_key: pub_key,
            _priv_bytes: raw_key,
        };
        Ok(key)
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }
    
    /// exp calculates the shared secret with the provided public key.
    pub fn exp(&self, public_key: &PublicKey) -> [u8; KEY_SIZE] {
        exp(&public_key._key, &self._priv_bytes)
    }
    
    pub fn to_vec(&self) -> Vec<u8> {
        self._priv_bytes.to_vec()
    }

    pub fn as_array(&self) -> [u8; KEY_SIZE] {
        self._priv_bytes
    }

    pub fn from_bytes(&mut self, b: &[u8]) -> Result<(), &'static str> {
        if b.len() != KEY_SIZE {
            return Err("errInvalidKey")
        }
        self._priv_bytes.copy_from_slice(&b);
        self.public_key._key = exp_g(&self._priv_bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;
    use super::*;
    use self::rand::{Rng};
    use self::rand::os::OsRng;

    #[test]
    fn dh_ops_test() {
        let mut r = OsRng::new().expect("failure to create an OS RNG");
        let alice_private_key = PrivateKey::generate(&mut r).unwrap();
        let mut bob_sk = [0u8; KEY_SIZE];
        let mut rnd = OsRng::new().unwrap();
        let raw = rnd.gen_iter::<u8>().take(KEY_SIZE).collect::<Vec<u8>>();
        bob_sk.copy_from_slice(raw.as_slice());
        let bob_pk = exp_g(&bob_sk);
        let tmp1 = exp_g(&alice_private_key.as_array());
        assert_eq!(tmp1, alice_private_key.public_key._key);
        let alice_s = exp(&bob_pk, &alice_private_key.as_array());
        let bob_s = exp(&alice_private_key.public_key._key, &bob_sk);
        assert_eq!(alice_s, bob_s);
    }
}
