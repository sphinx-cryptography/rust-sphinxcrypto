// ecdh.rs - wrapping library for curve25519 dh operations
// Copyright (C) 2018  David Anthony Stainton.
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
    
extern crate rand;
extern crate sodiumoxide;

use self::rand::{Rng};
use self::rand::os::OsRng;
use sodiumoxide::crypto::scalarmult::curve25519::{Scalar, GroupElement, scalarmult, scalarmult_base};

const CURVE25519_SIZE: usize = 32;

// KEY_SIZE is the size in bytes of the keys.
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

    pub fn generate() -> Result<PrivateKey, &'static str> {
        let rnd = OsRng::new();
        let mut rnd = match rnd {
            Ok(r) => r,
            Err(_) => return Err("failed to retrieve random data"),
        };
        let raw_key = rnd.gen_iter::<u8>().take(KEY_SIZE).collect::<Vec<u8>>();
        let mut raw_arr = [0u8; KEY_SIZE];
        raw_arr.copy_from_slice(&raw_key);
        let pub_key = PublicKey{
            _key: exp_g(&raw_arr),
        };
        let key = PrivateKey{
            public_key: pub_key,
            _priv_bytes: raw_arr,
        };
        Ok(key)
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }
    
    /// Exp calculates the shared secret with the provided public key.
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
        let alice_private_key = PrivateKey::generate().unwrap();        
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
