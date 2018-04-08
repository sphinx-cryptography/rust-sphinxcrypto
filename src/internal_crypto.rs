// Copyright 2016 Jeffrey Burdges and David Stainton

//! Sphinx crypto primitives

extern crate crypto;
extern crate tiny_keccak;

use crypto::chacha20::ChaCha20;
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::blake2b::Blake2b;
use crypto::digest::Digest;
use self::tiny_keccak::Keccak;
use std::vec::Vec;

use super::ecdh::CURVE25519_SIZE;

pub const HASH_SIZE: usize = 32;
pub const MAC_KEY_SIZE: usize = 32;
pub const MAC_SIZE: usize = 16;
pub const STREAM_KEY_SIZE: usize = 32;
pub const STREAM_IV_SIZE: usize = 12;
pub const SPRP_KEY_SIZE: usize = 128;
pub const SPRP_IV_SIZE: usize = 48;
pub const GROUP_ELEMENT_SIZE: usize = CURVE25519_SIZE;

const KDF_OUTPUT_SIZE: usize = MAC_KEY_SIZE + STREAM_KEY_SIZE + STREAM_IV_SIZE + SPRP_KEY_SIZE + GROUP_ELEMENT_SIZE;

/// stream cipher for sphinx crypto usage
#[derive(Clone, Copy)]
pub struct StreamCipher {
    cipher: ChaCha20,
}

impl StreamCipher {

    /// create a new StreamCipher struct
    pub fn new(&self, key: &[u8; 32], iv: &[u8; 32]) -> StreamCipher {
        StreamCipher {
            cipher: ChaCha20::new(key, iv),
        }
    }

    /// given a key return a cipher stream of length n
    pub fn generate(&mut self, n: usize) -> Vec<u8> {
        let zeros = vec![0u8; n];
        let mut output = vec![0u8; n];
        self.cipher.process(zeros.as_slice(), output.as_mut_slice());
        output
    }
}

pub struct PacketKeys {
    header_mac: [u8; MAC_KEY_SIZE],
    header_encryption: [u8; STREAM_KEY_SIZE],
    header_encryption_iv: [u8; STREAM_IV_SIZE],
    payload_encryption: [u8; SPRP_KEY_SIZE],
    blinding_factor: [u8; CURVE25519_SIZE],
}

pub fn kdf(input: &[u8; CURVE25519_SIZE]) -> *mut PacketKeys {
    let mut shake = Keccak::new_shake128();
    shake.update(input);
    let mut xof = shake.xof();
    let mut output = [0u8; KDF_OUTPUT_SIZE];
    xof.squeeze(&mut output);
    let (a1,a2,a3,a4,a5) = array_refs![&output,MAC_KEY_SIZE,STREAM_KEY_SIZE,STREAM_IV_SIZE,SPRP_KEY_SIZE,GROUP_ELEMENT_SIZE];
    &mut PacketKeys{
        header_mac: *a1,
        header_encryption: *a2,
        header_encryption_iv: *a3,
        payload_encryption: *a4,
        blinding_factor: *a5,
    }
}
