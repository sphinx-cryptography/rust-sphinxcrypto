// Copyright 2018 David Stainton

//! Sphinx crypto primitives

extern crate rust_lioness;
extern crate crypto;
extern crate tiny_keccak;

use self::rust_lioness::{encrypt, decrypt, RAW_KEY_SIZE, IV_SIZE};
use crypto::chacha20::ChaCha20;
use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::blake2b::Blake2b;
use crypto::digest::Digest;
use self::tiny_keccak::Keccak;
use std::vec::Vec;

use super::ecdh::CURVE25519_SIZE;

/// the output size of the unkeyed hash in bytes
pub const HASH_SIZE: usize = 32;

/// the key size of the MAC in bytes
pub const MAC_KEY_SIZE: usize = 32;

/// the output size of the MAC in bytes.
pub const MAC_SIZE: usize = 16;

/// the key size of the stream cipher in bytes.
pub const STREAM_KEY_SIZE: usize = 32;

/// the IV size of the stream cipher in bytes.
pub const STREAM_IV_SIZE: usize = 12;

/// the key size of the SPRP in bytes.
pub const SPRP_KEY_SIZE: usize = RAW_KEY_SIZE;

/// the IV size of the SPRP in bytes.
pub const SPRP_IV_SIZE: usize = IV_SIZE;

/// the size of the DH group element in bytes.
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

/// PacketKeys are the per-hop Sphinx Packet Keys, derived from the blinded
/// DH key exchange.
pub struct PacketKeys {
    header_mac: [u8; MAC_KEY_SIZE],
    header_encryption: [u8; STREAM_KEY_SIZE],
    header_encryption_iv: [u8; STREAM_IV_SIZE],
    payload_encryption: [u8; SPRP_KEY_SIZE],
    blinding_factor: [u8; CURVE25519_SIZE],
}

/// kdf takes the input key material and returns the Sphinx Packet keys.
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

/// hash calculates the digest of a message
pub fn hash(input: &[u8]) -> Vec<u8> {
    let mut h = Blake2b::new(HASH_SIZE);
    h.input(&input);
    let mut output: Vec<u8> = Vec::with_capacity(HASH_SIZE);
    h.result(output.as_mut_slice());
    output
}

/// hmac returns the hmac of the data using a given key
pub fn hmac(key: &[u8; MAC_KEY_SIZE], data: &[u8]) -> [u8; MAC_SIZE] {
    let mut m = Blake2b::new_keyed(MAC_SIZE, &key[..]);
    m.input(data);
    let mut out = [0u8; 16];
    m.result(&mut out);
    out
}

/// returns the plaintext of the message msg, decrypted via the
/// Sphinx SPRP with a given key and IV.
pub fn sprp_decrypt(key: &[u8; SPRP_KEY_SIZE], iv: &[u8; SPRP_IV_SIZE], msg: Vec<u8>) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::with_capacity(msg.len());
    decrypt(key, iv, &mut output, &msg);
    output
}

/// returns the ciphertext of the message msg, encrypted via the
/// Sphinx SPRP with a given key and IV.
pub fn sprp_encrypt(key: &[u8; SPRP_KEY_SIZE], iv: &[u8; SPRP_IV_SIZE], msg: Vec<u8>) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::with_capacity(msg.len());
    encrypt(key, iv, &mut output, &msg);
    output
}
