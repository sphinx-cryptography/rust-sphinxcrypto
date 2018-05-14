// Copyright 2018 David Stainton

//! Sphinx crypto primitives

extern crate rust_lioness;
extern crate chacha;
extern crate keystream;
extern crate tiny_keccak;
extern crate blake2b;

use self::rust_lioness::{LionessError, encrypt, decrypt, RAW_KEY_SIZE, IV_SIZE};

use super::ecdh::KEY_SIZE;

use self::chacha::ChaCha as ChaCha20;
use self::keystream::KeyStream;
use self::blake2b::{blake2b, blake2b_keyed};
use self::tiny_keccak::Keccak;



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
pub const GROUP_ELEMENT_SIZE: usize = KEY_SIZE;

const KDF_OUTPUT_SIZE: usize = MAC_KEY_SIZE + STREAM_KEY_SIZE + STREAM_IV_SIZE + SPRP_KEY_SIZE + SPRP_IV_SIZE + KEY_SIZE;

/// stream cipher for sphinx crypto usage
pub struct StreamCipher {
    cipher: ChaCha20,
}

impl StreamCipher {
    /// create a new StreamCipher struct
    pub fn new(key: &[u8; STREAM_KEY_SIZE], iv: &[u8; STREAM_IV_SIZE]) -> StreamCipher {
        StreamCipher {
            cipher: ChaCha20::new_ietf(key, iv),
        }
    }

    /// given a key return a cipher stream of length n
    pub fn generate(&mut self, n: usize) -> Vec<u8> {
        let mut output = vec![0u8; n];
        self.cipher.xor_read(&mut output).unwrap();
        output
    }

    pub fn xor_key_stream(&mut self, mut dst: &mut [u8], src: &[u8]) {
        dst.copy_from_slice(src);
        self.cipher.xor_read(&mut dst).unwrap();
    }
}

/// PacketKeys are the per-hop Sphinx Packet Keys, derived from the blinded
/// DH key exchange.
pub struct PacketKeys {
    pub header_mac: [u8; MAC_KEY_SIZE],
    pub header_encryption: [u8; STREAM_KEY_SIZE],
    pub header_encryption_iv: [u8; STREAM_IV_SIZE],
    pub payload_encryption: [u8; SPRP_KEY_SIZE],
    pub payload_encryption_iv: [u8; SPRP_IV_SIZE],
    pub blinding_factor: [u8; KEY_SIZE],
}

/// kdf takes the input key material and returns the Sphinx Packet keys.
pub fn kdf(input: &[u8; KEY_SIZE]) -> PacketKeys {
    let mut shake = Keccak::new_shake256();
    shake.update(input);
    let mut xof = shake.xof();
    let mut output = [0u8; KDF_OUTPUT_SIZE];
    xof.squeeze(&mut output);
    let (a1,a2,a3,a4,a5,a6) = array_refs![&output,MAC_KEY_SIZE,STREAM_KEY_SIZE,STREAM_IV_SIZE,SPRP_KEY_SIZE,SPRP_IV_SIZE,KEY_SIZE];
    PacketKeys{
        header_mac: *a1,
        header_encryption: *a2,
        header_encryption_iv: *a3,
        payload_encryption: *a4,
        payload_encryption_iv: *a5,
        blinding_factor: *a6,
    }
}

/// hash calculates the digest of a message
pub fn hash(input: &[u8]) -> Vec<u8> {
    let h = blake2b(HASH_SIZE, input);
    let mut out = Vec::new();
    out.extend(h.iter());
    return out;
}

/// hmac returns the hmac of the data using a given key
pub fn hmac(key: &[u8; MAC_KEY_SIZE], data: &[u8]) -> [u8; MAC_SIZE] {
    let _out = blake2b_keyed(MAC_SIZE, key, data);
    let mut out = [0u8; MAC_SIZE];
    out.copy_from_slice(&_out.to_vec());
    return out;
}

/// returns the plaintext of the message msg, decrypted via the
/// Sphinx SPRP with a given key and IV.
pub fn sprp_decrypt(key: &[u8; SPRP_KEY_SIZE], iv: &[u8; SPRP_IV_SIZE], msg: Vec<u8>) -> Result<Vec<u8>, LionessError> {
    let mut output: Vec<u8> = vec![0u8; msg.len()];
    decrypt(key, iv, &mut output, &msg)?;
    Ok(output)
}

/// returns the ciphertext of the message msg, encrypted via the
/// Sphinx SPRP with a given key and IV.
pub fn sprp_encrypt(key: &[u8; SPRP_KEY_SIZE], iv: &[u8; SPRP_IV_SIZE], msg: Vec<u8>) -> Result<Vec<u8>, LionessError> {
    let mut output: Vec<u8> = vec![0u8; msg.len()];
    encrypt(key, iv, &mut output, &msg)?;
    Ok(output)
}
